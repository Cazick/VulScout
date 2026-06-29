"""Web 爬虫 -- URL 发现、表单提取、链接去重."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup, Comment, Tag

from vulnscout.core.http_client import HttpClient

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredForm:
    """从页面中发现的 HTML 表单."""

    action_url: str
    method: str  # GET / POST
    inputs: List[Dict[str, str]] = field(default_factory=list)
    page_url: str = ""


@dataclass
class DiscoveredEndpoint:
    """从页面中发现的一个端点（URL 或 API）. """

    url: str
    source_url: str = ""
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    is_form: bool = False


@dataclass
class CrawlResult:
    """一次爬取的结果."""

    target_url: str
    pages_visited: int = 0
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    urls_found: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class Crawler:
    """异步 Web 爬虫，自动发现攻击面."""

    def __init__(
        self,
        http_client: HttpClient,
        max_depth: int = 2,
        max_pages: int = 50,
        same_origin_only: bool = True,
        extract_forms: bool = True,
        extract_scripts: bool = True,
        extract_comments: bool = True,
    ):
        self._http = http_client
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._same_origin_only = same_origin_only
        self._extract_forms = extract_forms
        self._extract_scripts = extract_scripts
        self._extract_comments = extract_comments

    async def crawl(self, start_url: str) -> CrawlResult:
        """从起始 URL 开始爬取."""
        result = CrawlResult(target_url=start_url)
        visited: Set[str] = set()
        to_visit: List[Tuple[str, int]] = [(start_url, 0)]
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc

        sem = asyncio.Semaphore(5)  # 最多并发 5 页

        async def _fetch(url: str, depth: int):
            async with sem:
                if url in visited or len(visited) >= self._max_pages:
                    return
                visited.add(url)
                result.pages_visited = len(visited)

                try:
                    resp = await self._http.get(url)
                    ct = resp.headers.get("content-type", "")
                    if "text/html" not in ct and "application/xhtml" not in ct:
                        return

                    html = resp.text
                    page_url = str(resp.url)  # 最终 URL（经过重定向后）

                    soup = BeautifulSoup(html, "lxml")

                    # 提取链接
                    if depth < self._max_depth:
                        new_urls = self._extract_links(soup, page_url, base_domain)
                        for nu in new_urls:
                            if nu not in visited and len(to_visit) < self._max_pages:
                                to_visit.append((nu, depth + 1))
                        result.urls_found.extend(new_urls)

                    # 提取表单
                    if self._extract_forms:
                        forms = self._extract_forms_from_soup(soup, page_url)
                        result.forms.extend(forms)
                        for f in forms:
                            ep = DiscoveredEndpoint(
                                url=f.action_url,
                                source_url=page_url,
                                method=f.method,
                                is_form=True,
                            )
                            result.endpoints.append(ep)

                    # 提取 JavaScript 文件
                    if self._extract_scripts:
                        scripts = self._extract_scripts_from_soup(soup, page_url)
                        for s in scripts:
                            result.endpoints.append(
                                DiscoveredEndpoint(url=s, source_url=page_url, method="GET")
                            )

                    # 提取 HTML 注释
                    if self._extract_comments:
                        comments = self._extract_comments_from_soup(soup)
                        result.comments.extend(comments)

                except Exception as e:
                    logger.debug("爬取出错 %s: %s", url, e)
                    result.errors.append(f"{url}: {e}")

        # 主爬取循环
        while to_visit and len(visited) < self._max_pages:
            batch = []
            batch_count = min(len(to_visit), 10)
            for _ in range(batch_count):
                if to_visit:
                    batch.append(to_visit.pop(0))

            tasks = [_fetch(url, depth) for url, depth in batch]
            await asyncio.gather(*tasks)

        # 去重最终 URL 列表
        result.urls_found = list(dict.fromkeys(result.urls_found))

        # 去重端点
        seen_urls: Set[str] = set()
        unique_endpoints = []
        for ep in result.endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen_urls:
                seen_urls.add(key)
                unique_endpoints.append(ep)
        result.endpoints = unique_endpoints

        return result

    def _extract_links(
        self,
        soup: BeautifulSoup,
        page_url: str,
        base_domain: str,
    ) -> List[str]:
        """从页面中提取所有链接."""
        urls: List[str] = []

        for tag, attr in [
            ("a", "href"),
            ("link", "href"),
            ("area", "href"),
        ]:
            for el in soup.find_all(tag, href=True):
                href = el["href"]
                full = self._normalize_url(href, page_url)
                if full and self._should_include(full, base_domain):
                    urls.append(full)

        # iframe / frame / embed
        for tag, attr in [("iframe", "src"), ("frame", "src"), ("embed", "src"), ("object", "data")]:
            for el in soup.find_all(tag, **{attr: True}):
                src = el[attr]
                full = self._normalize_url(src, page_url)
                if full and self._should_include(full, base_domain):
                    urls.append(full)

        return urls

    def _extract_forms_from_soup(
        self,
        soup: BeautifulSoup,
        page_url: str,
    ) -> List[DiscoveredForm]:
        """从页面中提取表单."""
        forms = []
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            method = form_tag.get("method", "GET").upper()
            action_url = self._normalize_url(action, page_url) or page_url

            inputs = []
            for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                input_info = {
                    "name": input_tag.get("name", ""),
                    "type": input_tag.get("type", "text"),
                }
                if input_tag.name == "textarea":
                    input_info["type"] = "textarea"
                elif input_tag.name == "select":
                    input_info["type"] = "select"
                    options = []
                    for opt in input_tag.find_all("option"):
                        options.append({"value": opt.get("value", ""), "text": opt.text})
                    input_info["options"] = options
                inputs.append(input_info)

            forms.append(DiscoveredForm(
                action_url=action_url,
                method=method,
                inputs=inputs,
                page_url=page_url,
            ))
        return forms

    def _extract_scripts_from_soup(
        self,
        soup: BeautifulSoup,
        page_url: str,
    ) -> List[str]:
        """从页面中提取 JavaScript 文件 URL."""
        scripts = []
        for script in soup.find_all("script", src=True):
            src = script["src"]
            full = self._normalize_url(src, page_url)
            if full:
                scripts.append(full)
        return scripts

    def _extract_comments_from_soup(
        self,
        soup: BeautifulSoup,
        _page_url: str,
    ) -> List[str]:
        """从 HTML 中提取注释."""
        comments = []
        for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
            text = str(comment).strip()
            if text:
                comments.append(text)
        return comments

    def _normalize_url(self, href: str, base_url: str) -> Optional[str]:
        """规范化 URL：相对路径 → 绝对路径，跳过无效协议."""
        if not href or href.startswith("data:") or href.startswith("javascript:"):
            return None
        if href.startswith("#"):
            return None
        if href.startswith("//"):
            href = "https:" + href

        full = urljoin(base_url, href)
        parsed = urlparse(full)

        # 只保留 http/https
        if parsed.scheme not in ("http", "https"):
            return None

        # 去除 fragment
        cleaned = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, parsed.query, ""
        ))
        return cleaned

    def _should_include(self, url: str, base_domain: str) -> bool:
        """判断 URL 是否应被包含在爬取范围内."""
        parsed = urlparse(url)
        if self._same_origin_only and parsed.netloc != base_domain:
            return False
        # 跳过常见非 HTML 静态资源
        skip_extensions = {".jpg", ".jpeg", ".png", ".gif", ".svg",
                           ".ico", ".woff", ".woff2", ".ttf", ".eot",
                           ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz"}
        ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
        if f".{ext}" in skip_extensions:
            return False
        return True
