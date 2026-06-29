"""爬虫单元测试."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bs4 import BeautifulSoup

from vulnscout.core.crawler import Crawler, DiscoveredForm
from vulnscout.core.http_client import HttpClient


@pytest.fixture
def mock_http():
    """创建 mock HTTP 客户端."""
    client = AsyncMock(spec=HttpClient)
    return client


@pytest.fixture
def crawler(mock_http):
    """创建测试用爬虫."""
    return Crawler(
        http_client=mock_http,
        max_depth=2,
        max_pages=10,
        same_origin_only=True,
        extract_forms=True,
        extract_scripts=True,
        extract_comments=True,
    )


class TestLinkExtraction:
    """测试链接提取."""

    def test_normalize_url_absolute(self, crawler):
        """绝对路径保持不变."""
        result = crawler._normalize_url("https://example.com/page", "https://example.com/")
        assert result == "https://example.com/page"

    def test_normalize_url_relative(self, crawler):
        """相对路径转为绝对路径."""
        result = crawler._normalize_url("/page", "https://example.com/base/")
        assert result == "https://example.com/page"

    def test_normalize_url_skip_javascript(self, crawler):
        """跳过 javascript: 链接."""
        assert crawler._normalize_url("javascript:void(0)", "https://example.com/") is None

    def test_normalize_url_skip_fragment(self, crawler):
        """跳过纯片段链接."""
        assert crawler._normalize_url("#section", "https://example.com/") is None

    def test_normalize_url_skip_data_uri(self, crawler):
        """跳过 data: URI."""
        assert crawler._normalize_url("data:text/plain,hello", "https://example.com/") is None

    def test_should_include_same_origin(self, crawler):
        """同域名链接应被包含."""
        assert crawler._should_include("https://example.com/page", "example.com") is True

    def test_should_include_different_origin(self, crawler):
        """跨域名链接应被排除 (same_origin_only=True)."""
        assert crawler._should_include("https://other.com/page", "example.com") is False

    def test_should_include_skip_static(self, crawler):
        """静态资源应被排除."""
        assert crawler._should_include("https://example.com/image.jpg", "example.com") is False
        assert crawler._should_include("https://example.com/script.js", "example.com") is True


class TestFormExtraction:
    """测试表单提取."""

    def test_extract_basic_form(self, crawler):
        """提取基本表单."""
        html = '<form action="/login" method="POST"><input name="user"><input type="submit"></form>'
        soup = BeautifulSoup(html, "lxml")
        forms = crawler._extract_forms_from_soup(soup, "https://example.com/")
        assert len(forms) == 1
        assert forms[0].action_url == "https://example.com/login"
        assert forms[0].method == "POST"
        assert len(forms[0].inputs) == 2

    def test_extract_form_no_action(self, crawler):
        """无 action 的表单应使用当前页面 URL."""
        html = '<form method="GET"><input name="q"></form>'
        soup = BeautifulSoup(html, "lxml")
        forms = crawler._extract_forms_from_soup(soup, "https://example.com/search")
        assert forms[0].action_url == "https://example.com/search"


class TestScriptExtraction:
    """测试脚本提取."""

    def test_extract_scripts(self, crawler):
        """提取 JavaScript 文件 URL."""
        html = '<script src="/js/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
        soup = BeautifulSoup(html, "lxml")
        scripts = crawler._extract_scripts_from_soup(soup, "https://example.com/")
        assert len(scripts) == 2
        assert "https://example.com/js/app.js" in scripts
        assert "https://cdn.example.com/lib.js" in scripts


class TestCommentExtraction:
    """测试注释提取."""

    def test_extract_comments(self, crawler):
        """提取 HTML 注释."""
        html = '<!-- TODO: fix this --><p>text</p><!-- FIXME: security issue -->'
        soup = BeautifulSoup(html, "lxml")
        comments = crawler._extract_comments_from_soup(soup, "https://example.com/")
        assert len(comments) == 2
        assert "TODO: fix this" in comments
        assert "FIXME: security issue" in comments


@pytest.mark.asyncio
async def test_crawl_basic():
    """集成测试: 爬虫抓取真实页面."""
    async with HttpClient(timeout=10.0) as http:
        crawler = Crawler(http, max_depth=1, max_pages=3)
        result = await crawler.crawl("https://httpbin.org/links/5")

        assert result.pages_visited >= 1
        assert result.target_url == "https://httpbin.org/links/5"
