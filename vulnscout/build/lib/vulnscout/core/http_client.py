"""异步 HTTP 客户端 -- 封装 httpx，支持代理、Cookie、UA 轮换."""

from __future__ import annotations

import random
from typing import Dict, Optional

import httpx
from httpx import URL as HttpxURL

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]


class HttpClient:
    """异步 HTTP 客户端，支持会话、代理、超时和重试."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_redirects: int = 5,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        random_ua: bool = True,
        retry_count: int = 2,
        delay: float = 0.0,
        **kwargs,
    ):
        self._timeout = timeout
        self._max_redirects = max_redirects
        self._proxy = proxy
        self._random_ua = random_ua
        self._retry_count = retry_count
        self._delay = delay
        self._custom_headers = headers or {}
        self._extra_kwargs = kwargs

        # 在首次使用时再创建 client，方便异步上下文
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            limits = httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
            )
            transport = httpx.AsyncHTTPTransport(
                retries=0,  # 我们自己控制重试
            )
            client_kwargs = dict(
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=False,  # 手动控制重定向
                limits=limits,
                transport=transport,
                **self._extra_kwargs,
            )
            if self._proxy:
                client_kwargs["proxy"] = self._proxy

            self._client = httpx.AsyncClient(**client_kwargs)
        return self._client

    def _build_headers(self) -> Dict[str, str]:
        """构建请求头，支持 UA 随机轮换."""
        headers = dict(self._custom_headers)
        if self._random_ua:
            headers.setdefault("User-Agent", random.choice(_USER_AGENTS))
        else:
            headers.setdefault("User-Agent", _USER_AGENTS[0])
        headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        headers.setdefault("Accept-Language", "en-US,en;q=0.5")
        return headers

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """发起 HTTP 请求，自动重试."""
        headers = self._build_headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        last_exc = None
        for attempt in range(self._retry_count + 1):
            try:
                response = await self.client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    **kwargs,
                )
                return response
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt < self._retry_count:
                    continue
                raise httpx.RequestError(f"请求失败 (重试{self._retry_count}次): {url}") from last_exc

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET 请求."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, data: Optional[Dict] = None, **kwargs) -> httpx.Response:
        """POST 请求."""
        return await self.request("POST", url, content=data, **kwargs)

    async def close(self):
        """关闭 HTTP 客户端."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
