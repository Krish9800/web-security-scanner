"""Asynchronous HTTP requester with rate limiting, scope verification, and timeout controls."""

import asyncio
import time
from typing import Any

import httpx

from webscan.config.settings import get_settings
from webscan.core.scope import ScopeGuardian


class AsyncRequester:
    """Asynchronous HTTP engine enforcing rate limits, concurrency bounds, and scope checks."""

    def __init__(
        self,
        scope_guardian: ScopeGuardian | None = None,
        timeout: float | None = None,
        concurrency: int | None = None,
        rate_limit_rps: float | None = None,
        custom_headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        verify_ssl: bool = True,
    ) -> None:
        settings = get_settings()
        self.scope_guardian = scope_guardian or ScopeGuardian()
        self.timeout = timeout if timeout is not None else settings.default_timeout_seconds
        self.concurrency = concurrency if concurrency is not None else settings.max_concurrency
        self.rate_limit_rps = (
            rate_limit_rps if rate_limit_rps is not None else settings.max_requests_per_second
        )
        self.verify_ssl = verify_ssl

        headers = {"User-Agent": settings.user_agent}
        if custom_headers:
            headers.update(custom_headers)

        self._client: httpx.AsyncClient | None = None
        self._default_headers = headers
        self._default_cookies = cookies or {}
        self._semaphore = asyncio.Semaphore(self.concurrency)
        self._min_interval = 1.0 / self.rate_limit_rps if self.rate_limit_rps > 0 else 0.0
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def get_client(self) -> httpx.AsyncClient:
        """Initialize or retrieve the underlying httpx.AsyncClient."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                headers=self._default_headers,
                cookies=self._default_cookies,
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=False,
            )
        return self._client

    async def close(self) -> None:
        """Close client session and release network resources."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "AsyncRequester":
        await self.get_client()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def _throttle(self) -> None:
        """Enforce rate limits across asynchronous coroutines."""
        if self._min_interval <= 0:
            return

        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_request_time = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute rate-limited, scope-checked HTTP request with bounded redirect loop."""
        self.scope_guardian.assert_in_scope(url)
        client = await self.get_client()

        current_url = url
        redirects_count = 0

        while True:
            await self._throttle()
            async with self._semaphore:
                response = await client.request(method, current_url, **kwargs)

            if (
                follow_redirects
                and response.is_redirect
                and "location" in response.headers
                and redirects_count < max_redirects
            ):
                redirects_count += 1
                redirect_url = str(response.next_request.url if response.next_request else "")
                if not redirect_url:
                    redirect_url = response.headers["location"]

                # Ensure redirect target is also in scope before following
                self.scope_guardian.assert_in_scope(redirect_url)
                current_url = redirect_url
                # Next hop for 301/302/303 is typically GET
                if response.status_code in (301, 302, 303):
                    method = "GET"
                    kwargs.pop("content", None)
                    kwargs.pop("data", None)
                    kwargs.pop("json", None)
                continue

            return response

    async def get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response:
        """Execute GET request."""
        return await self.request(
            "GET", url, params=params, headers=headers, follow_redirects=follow_redirects
        )

    async def post(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response:
        """Execute POST request."""
        return await self.request(
            "POST",
            url,
            data=data,
            json=json,
            headers=headers,
            follow_redirects=follow_redirects,
        )
