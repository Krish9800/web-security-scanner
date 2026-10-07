"""Unit tests for AsyncRequester with mock transports and scope validation."""

import httpx
import pytest

from webscan.core.requester import AsyncRequester
from webscan.core.scope import ScopeGuardian, ScopeViolationError


@pytest.mark.asyncio
async def test_async_requester_get_and_post() -> None:
    """Test standard GET and POST requests using mock HTTP transport."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"status": "ok", "path": str(request.url.path)})
        elif request.method == "POST":
            return httpx.Response(201, json={"created": True})
        return httpx.Response(405)

    transport = httpx.MockTransport(handler)

    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["127.0.0.1", "localhost"]),
        rate_limit_rps=100.0,
    )
    # Inject mock client
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        res_get = await requester.get("http://127.0.0.1:8000/api/status")
        assert res_get.status_code == 200
        assert res_get.json()["status"] == "ok"

        res_post = await requester.post("http://localhost:8000/api/items", json={"name": "test"})
        assert res_post.status_code == 201
        assert res_post.json()["created"] is True


@pytest.mark.asyncio
async def test_async_requester_blocks_out_of_scope() -> None:
    """Test that AsyncRequester rejects out-of-scope targets before sending requests."""
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
    )
    async with requester:
        with pytest.raises(ScopeViolationError, match="outside authorized scanning scope"):
            await requester.get("https://unauthorized-victim.org/login")


@pytest.mark.asyncio
async def test_async_requester_redirect_in_scope_and_out_of_scope() -> None:
    """Test redirect following within scope and blocking when redirecting out of scope."""

    def redirect_handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://localhost:8000/start":
            return httpx.Response(302, headers={"Location": "http://localhost:8000/final"})
        elif str(request.url) == "http://localhost:8000/final":
            return httpx.Response(200, text="Landed safely")
        elif str(request.url) == "http://localhost:8000/evil_redirect":
            return httpx.Response(302, headers={"Location": "https://evil-attacker.com/steal"})
        return httpx.Response(404)

    transport = httpx.MockTransport(redirect_handler)
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        # In-scope redirect succeeds
        res = await requester.get("http://localhost:8000/start", follow_redirects=True)
        assert res.status_code == 200
        assert res.text == "Landed safely"

        # Out-of-scope redirect raises ScopeViolationError
        with pytest.raises(ScopeViolationError, match="outside authorized scanning scope"):
            await requester.get("http://localhost:8000/evil_redirect", follow_redirects=True)
