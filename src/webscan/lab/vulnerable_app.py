"""Embedded vulnerable target application for offline E2E verification and security lab testing."""

import logging
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

logger = logging.getLogger(__name__)


def create_vulnerable_test_app() -> FastAPI:
    """Create a FastAPI application with deliberate vulnerabilities for testing."""
    app = FastAPI(
        title="WebScan Vulnerable Target Lab",
        description="Deliberately insecure testing ground for web-security-scanner verification.",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def add_security_headers_and_banner(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        # Deliberately expose technical banner and insecure cookie
        response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
        response.headers["X-Powered-By"] = "PHP/7.4.3"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Root landing page with intentional links for crawling."""
        response = HTMLResponse(
            """<!DOCTYPE html>
<html>
<head><title>Vulnerable Security Lab</title></head>
<body>
  <h1>Security Testing Sandbox</h1>
  <ul>
    <li><a href="/search?q=test">Search Query (XSS)</a></li>
    <li><a href="/users?id=1">User Profile (SQLi)</a></li>
    <li><a href="/login?next=/dashboard">Authentication Gateway (Redirect)</a></li>
    <li><a href="/api/user">User API (CORS)</a></li>
  </ul>
</body>
</html>"""
        )
        response.set_cookie(key="session_id", value="insecure_cookie_12345")
        return response

    @app.get("/search", response_class=HTMLResponse)
    async def search(q: str = "") -> str:
        """Reflected XSS vulnerable parameter."""
        return f"<html><body><h1>Search Results for: {q}</h1></body></html>"

    @app.get("/users")
    async def users(user_id: str = Query("1", alias="id")) -> Response:
        """SQL error disclosure vulnerable parameter."""
        if "'" in user_id:
            return PlainTextResponse(
                'sqlite3.OperationalError: near "\'": syntax error in query',
                status_code=500,
            )
        return JSONResponse({"id": user_id, "username": "admin", "role": "superuser"})

    @app.get("/api/user")
    async def api_user(request: Request) -> JSONResponse:
        """CORS misconfiguration reflecting arbitrary Origin with credentials."""
        origin = request.headers.get("origin", "")
        headers = {}
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return JSONResponse(
            {"id": "usr_99", "name": "Admin Operator", "balance": 10000},
            headers=headers,
        )

    @app.get("/login")
    async def login(target: str = Query("", alias="next")) -> Response:
        """Open redirect vulnerable parameter."""
        if target:
            return RedirectResponse(url=target, status_code=302)
        return HTMLResponse("<html><body><h1>Login Form</h1></body></html>")

    @app.get("/.env", response_class=PlainTextResponse)
    async def dot_env() -> str:
        """Sensitive environment secrets file disclosure."""
        return "DB_PASSWORD=secret_postgres_pass\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n"

    @app.get("/.git/HEAD", response_class=PlainTextResponse)
    async def git_head() -> str:
        """Sensitive Git repository metadata exposure."""
        return "ref: refs/heads/main\n"

    @app.get("/robots.txt", response_class=PlainTextResponse)
    async def robots() -> str:
        """Robots exclusion policy file."""
        return "User-agent: *\nDisallow: /admin\nDisallow: /internal\n"

    @app.get("/.well-known/security.txt", response_class=PlainTextResponse)
    async def security_txt() -> str:
        """Security disclosure policy."""
        return "Contact: mailto:security@lab.local\n"

    @app.get("/backup.sql", response_class=PlainTextResponse)
    async def backup_sql() -> str:
        """Database backup file disclosure."""
        return (
            "CREATE TABLE users (id INT, secret VARCHAR(255));\n"
            "INSERT INTO users VALUES (1, 'classified_hash');\n"
        )

    @app.api_route("/api/methods", methods=["GET", "POST", "PUT", "TRACE", "OPTIONS"])
    async def api_methods(request: Request) -> Response:
        """Dangerous HTTP methods probe endpoint."""
        if request.method == "TRACE":
            return PlainTextResponse(f"TRACE {request.url.path} HTTP/1.1\r\nHost: test\r\n")
        if request.method == "PUT":
            return PlainTextResponse("Created via PUT", status_code=201)
        headers = {"Allow": "GET, POST, PUT, TRACE, OPTIONS"}
        return PlainTextResponse("Method probe OK", headers=headers)

    return app


def run_lab_server(host: str = "127.0.0.1", port: int = 8888) -> None:
    """Run vulnerable test target with uvicorn."""
    import uvicorn

    uvicorn.run(create_vulnerable_test_app(), host=host, port=port, log_level="warning")
