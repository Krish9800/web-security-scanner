"""FastAPI application initialization for web-security-scanner API microservice."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from webscan.api.routes import router

api_app = FastAPI(
    title="Web Security Scanner API",
    description="Enterprise REST microservice for automated web security scanning.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration for authorized security dashboard access
api_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_app.include_router(router)
