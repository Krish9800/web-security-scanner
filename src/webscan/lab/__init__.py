"""Security testing lab and vulnerable mock target package."""

from webscan.lab.vulnerable_app import create_vulnerable_test_app, run_lab_server

__all__ = [
    "create_vulnerable_test_app",
    "run_lab_server",
]
