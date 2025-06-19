"""API Routes Module"""

from .auth_routes import auth_router
from .scan_routes import scan_router
from .report_routes import report_router
from .webhook_routes import webhook_router
from .config_routes import config_router

__all__ = ["auth_router", "scan_router", "report_router", "webhook_router", "config_router"]