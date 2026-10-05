"""Automated Canvas web-session auth (PennKey + Duo) for headless servers."""

from .manager import (
    SessionManager,
    get_session_manager,
    is_auto_auth_enabled,
    reset_session_manager,
)
from .pennkey import BadCredentialsError, DuoError, LoginError
from .settings import AuthConfigError, AuthSettings, get_auth_mode

__all__ = [
    "AuthConfigError",
    "AuthSettings",
    "BadCredentialsError",
    "DuoError",
    "LoginError",
    "SessionManager",
    "get_auth_mode",
    "get_session_manager",
    "is_auto_auth_enabled",
    "reset_session_manager",
]
