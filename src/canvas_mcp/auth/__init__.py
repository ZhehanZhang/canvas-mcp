"""Automated Canvas token retrieval (PennKey + Duo) for headless servers."""

from .manager import (
    TokenManager,
    get_token_manager,
    is_auto_auth_enabled,
    reset_token_manager,
)
from .pennkey import BadCredentialsError, DuoError, LoginError
from .settings import AuthConfigError, AuthSettings, get_auth_mode

__all__ = [
    "AuthConfigError",
    "AuthSettings",
    "BadCredentialsError",
    "DuoError",
    "LoginError",
    "TokenManager",
    "get_auth_mode",
    "get_token_manager",
    "is_auto_auth_enabled",
    "reset_token_manager",
]
