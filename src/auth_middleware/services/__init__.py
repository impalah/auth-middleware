"""Services module for auth-middleware."""

from auth_middleware.providers.aws.services.cognito_auth_models import (
    ChallengeRequest,
    ChallengeResponse,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    LoginResponse,
    MeResponse,
    MessageResponse,
    RefreshRequest,
    ResetPasswordRequest,
    TokenResponse,
    TotpSetupResponse,
    VerifyTotpRequest,
)
from auth_middleware.providers.aws.services.cognito_auth_service import (
    CognitoAuthService,
)
from auth_middleware.providers.aws.services.m2m_detector import M2MTokenDetector
from auth_middleware.services.audit import AuditEvent, AuditLogger, AuditMiddleware
from auth_middleware.services.metrics import MetricsCollector
from auth_middleware.services.rate_limiter import RateLimiter, rate_limit

__all__ = [
    "CognitoAuthService",
    "ChallengeRequest",
    "ChallengeResponse",
    "ChangePasswordRequest",
    "ForgotPasswordRequest",
    "ForgotPasswordResponse",
    "LoginRequest",
    "LoginResponse",
    "MeResponse",
    "MessageResponse",
    "RefreshRequest",
    "ResetPasswordRequest",
    "TokenResponse",
    "TotpSetupResponse",
    "VerifyTotpRequest",
    "M2MTokenDetector",
    "RateLimiter",
    "rate_limit",
    "AuditEvent",
    "AuditLogger",
    "AuditMiddleware",
    "MetricsCollector",
]
