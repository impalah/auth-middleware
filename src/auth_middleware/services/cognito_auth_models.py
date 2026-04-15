"""Pydantic request/response models for Cognito-based authentication."""

from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

class BaseLoginRequest(BaseModel):
    username: str = Field(..., description="Username or email")


class LoginRequest(BaseLoginRequest):
    """Credentials payload for the initial login step."""

    password: str = Field(..., description="User password")


class ChallengeRequest(BaseModel):
    """Payload for responding to an authentication challenge (MFA or forced password change)."""

    session: str = Field(..., description="Opaque session token returned by /auth/login")
    challenge: Literal["MFA_TOTP", "SMS_MFA", "NEW_PASSWORD_REQUIRED"] = Field(
        ..., description="Challenge type"
    )
    response: str = Field(
        ..., description="OTP code (MFA) or new password (NEW_PASSWORD_REQUIRED)"
    )
    username: str = Field(..., description="Username submitted at the initial login step")


class RefreshRequest(BaseModel):
    """Payload for obtaining a new access token using a refresh token."""

    refresh_token: str = Field(..., description="Refresh token issued at login")


class ChangePasswordRequest(BaseModel):
    """Payload for changing the authenticated user's password."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., description="New password")


class ForgotPasswordRequest(BaseLoginRequest):
    """Payload for initiating the forgot-password flow (sends a verification code)."""
    ...


class ResetPasswordRequest(BaseLoginRequest):
    """Payload for completing a password reset using the emailed verification code."""

    code: str = Field(..., description="Verification code sent by Cognito")
    new_password: str = Field(..., description="New password")


class VerifyTotpRequest(BaseModel):
    """Payload for verifying and registering a TOTP MFA device."""

    code: str = Field(..., description="6-digit TOTP code")
    device_name: str = Field(default="My device", description="Friendly device name")


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


class TokenResponse(BaseModel):
    """JWT token set issued after successful authentication."""

    access_token: str
    id_token: str
    refresh_token: str | None = None
    expires_in: int
    token_type: str = "Bearer"


class ChallengeResponse(BaseModel):
    """Cognito authentication challenge requiring further user interaction."""

    challenge: Literal["MFA_TOTP", "SMS_MFA", "NEW_PASSWORD_REQUIRED"]
    session: str = Field(..., description="Opaque session token — send back in /auth/login/challenge")


class LoginResponse(BaseModel):
    """Login result: either a token set (success) or a challenge (further action required)."""

    tokens: TokenResponse | None = None
    challenge: ChallengeResponse | None = None


class MeResponse(BaseModel):
    """Authenticated user's profile and Cognito group memberships."""

    sub: str
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    groups: list[str] = Field(default_factory=list)
    bio: str | None = None
    avatar_url: str | None = None


class MessageResponse(BaseModel):
    """Generic single-message response for operations that return no resource."""

    message: str


class ForgotPasswordResponse(BaseModel):
    """Confirmation that the password-reset code has been dispatched."""

    delivery_medium: str = Field(..., description="EMAIL or SMS")
    destination: str = Field(..., description="Obfuscated delivery destination")


class TotpSetupResponse(BaseModel):
    """TOTP MFA setup data: secret and QR code URI to be shown to the user."""

    secret_code: str
    qr_uri: str
