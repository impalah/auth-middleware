"""CognitoAuthService — wraps AWS Cognito Identity Provider operations."""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any
from urllib.parse import quote

try:
    from botocore.exceptions import ClientError as _ClientError
except ImportError:
    _ClientError = Exception  # type: ignore[assignment, misc]

from auth_middleware.exceptions.cognito_exceptions import (
    AuthenticationError,
    InvalidChallengeError,
    MfaSetupError,
    PasswordPolicyError,
    UserNotFoundError,
)
from auth_middleware.services.cognito_auth_models import (
    ChallengeResponse,
    ForgotPasswordResponse,
    LoginResponse,
    MeResponse,
    MessageResponse,
    TokenResponse,
    TotpSetupResponse,
)

# Mapping from Cognito challenge names to simplified names
_CHALLENGE_MAP: dict[str, str] = {
    "SOFTWARE_TOKEN_MFA": "MFA_TOTP",  # nosec B105 - Cognito challenge type name, not a password
    "SMS_MFA": "SMS_MFA",
    "NEW_PASSWORD_REQUIRED": "NEW_PASSWORD_REQUIRED",  # nosec B105 - Cognito challenge type name, not a password
}


def _error_code(exc: Exception) -> str | None:
    """Extract Cognito error code from a ClientError without importing botocore at module level."""
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code")
    return None


class CognitoAuthService:
    """Wraps AWS Cognito Identity Provider operations for authentication and user sessions."""

    def __init__(
        self,
        client_id: str,
        user_pool_id: str,
        region: str,
        client_secret: str | None = None,
        cognito_client: Any | None = None,
    ) -> None:
        """Initialise the service with Cognito connection parameters.

        Args:
            client_id: The Cognito app client ID.
            user_pool_id: The Cognito user pool ID.
            region: AWS region name.
            client_secret: Optional app client secret for SECRET_HASH computation.
            cognito_client: Optional pre-configured boto3 Cognito IDP client.
                When omitted a default client is created using ambient credentials.
        """
        self._client_id = client_id
        self._client_secret = client_secret
        self._user_pool_id = user_pool_id
        self._region = region
        if cognito_client is not None:
            self._cognito = cognito_client
        else:
            import boto3  # lazy import — boto3 is optional at module level

            self._cognito = boto3.client("cognito-idp", region_name=self._region)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _secret_hash(self, username: str) -> str | None:
        """Compute CLIENT_SECRET_HASH required when the app client has a secret."""
        if not self._client_secret:
            return None
        message = username + self._client_id
        dig = hmac.new(
            self._client_secret.encode("utf-8"),
            msg=message.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        return base64.b64encode(dig).decode()

    def _auth_params(self, username: str, password: str) -> dict[str, str]:
        """Build the AUTH_PARAMETERS dict for Cognito InitiateAuth, adding SECRET_HASH when required."""
        params: dict[str, str] = {"USERNAME": username, "PASSWORD": password}
        secret_hash = self._secret_hash(username)
        if secret_hash:
            params["SECRET_HASH"] = secret_hash
        return params

    def _tokens_from_result(self, auth_result: dict[str, Any]) -> TokenResponse:
        """Convert a Cognito AuthenticationResult dict into a TokenResponse."""
        return TokenResponse(
            access_token=auth_result["AccessToken"],
            id_token=auth_result["IdToken"],
            refresh_token=auth_result.get("RefreshToken"),
            expires_in=auth_result.get("ExpiresIn", 3600),
        )

    def _map_challenge(self, cognito_name: str) -> str:
        """Translate a Cognito challenge name to this application's simplified challenge name."""
        return _CHALLENGE_MAP.get(cognito_name, cognito_name)

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def login(self, username: str, password: str) -> LoginResponse:
        """Initiate password-based authentication via Cognito; returns tokens or a challenge."""
        try:
            resp = self._cognito.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters=self._auth_params(username, password),
                ClientId=self._client_id,
            )
        except _ClientError as exc:
            code = _error_code(exc) or ""
            if code in ("NotAuthorizedException", "UserNotFoundException"):
                raise AuthenticationError() from exc
            if code == "PasswordResetRequiredException":
                raise AuthenticationError("Password reset required") from exc
            raise

        if "ChallengeName" in resp:
            challenge_name = self._map_challenge(resp["ChallengeName"])
            return LoginResponse(
                challenge=ChallengeResponse(
                    challenge=challenge_name,  # type: ignore[arg-type]
                    session=resp["Session"],
                )
            )

        return LoginResponse(tokens=self._tokens_from_result(resp["AuthenticationResult"]))

    def respond_to_challenge(
        self, session: str, challenge: str, response: str, username: str | None = None
    ) -> LoginResponse:
        """Submit a challenge response to Cognito (e.g., MFA code or new password)."""
        cognito_challenge = {v: k for k, v in _CHALLENGE_MAP.items()}.get(challenge, challenge)

        challenge_responses: dict[str, str] = {"USERNAME": username or ""}
        if challenge == "MFA_TOTP":
            challenge_responses["SOFTWARE_TOKEN_MFA_CODE"] = response
        elif challenge == "SMS_MFA":
            challenge_responses["SMS_MFA_CODE"] = response
        elif challenge == "NEW_PASSWORD_REQUIRED":
            challenge_responses["NEW_PASSWORD"] = response

        secret_hash = self._secret_hash(username or "")
        if secret_hash:
            challenge_responses["SECRET_HASH"] = secret_hash

        try:
            resp = self._cognito.respond_to_auth_challenge(
                ClientId=self._client_id,
                ChallengeName=cognito_challenge,
                Session=session,
                ChallengeResponses=challenge_responses,
            )
        except _ClientError as exc:
            code = _error_code(exc) or ""
            if code in ("CodeMismatchException", "ExpiredCodeException", "NotAuthorizedException"):
                raise InvalidChallengeError() from exc
            if code == "InvalidPasswordException":
                raise PasswordPolicyError() from exc
            raise

        if "ChallengeName" in resp:
            challenge_name = self._map_challenge(resp["ChallengeName"])
            return LoginResponse(
                challenge=ChallengeResponse(
                    challenge=challenge_name,  # type: ignore[arg-type]
                    session=resp["Session"],
                )
            )

        return LoginResponse(tokens=self._tokens_from_result(resp["AuthenticationResult"]))

    def logout(self, access_token: str) -> MessageResponse:
        """Invalidate all sessions for the user (Cognito global sign-out)."""
        try:
            self._cognito.global_sign_out(AccessToken=access_token)
        except _ClientError as exc:
            code = _error_code(exc) or ""
            if code == "NotAuthorizedException":
                raise AuthenticationError("Token is invalid or expired") from exc
            raise
        return MessageResponse(message="Logged out successfully")

    def refresh(self, refresh_token: str) -> TokenResponse:
        """Obtain a new access token using a valid refresh token."""
        try:
            resp = self._cognito.initiate_auth(
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={"REFRESH_TOKEN": refresh_token},
                ClientId=self._client_id,
            )
        except _ClientError as exc:
            code = _error_code(exc) or ""
            if code == "NotAuthorizedException":
                raise AuthenticationError("Refresh token is invalid or expired") from exc
            raise
        return self._tokens_from_result(resp["AuthenticationResult"])

    def get_user(self, access_token: str) -> MeResponse:
        """Return profile and group membership for the token owner."""
        try:
            resp = self._cognito.get_user(AccessToken=access_token)
        except _ClientError as exc:
            code = _error_code(exc) or ""
            if code == "NotAuthorizedException":
                raise AuthenticationError() from exc
            raise

        attributes = {a["Name"]: a["Value"] for a in resp.get("UserAttributes", [])}

        groups: list[str] = []
        try:
            groups_resp = self._cognito.admin_list_groups_for_user(
                Username=resp["Username"],
                UserPoolId=self._user_pool_id,
            )
            groups = [g["GroupName"] for g in groups_resp.get("Groups", [])]
        except _ClientError:
            pass  # Groups are informational — don't fail the whole request

        return MeResponse(
            sub=attributes.get("sub", resp["Username"]),
            email=attributes.get("email"),
            email_verified=attributes.get("email_verified") == "true",
            name=attributes.get("name"),
            groups=groups,
            bio=attributes.get("custom:bio"),
            avatar_url=attributes.get("custom:avatar_url"),
        )

    def change_password(
        self, access_token: str, current_password: str, new_password: str
    ) -> MessageResponse:
        """Change the authenticated user's password in Cognito."""
        try:
            self._cognito.change_password(
                AccessToken=access_token,
                PreviousPassword=current_password,
                ProposedPassword=new_password,
            )
        except _ClientError as exc:
            code = _error_code(exc) or ""
            if code == "NotAuthorizedException":
                raise AuthenticationError("Current password is incorrect") from exc
            if code == "InvalidPasswordException":
                raise PasswordPolicyError() from exc
            raise
        return MessageResponse(message="Password changed successfully")

    def forgot_password(self, username: str) -> ForgotPasswordResponse:
        """Trigger a password-reset code to be sent to the user's registered email or phone."""
        params: dict[str, Any] = {"ClientId": self._client_id, "Username": username}
        secret_hash = self._secret_hash(username)
        if secret_hash:
            params["SecretHash"] = secret_hash
        try:
            resp = self._cognito.forgot_password(**params)
        except _ClientError as exc:
            code = _error_code(exc) or ""
            if code == "UserNotFoundException":
                raise UserNotFoundError() from exc
            raise
        delivery = resp["CodeDeliveryDetails"]
        return ForgotPasswordResponse(
            delivery_medium=delivery.get("DeliveryMedium", "EMAIL"),
            destination=delivery.get("Destination", ""),
        )

    def reset_password(
        self, username: str, code: str, new_password: str
    ) -> MessageResponse:
        """Complete the password-reset flow using the verification code sent to the user."""
        params: dict[str, Any] = {
            "ClientId": self._client_id,
            "Username": username,
            "ConfirmationCode": code,
            "Password": new_password,
        }
        secret_hash = self._secret_hash(username)
        if secret_hash:
            params["SecretHash"] = secret_hash
        try:
            self._cognito.confirm_forgot_password(**params)
        except _ClientError as exc:
            code_err = _error_code(exc) or ""
            if code_err in ("CodeMismatchException", "ExpiredCodeException"):
                raise InvalidChallengeError("Invalid or expired reset code") from exc
            if code_err == "InvalidPasswordException":
                raise PasswordPolicyError() from exc
            if code_err == "UserNotFoundException":
                raise UserNotFoundError() from exc
            raise
        return MessageResponse(message="Password reset successfully")

    def setup_totp(self, access_token: str) -> TotpSetupResponse:
        """Begin TOTP MFA setup. Returns the shared secret and a QR URI for authenticator apps."""
        try:
            resp = self._cognito.associate_software_token(AccessToken=access_token)
        except _ClientError as exc:
            raise MfaSetupError() from exc
        secret = resp["SecretCode"]
        qr_uri = f"otpauth://totp/{quote(self._client_id)}?secret={secret}"
        return TotpSetupResponse(secret_code=secret, qr_uri=qr_uri)

    def verify_totp(
        self, access_token: str, code: str, device_name: str
    ) -> MessageResponse:
        """Verify the TOTP code and activate MFA on the account."""
        try:
            self._cognito.verify_software_token(
                AccessToken=access_token,
                UserCode=code,
                FriendlyDeviceName=device_name,
            )
            self._cognito.set_user_mfa_preference(
                AccessToken=access_token,
                SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
            )
        except _ClientError as exc:
            code_err = _error_code(exc) or ""
            if code_err in ("CodeMismatchException", "EnableSoftwareTokenMFAException"):
                raise MfaSetupError("Invalid TOTP code") from exc
            raise
        return MessageResponse(message="TOTP MFA enabled successfully")

    def disable_totp(self, access_token: str) -> MessageResponse:
        """Disable TOTP MFA for the authenticated user."""
        try:
            self._cognito.set_user_mfa_preference(
                AccessToken=access_token,
                SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
            )
        except _ClientError as exc:
            raise MfaSetupError("Failed to disable TOTP MFA") from exc
        return MessageResponse(message="TOTP MFA disabled")
