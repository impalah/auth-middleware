"""
M2M Token Detection Service.

This module provides utilities to detect Machine-to-Machine (M2M) tokens
in AWS Cognito authentication flows.
"""

import logging
from typing import Any

from auth_middleware.types.jwt import JWTAuthorizationCredentials

logger = logging.getLogger(__name__)


class M2MTokenDetector:
    """Service to detect Machine-to-Machine (M2M) authentication tokens.

    M2M tokens are typically issued for service-to-service authentication
    and have different characteristics than user authentication tokens.

    Detection Criteria:
        1. Missing 'cognito:username' claim (Cognito-specific)
        2. 'token_use' is 'access' instead of 'id'
        3. Presence of 'client_id' without user context
        4. Missing user-specific claims (email, name, etc.)

    Example:
        ```python
        from auth_middleware.services.m2m_detector import M2MTokenDetector

        detector = M2MTokenDetector()
        is_m2m = detector.is_m2m_token(jwt_credentials)

        if is_m2m:
            client_id = detector.get_client_id(jwt_credentials)
            print(f"M2M token from client: {client_id}")
        ```
    """

    @staticmethod
    def is_m2m_token(token: JWTAuthorizationCredentials) -> bool:
        """Detect if a JWT token is a Machine-to-Machine token.

        Args:
            token: JWT authorization credentials to analyze

        Returns:
            True if token is M2M, False if it's a user token

        Example:
            ```python
            # User token
            user_token = JWTAuthorizationCredentials(...)
            assert detector.is_m2m_token(user_token) == False

            # M2M token
            m2m_token = JWTAuthorizationCredentials(...)
            assert detector.is_m2m_token(m2m_token) == True
            ```
        """
        claims = token.claims

        # Primary indicator: Missing cognito:username (Cognito-specific)
        has_cognito_username = "cognito:username" in claims or "username" in claims

        # Secondary indicators
        token_use = claims.get("token_use", "")
        has_client_id = "client_id" in claims
        has_email = "email" in claims
        has_name = "name" in claims or "given_name" in claims or "family_name" in claims

        # M2M tokens typically:
        # - Don't have username
        # - Are access tokens (not ID tokens)
        # - Have client_id but no user-specific claims
        is_m2m = (
            not has_cognito_username
            and (token_use == "access" or not token_use)
            and has_client_id
            and not has_email
            and not has_name
        )

        if is_m2m:
            logger.debug(
                f"Detected M2M token: client_id={claims.get('client_id')}, "
                f"token_use={token_use}"
            )
        else:
            logger.debug(
                f"Detected user token: username={claims.get('cognito:username') or claims.get('username')}"
            )

        return is_m2m

    @staticmethod
    def get_client_id(token: JWTAuthorizationCredentials) -> str | None:
        """Extract client ID from token.

        Args:
            token: JWT authorization credentials

        Returns:
            Client ID if present, None otherwise

        Example:
            ```python
            client_id = detector.get_client_id(m2m_token)
            # Output: "7a8b9c0d1e2f3g4h5i6j"
            ```
        """
        return token.claims.get("client_id")

    @staticmethod
    def get_token_metadata(token: JWTAuthorizationCredentials) -> dict[str, Any]:
        """Extract relevant metadata from token for analysis.

        Args:
            token: JWT authorization credentials

        Returns:
            Dictionary with token metadata

        Example:
            ```python
            metadata = detector.get_token_metadata(token)
            # Output: {
            #     'is_m2m': True,
            #     'client_id': '7a8b9c...',
            #     'token_use': 'access',
            #     'scopes': ['api/read', 'api/write'],
            #     'has_user_context': False
            # }
            ```
        """
        claims = token.claims
        is_m2m = M2MTokenDetector.is_m2m_token(token)

        metadata = {
            "is_m2m": is_m2m,
            "client_id": claims.get("client_id"),
            "token_use": claims.get("token_use"),
            "scopes": claims.get("scope", "").split() if claims.get("scope") else [],
            "has_user_context": bool(
                claims.get("cognito:username")
                or claims.get("username")
                or claims.get("email")
            ),
            "subject": claims.get("sub"),
        }

        if is_m2m:
            # M2M-specific metadata
            metadata["service_account"] = claims.get("client_id")
        else:
            # User-specific metadata
            metadata["username"] = claims.get("cognito:username") or claims.get(
                "username"
            )
            metadata["email"] = claims.get("email")

        return metadata

    @staticmethod
    def requires_user_context(token: JWTAuthorizationCredentials) -> bool:
        """Check if token requires user context for operations.

        M2M tokens don't have user context and shouldn't be used for
        user-specific operations.

        Args:
            token: JWT authorization credentials

        Returns:
            True if token has user context, False for M2M tokens

        Example:
            ```python
            if not detector.requires_user_context(token):
                raise HTTPException(
                    status_code=403,
                    detail="This operation requires user authentication"
                )
            ```
        """
        return not M2MTokenDetector.is_m2m_token(token)
