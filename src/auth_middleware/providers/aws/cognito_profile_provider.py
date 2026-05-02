from typing import Any

from auth_middleware.contracts.profile_provider import ProfileProvider
from auth_middleware.logging import logger


class CognitoProfileProvider(ProfileProvider):
    """Fetches user profile from Cognito User Pool custom attributes.

    Calls ``AdminGetUser`` using a Boto3 client. The returned dict maps
    each custom attribute name (e.g. ``custom:first_name``) directly to
    its value, with no transformation — callers decide how to normalise
    the keys for their API contracts.

    Args:
        user_pool_id: The Cognito User Pool ID (e.g. ``us-east-1_abc123``).
        region_name: AWS region where the User Pool lives.
        boto_client: Optional pre-configured boto3 Cognito IDP client.
            When omitted a default client is created using ambient credentials.
    """

    def __init__(
        self,
        user_pool_id: str,
        region_name: str,
        boto_client: Any | None = None,
    ) -> None:
        self._user_pool_id = user_pool_id
        if boto_client is not None:
            self._client = boto_client
        else:
            import boto3  # lazy import — boto3 is optional at module level

            self._client = boto3.client("cognito-idp", region_name=region_name)

    async def fetch_profile(self, user_id: str) -> dict[str, Any]:
        """Return Cognito custom attributes for the given Cognito sub.

        Args:
            user_id: Cognito ``sub`` of the user.

        Returns:
            Flat dict of all custom (and standard) Cognito attributes.
            Empty dict if the user is not found or an error occurs.
        """
        try:
            response = self._client.admin_get_user(
                UserPoolId=self._user_pool_id,
                Username=user_id,
            )
        except Exception as exc:
            # Catch ClientError from botocore without importing it at module level
            error_code: str | None = None
            if hasattr(exc, "response") and isinstance(exc.response, dict):
                error_code = exc.response.get("Error", {}).get("Code")
            if error_code == "UserNotFoundException":
                logger.warning("CognitoProfileProvider: user {} not found", user_id)
                return {}
            logger.error(
                "CognitoProfileProvider: error fetching profile for {}: {}",
                user_id,
                str(exc),
            )
            return {}

        attributes: list[dict[str, str]] = response.get("UserAttributes", [])
        return {attr["Name"]: attr["Value"] for attr in attributes}
