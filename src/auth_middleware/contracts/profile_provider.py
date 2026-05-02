from abc import ABCMeta, abstractmethod
from typing import Any


class ProfileProvider(metaclass=ABCMeta):
    """Abstract contract for fetching user profile attributes.

    Implementations may read from Cognito User Pool custom attributes,
    a local database, or any other store. The returned dict has no fixed
    schema — keys and values are defined by each deployment.
    """

    @abstractmethod
    async def fetch_profile(self, user_id: str) -> dict[str, Any]:
        """Return profile attributes for the given user ID.

        Args:
            user_id: The subject (``sub``) claim identifying the user.

        Returns:
            Arbitrary key-value mapping of profile attributes.
            Returns an empty dict when no profile is found.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
