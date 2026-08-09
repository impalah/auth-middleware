# Activate annotations for Python 3.7+ and from __future__ import annotations
from __future__ import annotations

from ksuid import Ksuid
from sqlalchemy import String, select
from sqlalchemy.orm import Mapped, mapped_column

from auth_middleware.contracts.permissions_provider import PermissionsProvider
from auth_middleware.logging import logger
from auth_middleware.types.jwt import JWTAuthorizationCredentials

from .async_database import AsyncDatabase
from .sql_base_model import Base


class PermissionsModel(Base):  # type: ignore[misc]
    """Repository permissions model

    Args:
        Base (_type_): SQLAlchemy base model
        BaseModel (_type_): base entity model
    """

    __tablename__ = "authz_permissions"

    id: Mapped[str] = mapped_column(
        String(27),
        primary_key=True,
        default=lambda: str(Ksuid()),
        index=True,
    )

    username: Mapped[str] = mapped_column(String(500), nullable=False)
    permission: Mapped[str] = mapped_column(String(100), nullable=False)


class SqlPermissionsProvider(PermissionsProvider):
    """Recovers permissions from a SQL database, keyed by an identifier
    claim from the JWT.

    Args:
        id_claim (str): name of the JWT claim used as the lookup key when
            ``fetch_permissions`` is called with a
            ``JWTAuthorizationCredentials``. Defaults to ``"username"``
            (Cognito's convention) for backward compatibility. Identity
            providers name this claim differently — e.g. Entra ID/OIDC
            providers typically use ``"preferred_username"`` (or the
            always-present, provider-agnostic ``"sub"``) instead.
    """

    def __init__(self, *, id_claim: str = "username") -> None:
        self._id_claim = id_claim

    async def fetch_permissions(
        self, token: str | JWTAuthorizationCredentials
    ) -> list[str]:
        """Get groups using the token provided

        Args:
            token (JWTAuthorizationCredentials | str): The token containing the claims.

        Raises:
            ValueError: If a JWTAuthorizationCredentials token is missing
                the configured id_claim.

        Returns:
            List[str]: _description_
        """

        # 1. Get the lookup identifier from the token
        if isinstance(token, JWTAuthorizationCredentials):
            identifier = token.claims.get(self._id_claim)
            if identifier is None:
                raise ValueError(
                    f"Token is missing the '{self._id_claim}' claim required "
                    "to look up permissions. Pass a different id_claim to "
                    "SqlPermissionsProvider matching a claim your identity "
                    "provider actually issues (e.g. 'preferred_username' or "
                    "'sub')."
                )
        else:
            identifier = token

        # 2. Check if permissions are in the cache

        # 3. If not in cache, fetch from the database
        permissions: list[str] = await self.get_permissions_from_db(username=identifier)

        # 4. Return the permissions
        return permissions

    async def get_permissions_from_db(
        self,
        *,
        username: str,
    ) -> list[str]:
        """Gets permissions from the database

        Args:
            username (str): Username

        Returns:
            List[str]: List of permissions
        """

        logger.debug("Username: {}", username)

        try:
            async with AsyncDatabase.get_session() as session:
                query = select(PermissionsModel).filter(
                    PermissionsModel.username == username
                )

                result = await session.execute(query)

                scalars = result.scalars()
                items: list[PermissionsModel] = list(scalars.all())
                return [item.permission for item in items]

        except Exception as ex:
            logger.exception("AsyncDatabase error")
            raise ex
