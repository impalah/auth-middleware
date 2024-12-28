# Activate annotations for Python 3.7+ and from __future__ import annotations
from __future__ import annotations

from typing import Any, Optional, List


from auth_middleware.types.jwt import JWTAuthorizationCredentials
from auth_middleware.logging import logger
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider


from ksuid import Ksuid


from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import select

from .sql_base_model import Base, BaseModel
from .async_database import AsyncDatabase


class PermissionsModel(Base):
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
    """Recovers groups from AWS Cognito using the token provided

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> List[str]:
        """Get groups using the token provided

        Args:
            token (JWTAuthorizationCredentials): _description_

        Raises:
            NotImplementedError: _description_

        Returns:
            List[str]: _description_
        """

        # 1. Get the username from the token
        username: str = token.claims["username"]

        # 2. Check if permissions are in the cache

        # 3. If not in cache, fetch from the database
        permissions: List[str] = await self.get_permissions_from_db(username=username)

        # 4. Return the permissions
        return permissions

    async def get_permissions_from_db(
        self,
        *,
        username: str,
    ) -> List[str]:
        """Gets permissions from the database

        Args:
            username (str): Username

        Returns:
            List[str]: List of permissions
        """

        logger.debug("Username: {}", username)

        # TODO: exception capture on init

        async with AsyncDatabase.get_session() as session:
            try:

                query = select(PermissionsModel).filter(
                    PermissionsModel.username == username
                )

                result = await session.execute(query)

                scalars = result.scalars()
                items: List[PermissionsModel] = scalars.all()
                return [item.permission for item in items]

            except Exception as ex:
                logger.exception("AsyncDatabase error")
                raise ex
