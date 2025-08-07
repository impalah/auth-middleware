from typing import Any

from pydantic import BaseModel

JWK = dict[str, Any]


class JWKS(BaseModel):
    keys: list[JWK] | None = []
    timestamp: int | None = None
    usage_counter: int | None = 0


class JWTAuthorizationCredentials(BaseModel):
    jwt_token: str
    header: dict[str, str]
    claims: dict[str, Any]
    signature: str
    message: str
