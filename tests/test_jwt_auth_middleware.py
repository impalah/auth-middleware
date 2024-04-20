import pytest
from fastapi import Request, Response
from starlette import status
from starlette.responses import JSONResponse

from auth_middleware.exceptions import InvalidTokenException
from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
from auth_middleware.jwt_bearer_manager import JWTBearerManager
from auth_middleware.types import User


class MockJWTAuthProvider:
    def create_user_from_token(self, token):
        return User(
            id="user_id", name="John Doe", groups=["admin"], email="john@example.com"
        )


class MockJWTBearerManager:
    async def get_credentials(self, request):
        return JWTBearerManager(token="valid_token")


class MockInvalidTokenJWTBearerManager:
    async def get_credentials(self, request):
        raise InvalidTokenException


@pytest.mark.asyncio
def test_dispatch_with_valid_token():
    middleware = JwtAuthMiddleware(MockJWTAuthProvider())
    middleware._jwt_bearer_manager = MockJWTBearerManager()

    async def mock_call_next(request):
        return Response("OK")

    request = Request({"Authorization": "Bearer valid_token"})
    response = middleware.dispatch(request, mock_call_next)

    assert response.status_code == status.HTTP_200_OK
    assert request.state.current_user.id == "user_id"
    assert request.state.current_user.name == "John Doe"
    assert request.state.current_user.groups == ["admin"]
    assert request.state.current_user.email == "john@example.com"


def test_dispatch_with_invalid_token():
    middleware = JwtAuthMiddleware(MockJWTAuthProvider())
    middleware._jwt_bearer_manager = MockInvalidTokenJWTBearerManager()

    async def mock_call_next(request):
        return Response("OK")

    request = Request({"Authorization": "Bearer invalid_token"})
    response = middleware.dispatch(request, mock_call_next)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json() == {"detail": "Invalid token"}


def test_dispatch_with_server_error():
    middleware = JwtAuthMiddleware(MockJWTAuthProvider())

    async def mock_call_next(request):
        raise Exception("Server error")

    request = Request({"Authorization": "Bearer valid_token"})
    response = middleware.dispatch(request, mock_call_next)

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json() == {"detail": "Server error: Server error"}


def test_get_current_user_with_valid_token():
    middleware = JwtAuthMiddleware(MockJWTAuthProvider())
    middleware._jwt_bearer_manager = MockJWTBearerManager()

    request = Request({"Authorization": "Bearer valid_token"})
    user = middleware.get_current_user(request)

    assert user.id == "user_id"
    assert user.name == "John Doe"
    assert user.groups == ["admin"]
    assert user.email == "john@example.com"


def test_get_current_user_with_invalid_token():
    middleware = JwtAuthMiddleware(MockJWTAuthProvider())
    middleware._jwt_bearer_manager = MockInvalidTokenJWTBearerManager()

    request = Request({"Authorization": "Bearer invalid_token"})
    user = middleware.get_current_user(request)

    assert user is None


def test_get_current_user_with_no_credentials():
    middleware = JwtAuthMiddleware(MockJWTAuthProvider())

    request = Request({})
    user = middleware.get_current_user(request)

    assert user is None
