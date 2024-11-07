# auth-middleware

Async Auth Middleware for FastAPI/Starlette.

## Installation

Using pip:

```bash
pip install auth-middleware
```

Using poetry

```bash
poetry add auth-middleware
```

## How to use it

Auth Middleware follows the middleware protocol and, therefore, should be added as a middleware to your FastApi or Starlette application.

The steps, using FastAPI:

```python

from fastapi import FastAPI, Depends

from starlette.requests import Request
from starlette.responses import Response

# Step 1: import the functions to control authentication
from auth_middleware.functions import require_groups, require_user
# Step 2: import the Middleware to use
from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
# Step 3: import the auth provider
from auth_middleware.providers.cognito import CognitoProvider

app: FastAPI = FastAPI()

# Step 4: Add Middleware with a Cognito auth Provider
app.add_middleware(JwtAuthMiddleware, auth_provider=CognitoProvider())

@app.get("/",
    dependencies=[
        # Step 5: add the authorization dependencies you want: require_user or requiere_groups
        # Depends(require_groups(["customer", "administrator"])),
        Depends(require_user()),
    ],)
async def root(request: Request):
    # Step 6: user information will be available in the request.state.current_user object
    return {"message": f"Hello {request.state.current_user.name}"}

```

Then set the environment variables (or your .env file)

```bash
AWS_COGNITO_USER_POOL_ID=your_cognito_user_pool_id
AWS_COGNITO_USER_POOL_REGION=your_cognito_user_pool_region

```

Call the method sending the id_token provided by Cognito:

```bash
curl -X GET http://localhost:8000/ -H "Authorization: Bearer MY_ID_TOKEN"
```

## Middleware configuration

The middleware configuration is done by environment variables (or using and .env file if your project uses python-dotenv).

The main variables are shwon in the table below:

| Name                                        | Description                             | Values                                | Default                                                                |
| ------------------------------------------- | --------------------------------------- | ------------------------------------- | ---------------------------------------------------------------------- |
| AUTH_MIDDLEWARE_LOG_LEVEL                   | Log level for the application           | DEBUG, INFO, WARNING, ERROR, CRITICAL | INFO                                                                   |
| AUTH_MIDDLEWARE_LOG_FORMAT                  | Log format                              | See python logger documentation       | %(log_color)s%(levelname)-9s%(reset)s %(asctime)s %(name)s %(message)s |
| AUTH_MIDDLEWARE_LOGGER_NAME                 | Auth middleware logger name             | A string                              | auth_middleware                                                        |
| AUTH_MIDDLEWARE_DISABLED                    | Auth middleware enabled/disabled        | false, true                           | false                                                                  |
| AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES | JWKS keys file refreshing interval      | An integer value                      | 20                                                                     |
| AUTH_MIDDLEWARE_JWKS_CACHE_USAGES           | JWKS keys refreshing interval (counter) | An integer value                      | 1000                                                                   |

## The User property

After authentication the Request object contains ifnormation about the current user in the state.current_user variable.

The table below shows the properties of the user object.

| Property | Description                                           |
| -------- | ----------------------------------------------------- |
| id       | Id of the user in the identity provider               |
| name     | User name (or id if not defined)                      |
| email    | User email (if any)                                   |
| groups   | Array of user groups as sent by the identity provider |

## Control authentication and authorization

There are two utility functions to control the authentication and authorization. These functions return an HttpException if the auth/authn fails.

The functions can be invoked directly or can be used as a dependency in frameworks as FastAPI.

To check if a user is logged in use require_user:

```python
require_user()
```

To check if a user has assigned a group or groups use require_groups:

```python
require_groups(["group1", "group2"])
```

## Authentication providers

### Amazon Cognito

TODO

### Azure Entra ID

TODO

### Google Idp

TODO

## Custom auth provider

TODO
