# auth-middleware

Async Auth Middleware for FastAPI/Starlette.

## Installation

Using pip:

```bash
pip install auth-middleware
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

TODO

## The User property
TODO

## Control authentication and authorization

TODO

## Authentication providers

### Amazon Cognito

TODO

### Azure Entra ID

TODO


### Google Idp

TODO

