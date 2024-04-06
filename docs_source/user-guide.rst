User Guide
==========

Auth Middleware follows the middleware protocol and, therefore, should be added as a middleware to your FastApi or Starlette application.

The steps, using FastAPI:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from starlette.requests import Request
   from starlette.responses import Response
   from auth_middleware.functions import require_groups, require_user
   from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.cognito import CognitoProvider

   app: FastAPI = FastAPI()
   app.add_middleware(JwtAuthMiddleware, auth_provider=CognitoProvider())

   @app.get("/",
       dependencies=[
           Depends(require_user()),
       ],)
   async def root(request: Request):
       return {"message": f"Hello {request.state.current_user.name}"}

Then set the environment variables (or your .env file)

.. code-block:: bash

   AWS_COGNITO_USER_POOL_ID=your_cognito_user_pool_id
   AWS_COGNITO_USER_POOL_REGION=your_cognito_user_pool_region

Call the method sending the id_token provided by Cognito:

.. code-block:: bash

   curl -X GET http://localhost:8000/ -H "Authorization: Bearer MY_ID_TOKEN"