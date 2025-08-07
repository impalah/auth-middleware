Authentication Functions
========================

This module provides utility functions and decorators for authentication and authorization. These functions make it easy to protect your FastAPI endpoints and implement fine-grained access control.

Authentication Decorators
-------------------------

require_user()
~~~~~~~~~~~~~

Requires that a user is authenticated to access an endpoint.

.. code-block:: python

   from fastapi import FastAPI, Depends
   from auth_middleware import require_user

   app = FastAPI()

   @app.get("/profile", dependencies=[Depends(require_user())])
   async def get_profile(request):
       user = request.state.current_user
       return {
           "id": user.id,
           "name": user.name,
           "email": user.email
       }

require_groups()
~~~~~~~~~~~~~~~

Requires that the authenticated user belongs to specific groups.

.. code-block:: python

   from auth_middleware import require_groups

   @app.get("/admin", dependencies=[Depends(require_groups(["administrators"]))])
   async def admin_panel(request):
       return {"message": "Admin access granted"}

   # Multiple groups (user must be in at least one)
   @app.get("/staff", dependencies=[Depends(require_groups(["managers", "supervisors"]))])
   async def staff_area(request):
       return {"message": "Staff access granted"}

require_permissions()
~~~~~~~~~~~~~~~~~~~~

Requires that the authenticated user has specific permissions.

.. code-block:: python

   from auth_middleware import require_permissions

   @app.post("/data", dependencies=[Depends(require_permissions(["write"]))])
   async def create_data(request):
       return {"message": "Data created"}

   # Multiple permissions (user must have all)
   @app.delete("/sensitive", dependencies=[Depends(require_permissions(["admin", "delete"]))])
   async def delete_sensitive(request):
       return {"message": "Sensitive data deleted"}

Utility Functions
----------------

get_current_user()
~~~~~~~~~~~~~~~~~

Retrieves the current authenticated user from the request state.

.. code-block:: python

   from auth_middleware import get_current_user

   @app.get("/user-info")
   async def get_user_info(user = Depends(get_current_user)):
       if user:
           return {
               "authenticated": True,
               "user_id": user.id,
               "name": user.name
           }
       return {"authenticated": False}

is_authenticated()
~~~~~~~~~~~~~~~~~

Checks if the current request has an authenticated user.

.. code-block:: python

   from auth_middleware import is_authenticated

   @app.get("/status")
   async def get_status(request):
       auth_status = is_authenticated(request)
       return {
           "authenticated": auth_status,
           "timestamp": datetime.utcnow().isoformat()
       }

Advanced Usage Examples
----------------------

Combining Requirements
~~~~~~~~~~~~~~~~~~~~~

You can combine multiple authentication requirements:

.. code-block:: python

   from fastapi import Depends
   from auth_middleware import require_user, require_groups, require_permissions

   # Requires user to be authenticated AND in admin group AND have delete permission
   @app.delete(
       "/admin/users/{user_id}",
       dependencies=[
           Depends(require_user()),
           Depends(require_groups(["administrators"])),
           Depends(require_permissions(["user:delete"]))
       ]
   )
   async def delete_user(user_id: str, request):
       return {"message": f"User {user_id} deleted"}

Optional Authentication
~~~~~~~~~~~~~~~~~~~~~~

For endpoints that work with or without authentication:

.. code-block:: python

   from typing import Optional
   from auth_middleware import get_current_user

   @app.get("/public-data")
   async def get_public_data(user: Optional[dict] = Depends(get_current_user)):
       base_data = {"public": "This is public information"}
       
       if user:
           base_data["private"] = "This is additional info for authenticated users"
           base_data["user_name"] = user.name
       
       return base_data

Custom Authorization Logic
~~~~~~~~~~~~~~~~~~~~~~~~~

Create custom authorization functions:

.. code-block:: python

   from fastapi import HTTPException, Depends
   from auth_middleware import get_current_user

   def require_user_or_api_key():
       async def check_auth(request, user = Depends(get_current_user)):
           # Check for user authentication
           if user:
               return user
           
           # Check for API key
           api_key = request.headers.get("X-API-Key")
           if api_key and validate_api_key(api_key):
               return {"type": "api_key", "key": api_key}
           
           raise HTTPException(status_code=401, detail="Authentication required")
       
       return check_auth

   @app.get("/api/data", dependencies=[Depends(require_user_or_api_key())])
   async def get_api_data(request):
       return {"data": "Sensitive information"}

Conditional Access
~~~~~~~~~~~~~~~~~

Implement conditional access based on user properties:

.. code-block:: python

   def require_verified_email():
       async def check_verification(user = Depends(get_current_user)):
           if not user:
               raise HTTPException(status_code=401, detail="Authentication required")
           
           if not user.email_verified:
               raise HTTPException(
                   status_code=403,
                   detail="Email verification required"
               )
           
           return user
       
       return check_verification

   @app.post("/sensitive-action", dependencies=[Depends(require_verified_email())])
   async def sensitive_action(request):
       return {"message": "Action completed"}

Error Handling
--------------

The authentication functions automatically raise appropriate HTTP exceptions:

.. code-block:: python

   from fastapi import HTTPException
   
   # require_user() raises HTTPException(401) if not authenticated
   # require_groups() raises HTTPException(403) if user lacks required groups  
   # require_permissions() raises HTTPException(403) if user lacks permissions

You can customize error handling:

.. code-block:: python

   from fastapi.responses import JSONResponse
   from starlette.exceptions import HTTPException

   @app.exception_handler(HTTPException)
   async def custom_http_exception_handler(request, exc):
       if exc.status_code == 401:
           return JSONResponse(
               status_code=401,
               content={
                   "error": "authentication_required",
                   "message": "Please provide valid authentication credentials",
                   "login_url": "/auth/login"
               }
           )
       elif exc.status_code == 403:
           return JSONResponse(
               status_code=403,
               content={
                   "error": "access_denied",
                   "message": "You don't have permission to access this resource",
                   "required_permissions": getattr(exc, 'required_permissions', [])
               }
           )
       
       return JSONResponse(
           status_code=exc.status_code,
           content={"error": str(exc.detail)}
       )

API Reference
-------------

.. automodule:: auth_middleware.functions
   :members:
