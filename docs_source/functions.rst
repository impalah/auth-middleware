Authentication Functions
========================

This module provides utility functions and decorators for authentication and authorization. These functions make it easy to protect your FastAPI endpoints and implement fine-grained access control.

.. note::
   All guard functions live in the ``auth_middleware.guards`` package. Import them from
   ``auth_middleware.guards`` or from the specific sub-module
   ``auth_middleware.guards.functions``.

Authentication Decorators
-------------------------

require_user()
~~~~~~~~~~~~~

Requires that a user is authenticated to access an endpoint.

.. code-block:: python

   from fastapi import FastAPI, Depends
   from auth_middleware.guards import require_user

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

   from auth_middleware.guards import require_groups

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

   from auth_middleware.guards import require_permissions

   @app.post("/data", dependencies=[Depends(require_permissions(["write"]))])
   async def create_data(request):
       return {"message": "Data created"}

   # Multiple permissions (user must have all)
   @app.delete("/sensitive", dependencies=[Depends(require_permissions(["admin", "delete"]))])
   async def delete_sensitive(request):
       return {"message": "Sensitive data deleted"}

require_roles()
~~~~~~~~~~~~~~

Requires that the authenticated user has specific roles.

.. code-block:: python

   from auth_middleware.guards import require_roles

   @app.get("/reports", dependencies=[Depends(require_roles(["analyst", "manager"]))])
   async def get_reports(request):
       return {"message": "Reports access granted"}

Utility Functions
-----------------

get_current_user()
~~~~~~~~~~~~~~~~~

Retrieves the current authenticated user from the request state.

.. code-block:: python

   from auth_middleware.guards import get_current_user

   @app.get("/user-info")
   async def get_user_info(user = Depends(get_current_user)):
       if user:
           return {
               "authenticated": True,
               "user_id": user.id,
               "name": user.name
           }
       return {"authenticated": False}

Checker Classes
---------------

The guards package also exposes three standalone checker classes for building
custom dependency chains.

GroupChecker
~~~~~~~~~~~

.. code-block:: python

   from auth_middleware.guards import GroupChecker

   # Used internally by require_groups() — can also be used directly
   checker = GroupChecker(groups=["admin"])

RoleChecker
~~~~~~~~~~

.. code-block:: python

   from auth_middleware.guards import RoleChecker

   checker = RoleChecker(roles=["analyst"])

PermissionsChecker
~~~~~~~~~~~~~~~~~

.. code-block:: python

   from auth_middleware.guards import PermissionsChecker

   checker = PermissionsChecker(permissions=["write"])

Advanced Usage Examples
-----------------------

Combining Requirements
~~~~~~~~~~~~~~~~~~~~~

You can combine multiple authentication requirements:

.. code-block:: python

   from fastapi import Depends
   from auth_middleware.guards import require_user, require_groups, require_permissions

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
   from auth_middleware.guards import get_current_user

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
   from auth_middleware.guards import get_current_user

   def require_user_or_api_key():
       async def check_auth(request, user = Depends(get_current_user)):
           if user:
               return user

           api_key = request.headers.get("X-API-Key")
           if api_key and validate_api_key(api_key):
               return {"type": "api_key", "key": api_key}

           raise HTTPException(status_code=401, detail="Authentication required")

       return check_auth

   @app.get("/api/data", dependencies=[Depends(require_user_or_api_key())])
   async def get_api_data(request):
       return {"data": "Sensitive information"}

Error Handling
--------------

The authentication functions automatically raise appropriate HTTP exceptions:

.. code-block:: python

   # require_user()        raises HTTPException(401) if not authenticated
   # require_groups()      raises HTTPException(403) if user lacks required groups
   # require_permissions() raises HTTPException(403) if user lacks permissions
   # require_roles()       raises HTTPException(403) if user lacks required roles

API Reference
-------------

.. automodule:: auth_middleware.guards.functions
   :members:

.. automodule:: auth_middleware.guards.group_checker
   :members:

.. automodule:: auth_middleware.guards.role_checker
   :members:

.. automodule:: auth_middleware.guards.permissions_checker
   :members:
