Control Authentication and Authorization
========================================

There are two utility functions to control the authentication and authorization. These functions return an HttpException if the auth/authn fails.

The functions can be invoked directly or can be used as a dependency in frameworks as FastAPI.

To check if a user is logged in use require_user:

.. code-block:: python

   require_user()

To check if a user has assigned a group or groups use require_groups:

.. code-block:: python

   require_groups(["group1", "group2"])