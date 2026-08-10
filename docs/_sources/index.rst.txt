.. auth-middleware documentation master file, created by
   sphinx-quickstart on Fri Apr  5 22:23:20 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Auth Middleware Documentation
=============================

**Auth Middleware** is a modern, high-performance authentication and authorization middleware for FastAPI and Starlette applications. It provides seamless integration with popular identity providers like AWS Cognito, Azure Entra ID, and Google, while supporting custom authentication providers.

.. image:: https://img.shields.io/pypi/v/auth-middleware.svg
   :target: https://pypi.org/project/auth-middleware/
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/pyversions/auth-middleware.svg
   :target: https://pypi.org/project/auth-middleware/
   :alt: Python Version

.. image:: https://img.shields.io/badge/license-MIT-blue.svg
   :target: https://github.com/impalah/auth-middleware/blob/main/LICENSE
   :alt: License

Key Features
============

* **JWT Authentication**: Secure JWT token validation and processing
* **Multiple Providers**: AWS Cognito, Azure Entra ID, Google, and custom providers
* **Group-based Authorization**: Fine-grained access control with user groups
* **Permission System**: Flexible permission-based authorization
* **High Performance**: Async-first design for maximum throughput
* **Easy Integration**: Simple middleware setup with minimal configuration
* **OpenAPI Support**: Automatic API documentation with security schemas
* **Type Safety**: Full TypeScript-style type hints for better development experience

Quick Start
===========

Installation::

   pip install auth-middleware

Basic usage with a generic OIDC issuer (works with AWS Cognito, Authentik,
Keycloak, Auth0, Okta, ...):

.. code-block:: python

   from fastapi import FastAPI, Depends
   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.guards import require_user
   from auth_middleware.providers.oidc.oidc_provider import OidcProvider
   from auth_middleware.providers.oidc.oidc_provider_settings import (
       OidcProviderSettings,
   )

   app = FastAPI(title="My Secure API")

   # Configure OIDC authentication. For AWS Cognito, the issuer is
   # https://cognito-idp.{region}.amazonaws.com/{user_pool_id}
   auth_settings = OidcProviderSettings(
       issuer="https://your-issuer.example.com",
       audience="your-client-id",
       jwt_token_verification_disabled=False,
   )

   # Add authentication middleware
   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=OidcProvider(settings=auth_settings),
   )

   @app.get("/protected", dependencies=[Depends(require_user())])
   async def protected_endpoint(request):
       return {"message": f"Hello {request.state.current_user.name}"}
======================

.. toctree::
   :maxdepth: 2
   :caption: Getting Started:

   installation
   user-guide
   middleware-configuration

.. toctree::
   :maxdepth: 2
   :caption: Infrastructure Setup:

   infrastructure

.. toctree::
   :maxdepth: 2
   :caption: Authentication Providers:

   entra_id_provider
   oidc_provider

.. toctree::
   :maxdepth: 2
   :caption: Advanced Topics:

   groups-provider
   permissions-provider
   extending-authz-providers
   user-property
   auth-authn
   services
   jwks-cache
   jwt_bearer_manager
   exceptions

.. toctree::
   :maxdepth: 2
   :caption: API Reference:

   api
   types
   functions

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
