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

* 🔐 **JWT Authentication**: Secure JWT token validation and processing
* 🏢 **Multiple Providers**: AWS Cognito, Azure Entra ID, Google, and custom providers
* 👥 **Group-based Authorization**: Fine-grained access control with user groups
* 🛡️ **Permission System**: Flexible permission-based authorization
* ⚡ **High Performance**: Async-first design for maximum throughput
* 🔧 **Easy Integration**: Simple middleware setup with minimal configuration
* 📊 **OpenAPI Support**: Automatic API documentation with security schemas
* 🎯 **Type Safety**: Full TypeScript-style type hints for better development experience

Quick Start
===========

Installation::

   pip install auth-middleware

Basic usage with AWS Cognito:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from auth_middleware import JwtAuthMiddleware, require_user
   from auth_middleware.providers.authn.cognito_provider import CognitoProvider
   from auth_middleware.providers.authn.cognito_authz_provider_settings import (
       CognitoAuthzProviderSettings,
   )

   app = FastAPI(title="My Secure API")

   # Configure Cognito authentication
   auth_settings = CognitoAuthzProviderSettings(
       user_pool_id="your_user_pool_id",
       user_pool_region="your_aws_region",
       jwt_token_verification_disabled=False,
   )

   # Add authentication middleware
   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=CognitoProvider(settings=auth_settings),
   )

   @app.get("/protected", dependencies=[Depends(require_user())])
   async def protected_endpoint(request):
       return {"message": f"Hello {request.state.current_user.name}"}

Documentation Contents
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

   cognito_provider
   entra_id_provider
   jwt_auth_provider

.. toctree::
   :maxdepth: 2
   :caption: Advanced Topics:

   groups-provider
   permissions-provider
   extending-authz-providers
   user-property
   auth-authn
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
