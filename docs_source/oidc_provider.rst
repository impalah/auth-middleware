Generic OIDC Provider
======================

``OidcProvider`` is a JWT authentication provider for any standards-compliant
OpenID Connect identity provider — `Authentik <https://goauthentik.io/>`_,
`Keycloak <https://www.keycloak.org/>`_, Auth0, Okta, or any other issuer
that exposes a ``.well-known/openid-configuration`` discovery document and a
JWKS endpoint. Unlike :doc:`cognito_provider` and :doc:`entra_id_provider`,
it is not tied to a specific cloud vendor.

Overview
--------

The OIDC provider handles:

* **JWKS discovery** — the signing keys are fetched automatically from
  ``{issuer}/.well-known/openid-configuration`` (or an explicit ``jwks_uri``),
  and cached the same way as the other providers.
* **Signature verification** and validation of the ``exp``/``nbf`` claims
  (with configurable clock-skew leeway).
* **Issuer validation** (``iss``) — always enforced.
* **Audience validation** (``aud``) — enforced when ``audience`` is
  configured. Strongly recommended: without it, any token signed by the
  issuer for *any* client of that issuer is accepted.
* **Claim mapping** — the claims used for the user's display name and
  groups are configurable, since different providers name them differently
  (OIDC's own convention is ``preferred_username`` and ``groups``, which are
  also Authentik's defaults).

Configuration
-------------

Basic Configuration
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.oidc.oidc_provider import OidcProvider
   from auth_middleware.providers.oidc.oidc_provider_settings import (
       OidcProviderSettings,
   )

   # Configure the OIDC settings — this example targets an Authentik
   # application, but the same settings work for any OIDC-compliant IdP.
   auth_settings = OidcProviderSettings(
       issuer="https://authentik.example.com/application/o/my-app/",
       audience="your-oidc-client-id",
   )

   # Create the provider
   auth_provider = OidcProvider(settings=auth_settings)

   # Add to FastAPI application
   app.add_middleware(JwtAuthMiddleware, auth_provider=auth_provider)

.. warning::

   ``audience`` is optional but strongly recommended, for the same reason
   as Cognito's ``user_pool_client_id``: without it, the provider only
   checks that the token was signed by the configured issuer, not which
   client it was issued for.

Explicit JWKS URL
~~~~~~~~~~~~~~~~~

By default the JWKS URL is discovered from the issuer's OIDC discovery
document on first use, and cached afterwards. If your IdP doesn't expose
standard discovery, or you want to skip that extra request, set
``jwks_uri`` explicitly:

.. code-block:: python

   auth_settings = OidcProviderSettings(
       issuer="https://authentik.example.com/application/o/my-app/",
       audience="your-oidc-client-id",
       jwks_uri="https://authentik.example.com/application/o/my-app/jwks/",
   )

Claim Mapping
~~~~~~~~~~~~~

Different identity providers use different claim names for the user's
display name and group memberships. Configure them to match your IdP:

.. code-block:: python

   auth_settings = OidcProviderSettings(
       issuer="https://idp.example.com/",
       audience="your-client-id",
       username_claim="upn",       # default: "preferred_username"
       groups_claim="roles",       # default: "groups"
   )

Set ``groups_claim=None`` to disable reading groups from the token claims
entirely — useful if groups should come from a separate
:class:`~auth_middleware.contracts.groups_provider.GroupsProvider` instead
(e.g. :doc:`groups-provider` backed by SQL).

Clock-Skew Leeway
~~~~~~~~~~~~~~~~~~

If the server clocks of your application and identity provider can drift,
allow a small grace period when validating ``exp``/``nbf``:

.. code-block:: python

   auth_settings = OidcProviderSettings(
       issuer="https://idp.example.com/",
       audience="your-client-id",
       jwt_leeway=30,  # seconds, default 0
   )

Example: Authentik
-------------------

See :doc:`infrastructure/authentik-setup` for how to create the
Authentik-side OAuth2/OIDC provider and application, and how to include
group membership in the token.

.. code-block:: python

   from fastapi import FastAPI, Depends
   from starlette.requests import Request
   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.guards import require_user, require_groups
   from auth_middleware.providers.oidc.oidc_provider import OidcProvider
   from auth_middleware.providers.oidc.oidc_provider_settings import (
       OidcProviderSettings,
   )

   app = FastAPI(title="Authentik Example API")

   auth_settings = OidcProviderSettings(
       issuer="https://authentik.example.com/application/o/my-app/",
       audience="your-oidc-client-id",
       groups_claim="groups",  # see the Authentik setup guide to enable this
   )

   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=OidcProvider(settings=auth_settings),
   )

   @app.get("/profile", dependencies=[Depends(require_user())])
   async def get_profile(request: Request):
       user = request.state.current_user
       return {"user": user.name, "email": user.email, "groups": await user.groups}

   @app.get("/admin", dependencies=[Depends(require_groups(["admins"]))])
   async def admin_only():
       return {"message": "Admin access granted"}

Example: Keycloak
------------------

See :doc:`infrastructure/keycloak-setup` for how to create the realm and
client in Keycloak, and how to map group membership into the token.

.. code-block:: python

   from fastapi import FastAPI, Depends
   from starlette.requests import Request
   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.guards import require_user, require_groups
   from auth_middleware.providers.oidc.oidc_provider import OidcProvider
   from auth_middleware.providers.oidc.oidc_provider_settings import (
       OidcProviderSettings,
   )

   app = FastAPI(title="Keycloak Example API")

   auth_settings = OidcProviderSettings(
       issuer="https://keycloak.example.com/realms/myapp",
       audience="my-app",
       groups_claim="groups",  # see the Keycloak setup guide to enable this
   )

   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=OidcProvider(settings=auth_settings),
   )

   @app.get("/profile", dependencies=[Depends(require_user())])
   async def get_profile(request: Request):
       user = request.state.current_user
       return {"user": user.name, "email": user.email, "groups": await user.groups}

   @app.get("/admin", dependencies=[Depends(require_groups(["admins"]))])
   async def admin_only():
       return {"message": "Admin access granted"}

Building Your Own Provider
---------------------------

If your identity provider isn't OIDC-compliant, or you need behavior
``OidcProvider`` doesn't cover, subclass the
:class:`~auth_middleware.contracts.jwt_provider.JWTProvider` contract
directly and implement ``load_jwks``, ``verify_token``, and
``create_user_from_token`` — this is exactly how ``CognitoProvider``,
``EntraIDProvider``, and ``OidcProvider`` itself are built. See
:doc:`extending-authz-providers` for the equivalent pattern on the
authorization side (groups/roles/permissions providers).

API Reference
-------------

.. automodule:: auth_middleware.providers.oidc.oidc_provider
   :members:

.. automodule:: auth_middleware.providers.oidc.oidc_provider_settings
   :members:

For more information about setting up an identity provider or other
authentication providers, see:

* :doc:`infrastructure/authentik-setup` - Authentik OAuth2/OIDC provider setup
* :doc:`infrastructure/keycloak-setup` - Keycloak realm and client setup
* :doc:`cognito_provider` - AWS Cognito integration
* :doc:`entra_id_provider` - Azure Entra ID integration
