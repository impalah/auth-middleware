.. _keycloak-infrastructure-setup:

Keycloak Infrastructure Setup
==============================

This guide walks you through setting up `Keycloak <https://www.keycloak.org/>`_ as an OpenID Connect identity provider for use with ``auth-middleware``'s :doc:`../oidc_provider`. It covers creating a realm and client, mapping groups into the token, creating users, and testing the setup.

Prerequisites
=============

Before starting, ensure you have:

- A running Keycloak instance with admin access
- Access to the Keycloak admin console, normally at ``https://keycloak.example.com/admin/``

Step 1: Create a Realm
=======================

Realms isolate a set of users, clients, and roles from each other. Most applications get their own realm.

1. **Open the realm dropdown** (top-left of the admin console) → **Create Realm**
2. **Realm name**: e.g. ``myapp``
3. Click **Create**

All following steps assume you're working inside this realm.

Step 2: Create a Client
========================

1. **Navigate to Clients**

   - Go to **Clients** → **Create client**

2. **General Settings**

   - **Client type**: ``OpenID Connect``
   - **Client ID**: e.g. ``my-app`` — you'll need this for ``OidcProviderSettings.audience``
   - Click **Next**

3. **Capability Config**

   - **Client authentication**: **On** for a confidential client that can keep a secret (recommended for server-side apps), **Off** for a public client (SPA/mobile)
   - **Authentication flow**: enable the flows you need:

     - **Standard flow** (authorization code) — for browser-based login
     - **Direct access grants** — for the Resource Owner Password flow (useful for testing)
     - **Service accounts roles** — for machine-to-machine, client-credentials tokens

   - Click **Next**

4. **Login Settings**

   - **Valid redirect URIs**: your application's callback URL(s), if it performs the login flow directly
   - Click **Save**

5. **Client Secret** (confidential clients only)

   - Go to the client's **Credentials** tab to find the generated **Client secret** — only needed if your application performs the OAuth2 login flow itself (``auth-middleware`` only verifies tokens, it doesn't need the secret)

.. _keycloak-groups-claim:

Step 3: Include Groups in the Token (Optional)
================================================

To use ``OidcProviderSettings.groups_claim`` (instead of a separate :class:`~auth_middleware.contracts.groups_provider.GroupsProvider`), add a group-membership mapper:

1. **Navigate to Client Scopes**

   - Go to **Client scopes**, and either edit the client's dedicated scope (``my-app-dedicated``) or create a new reusable scope (e.g. ``groups``) and assign it to the client under the client's **Client scopes** tab

2. **Add a Mapper**

   - Open the scope, go to the **Mappers** tab → **Add mapper** → **By configuration** → **Group Membership**
   - **Name**: ``groups``
   - **Token Claim Name**: ``groups``
   - **Full group path**: **Off** (so you get plain group names like ``admin`` instead of ``/admin``)
   - **Add to ID token**: **On**
   - **Add to access token**: **On** (needed if your application authenticates with access tokens rather than ID tokens)
   - Click **Save**

Step 4: Create Groups and Users
================================

1. **Create Groups**

   - Go to **Groups** → **Create group**, name it e.g. ``admin``
   - Repeat for any other groups your application needs (e.g. ``user``)

2. **Create Users**

   - Go to **Users** → **Add user**, fill in username/email
   - After creating the user, go to the **Credentials** tab to set a password (toggle **Temporary** off for a permanent password in test setups)
   - Go to the **Groups** tab and join the user to a group

Step 5: Testing Your Setup
============================

Fetch the discovery document to confirm the realm is reachable:

.. code-block:: bash

   curl https://keycloak.example.com/realms/myapp/.well-known/openid-configuration

It should return a JSON document including ``issuer`` and ``jwks_uri``.

To obtain a token for testing (Direct Access Grants / Resource Owner Password flow):

.. code-block:: bash

   curl -X POST https://keycloak.example.com/realms/myapp/protocol/openid-connect/token \
     -d "grant_type=password" \
     -d "client_id=my-app" \
     -d "client_secret=your-client-secret" \
     -d "username=user@example.com" \
     -d "password=user_password"

Or, for machine-to-machine testing (Client Credentials flow):

.. code-block:: bash

   curl -X POST https://keycloak.example.com/realms/myapp/protocol/openid-connect/token \
     -d "grant_type=client_credentials" \
     -d "client_id=my-app" \
     -d "client_secret=your-client-secret"

Configuration Summary
======================

.. code-block:: yaml

   Issuer: https://keycloak.example.com/realms/myapp
   Client ID: my-app
   Discovery URL: https://keycloak.example.com/realms/myapp/.well-known/openid-configuration

Configure auth-middleware
==========================

.. code-block:: python

   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.oidc.oidc_provider import OidcProvider
   from auth_middleware.providers.oidc.oidc_provider_settings import (
       OidcProviderSettings,
   )

   auth_settings = OidcProviderSettings(
       issuer="https://keycloak.example.com/realms/myapp",
       audience="my-app",
       groups_claim="groups",  # only if you completed Step 3
   )

   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=OidcProvider(settings=auth_settings),
   )

Use these values as described in the :doc:`../oidc_provider` documentation.

Troubleshooting
================

1. **401 "No public key found"**

   - Confirm the discovery document's ``jwks_uri`` (usually
     ``https://keycloak.example.com/realms/myapp/protocol/openid-connect/certs``) is reachable from your application server
   - Realm keys are managed under **Realm settings** → **Keys** — ensure an active RS256 key pair exists

2. **Groups missing from the token**

   - Confirm the **Group Membership** mapper (Step 3) is attached to a scope the client actually requests
   - Check whether your token is an access token or ID token, and that the mapper is enabled for the one you're verifying
   - Alternatively, use a dedicated :class:`~auth_middleware.contracts.groups_provider.GroupsProvider` — it takes precedence over ``groups_claim`` when both are configured, so it's the more robust option if you'd rather not maintain the mapper

3. **"aud" mismatch / token rejected**

   - By default, Keycloak access tokens may not include your client in the ``aud`` claim unless "Add to audience" is configured. Either add an **Audience** mapper for your client, or omit ``OidcProviderSettings.audience`` and rely on ``iss`` validation alone (less strict, but works with default Keycloak tokens)

4. **Wrong issuer**

   - The issuer is realm-scoped: ``https://<host>/realms/<realm-name>`` — not the client name or a per-application path

Security Best Practices
========================

1. Use **confidential** clients with client authentication enabled for server-side applications
2. Disable **Direct access grants** and **Implicit flow** in production unless you specifically need them
3. Rotate realm signing keys periodically (**Realm settings** → **Keys**)
4. Scope group/role mappers to only the claims your application needs
5. Serve Keycloak over HTTPS only, and keep it patched — it is a critical security component

Next Steps
==========

1. Configure ``auth-middleware`` with your Keycloak settings as shown above
2. Test the authentication flow end-to-end from your application
3. Implement authorization rules using ``require_groups``/``require_roles``/``require_permissions``
4. Deploy Keycloak and your application with production-grade TLS and monitoring

For implementation details, see the :doc:`../oidc_provider` documentation.
