.. _authentik-infrastructure-setup:

Authentik Infrastructure Setup
===============================

This guide walks you through setting up `Authentik <https://goauthentik.io/>`_ as an OpenID Connect identity provider for use with ``auth-middleware``'s :doc:`../oidc_provider`. It covers creating the OAuth2/OIDC provider and application, mapping groups into the token, creating users, and testing the setup.

Prerequisites
=============

Before starting, ensure you have:

- A running Authentik instance (self-hosted or Authentik Cloud) with admin access
- Access to the Authentik admin interface, normally at ``https://authentik.example.com/if/admin/``

Step 1: Create an OAuth2/OpenID Provider
=========================================

1. **Navigate to Providers**

   - In the admin interface, go to **Applications** → **Providers**
   - Click **Create**
   - Select **OAuth2/OpenID Provider** and click **Next**

2. **Configure the Provider**

   - **Name**: A descriptive name, e.g. ``myapp-oidc-provider``
   - **Authorization flow**: Select an existing authorization flow (the ``default-provider-authorization-implicit-consent`` flow works for most setups)
   - **Client type**:

     - **Confidential** — for server-side applications that can keep a client secret (recommended for ``auth-middleware``, since token verification happens server-side)
     - **Public** — for SPAs/mobile apps that cannot keep a secret

   - **Client ID**: Leave auto-generated, or set your own — you'll need this for ``OidcProviderSettings.audience``
   - **Client Secret**: Auto-generated for confidential clients — only needed if your application also performs the OAuth2 login flow itself (``auth-middleware`` only verifies tokens, it doesn't need the secret)
   - **Redirect URIs**: Add your application's callback URL(s) if it performs the login flow directly
   - **Signing Key**: Select (or generate) an RSA keypair — this is what signs the JWTs and is required for the RS256 tokens ``OidcProvider`` verifies

3. **Configure Scopes**

   - Under **Advanced protocol settings**, ensure the **Scopes** include at least ``openid``, ``email``, and ``profile``
   - See :ref:`authentik-groups-claim` below to also include a ``groups`` claim

4. **Save the Provider**

   - Click **Finish**

Step 2: Create an Application
==============================

The provider alone isn't reachable by clients — it must be bound to an **Application**, whose *slug* becomes part of your OIDC issuer URL.

1. **Navigate to Applications**

   - Go to **Applications** → **Applications**
   - Click **Create**

2. **Configure the Application**

   - **Name**: e.g. ``My App``
   - **Slug**: e.g. ``my-app`` — this determines the issuer URL:
     ``https://authentik.example.com/application/o/my-app/``
   - **Provider**: Select the provider created in Step 1
   - Click **Create**

.. _authentik-groups-claim:

Step 3: Include Groups in the Token (Optional)
===============================================

By default, Authentik's standard scopes don't include a ``groups`` claim. To use ``OidcProviderSettings.groups_claim`` (instead of a separate :class:`~auth_middleware.contracts.groups_provider.GroupsProvider`), add a custom scope mapping:

1. **Create a Scope Mapping**

   - Go to **Customization** → **Property Mappings**
   - Click **Create** → **Scope Mapping**
   - **Name**: ``groups``
   - **Scope name**: ``groups``
   - **Expression**:

     .. code-block:: python

        return {"groups": [group.name for group in request.user.ak_groups.all()]}

   - Click **Finish**

2. **Attach the Scope to Your Provider**

   - Go back to **Applications** → **Providers** → your provider
   - Under **Advanced protocol settings** → **Scopes**, add the ``groups`` scope you just created
   - Save

Step 4: Create Groups and Users
================================

1. **Create Groups**

   - Go to **Directory** → **Groups**
   - Click **Create**, name it e.g. ``admin``
   - Repeat for any other groups your application needs (e.g. ``user``)

2. **Create Users**

   - Go to **Directory** → **Users**
   - Click **Create**, fill in username/email, set a password under the user's **Credentials**
   - Add the user to a group: open the user, go to the **Groups** tab, and add them

Step 5: Testing Your Setup
===========================

Fetch the discovery document to confirm the provider is reachable:

.. code-block:: bash

   curl https://authentik.example.com/application/o/my-app/.well-known/openid-configuration

It should return a JSON document including ``issuer`` and ``jwks_uri``.

To obtain a token for testing (Resource Owner Password flow, if enabled on your authorization flow):

.. code-block:: bash

   curl -X POST https://authentik.example.com/application/o/token/ \
     -d "grant_type=password" \
     -d "client_id=your-client-id" \
     -d "client_secret=your-client-secret" \
     -d "username=user@example.com" \
     -d "password=user_password" \
     -d "scope=openid email profile groups"

Configuration Summary
======================

.. code-block:: yaml

   Issuer: https://authentik.example.com/application/o/my-app/
   Client ID: your-client-id
   Discovery URL: https://authentik.example.com/application/o/my-app/.well-known/openid-configuration

Configure auth-middleware
==========================

.. code-block:: python

   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.oidc.oidc_provider import OidcProvider
   from auth_middleware.providers.oidc.oidc_provider_settings import (
       OidcProviderSettings,
   )

   auth_settings = OidcProviderSettings(
       issuer="https://authentik.example.com/application/o/my-app/",
       audience="your-client-id",
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

   - Confirm the provider's **Signing Key** is set — without it, Authentik may issue unsigned or differently-signed tokens
   - Check that the discovery document's ``jwks_uri`` is reachable from your application server

2. **Groups missing from the token**

   - Confirm the ``groups`` scope mapping (Step 3) is attached to the provider, not just created
   - Confirm the client actually requests the ``groups`` scope when obtaining tokens
   - Alternatively, use a dedicated :class:`~auth_middleware.contracts.groups_provider.GroupsProvider` — it takes precedence over ``groups_claim`` when both are configured, so it's the more robust option if you'd rather not maintain the scope mapping

3. **"aud" mismatch / token rejected**

   - Ensure ``OidcProviderSettings.audience`` matches the provider's **Client ID** exactly

4. **Wrong issuer**

   - The issuer must match the **Application slug**, not the provider name — ``https://<host>/application/o/<app-slug>/``

Security Best Practices
========================

1. Use a **Confidential** client type when your application can keep the client secret server-side
2. Keep the signing RSA key private to Authentik — never export it
3. Use short-lived access/ID tokens and rely on refresh tokens for long sessions
4. Restrict the ``groups`` scope mapping expression to only the fields you need
5. Serve Authentik over HTTPS only

Next Steps
==========

1. Configure ``auth-middleware`` with your Authentik settings as shown above
2. Test the authentication flow end-to-end from your application
3. Implement authorization rules using ``require_groups``/``require_roles``/``require_permissions``
4. Deploy Authentik and your application with production-grade TLS and monitoring

For implementation details, see the :doc:`../oidc_provider` documentation.
