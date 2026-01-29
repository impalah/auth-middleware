.. _cognito-infrastructure-setup:

AWS Cognito Infrastructure Setup
================================

This guide walks you through setting up AWS Cognito infrastructure manually using the AWS Console. You'll create a User Pool, configure App Clients for different authentication flows, create users, and set up user groups.

Prerequisites
=============

Before starting, ensure you have:

- An active AWS account
- Appropriate IAM permissions to create and manage Cognito resources
- Access to the AWS Management Console

Step 1: Create a User Pool
==========================

1. **Navigate to Amazon Cognito**
   
   - Open the AWS Management Console
   - Search for "Cognito" and select "Amazon Cognito"
   - Click "Create user pool"

2. **Configure Sign-in Experience**
   
   - **Authentication providers**: Select "Cognito user pool"
   - **Cognito user pool sign-in options**: Choose your preferred options:
     - **Email** (recommended for most applications)
     - **Username** (optional, based on your needs)
     - **Phone number** (optional, requires SMS configuration)
   - Click "Next"

3. **Configure Security Requirements**
   
   - **Password policy**: Choose between "Cognito defaults" or "Custom"
     
     For custom policy, recommended settings:
     - Minimum length: 8 characters
     - Require numbers
     - Require special characters
     - Require uppercase letters
     - Require lowercase letters
   
   - **Multi-factor authentication**: 
     - **Optional** (recommended for production)
     - **Required** (for high-security applications)
   
   - **User account recovery**: Select preferred options:
     - **Email only** (most common)
     - **SMS and email** (if phone numbers are collected)
   
   - Click "Next"

4. **Configure Sign-up Experience**
   
   - **Self-service sign-up**: Enable if you want users to self-register
   - **Cognito-assisted verification**: Choose verification methods:
     - **Send email verification** (recommended)
     - **Send SMS verification** (if using phone numbers)
   
   - **Required attributes**: Select attributes to collect during sign-up:
     - **email** (strongly recommended)
     - **given_name** (optional)
     - **family_name** (optional)
     - **preferred_username** (optional)
   
   - **Custom attributes**: Add any application-specific attributes
   - Click "Next"

5. **Configure Message Delivery**
   
   - **Email provider**: 
     - **Send email with Cognito** (for testing/development)
     - **Send email with Amazon SES** (recommended for production)
   
   - **SMS**: Configure if using SMS verification
   - Click "Next"

6. **Integrate Your App**
   
   - **User pool name**: Enter a descriptive name (e.g., "MyApp-UserPool")
   - **Hosted authentication pages**: 
     - Check "Use the Cognito Hosted UI" if you want AWS-hosted login pages
     - Leave unchecked if you're building custom authentication UI
   
   - **Initial app client**: We'll configure this in the next step
     - **App client name**: Enter a temporary name (we'll create proper clients later)
     - **Client secret**: Select "Don't generate a client secret" for now
   
   - Click "Next"

7. **Review and Create**
   
   - Review all settings
   - Click "Create user pool"
   - **Save the User Pool ID** - you'll need this for configuration

Step 2: Create App Clients
==========================

You'll need two different app clients for different authentication flows:

App Client 1: Client Credentials Flow
------------------------------------

This client is used for server-to-server authentication.

1. **Navigate to App Integration**
   
   - In your User Pool, go to the "App integration" tab
   - Click "Create app client"

2. **Configure App Client**
   
   - **App type**: Select "Confidential client"
   - **App client name**: "MyApp-ClientCredentials"
   - **Client secret**: "Generate a client secret"
   - **Allowed callback URLs**: Not needed for client credentials
   - **Allowed sign-out URLs**: Not needed for client credentials

3. **Authentication Flows**
   
   - Uncheck "ALLOW_USER_SRP_AUTH"
   - Uncheck "ALLOW_USER_PASSWORD_AUTH" 
   - Uncheck "ALLOW_REFRESH_TOKEN_AUTH"
   - Check "ALLOW_ADMIN_USER_PASSWORD_AUTH" (for admin operations)
   - Check "ALLOW_CUSTOM_AUTH" (optional)

4. **OAuth 2.0 Settings**
   
   - **Allowed OAuth flows**: 
     - **Client credentials**
   - **Allowed OAuth scopes**: Select appropriate scopes for your API
   - **Hosted UI settings**: Not needed for client credentials

5. **Save the Configuration**
   
   - Click "Create app client"
   - **Save the Client ID and Client Secret** - you'll need these for configuration

App Client 2: User Password Flow
--------------------------------

This client is used for user authentication with username/password.

1. **Create Another App Client**
   
   - Click "Create app client" again

2. **Configure App Client**
   
   - **App type**: Select "Public client" or "Confidential client" based on your needs
   - **App client name**: "MyApp-UserAuth"
   - **Client secret**: 
     - Don't generate for public clients (mobile/SPA)
     - Generate for confidential clients (server-side web apps)

3. **Authentication Flows**
   
   - Check "ALLOW_USER_PASSWORD_AUTH"
   - Check "ALLOW_REFRESH_TOKEN_AUTH"
   - Uncheck "ALLOW_USER_SRP_AUTH" (unless you need SRP)
   - Uncheck "ALLOW_ADMIN_USER_PASSWORD_AUTH"

4. **OAuth 2.0 Settings**
   
   - **Allowed OAuth flows**: 
     - **Authorization code grant**
     - **Implicit grant** (only if needed for legacy apps)
   - **Allowed OAuth scopes**: 
     - **email**
     - **openid**
     - **profile**
   - **Callback URLs**: Add your application's callback URLs
   - **Sign-out URLs**: Add your application's sign-out URLs

5. **Advanced Settings**
   
   - **Access token expiration**: 60 minutes (default, adjust as needed)
   - **ID token expiration**: 60 minutes (default, adjust as needed)
   - **Refresh token expiration**: 30 days (default, adjust as needed)

6. **Save the Configuration**
   
   - Click "Create app client"
   - **Save the Client ID (and Client Secret if generated)**

Step 3: Create User Groups
=========================

User groups are essential for authorization and role-based access control.

1. **Navigate to Users and Groups**
   
   - In your User Pool, go to "Users and groups"
   - Click on the "Groups" tab
   - Click "Create group"

2. **Create Admin Group**
   
   - **Group name**: "admin"
   - **Description**: "Administrator group with full access"
   - **IAM role**: Leave blank unless you need AWS resource access
   - **Precedence**: 1 (lower numbers have higher precedence)
   - Click "Create group"

3. **Create User Group**
   
   - Click "Create group" again
   - **Group name**: "user"
   - **Description**: "Standard user group"
   - **IAM role**: Leave blank
   - **Precedence**: 10
   - Click "Create group"

4. **Create Additional Groups** (Optional)
   
   Create any additional groups your application needs:
   - "moderator" (precedence: 5)
   - "readonly" (precedence: 15)
   - "premium" (precedence: 8)

Step 4: Create Users
===================

Create test users to verify your setup.

1. **Create Admin User**
   
   - Go to "Users and groups" → "Users" tab
   - Click "Create user"
   - **Username**: "admin@example.com"
   - **Email**: "admin@example.com"
   - **Temporary password**: Generate a secure password
   - Check "Send an invitation to this new user?"
   - Check "Mark phone number as verified" (if applicable)
   - Check "Mark email as verified"
   - Click "Create user"

2. **Create Regular User**
   
   - Click "Create user" again
   - **Username**: "user@example.com"
   - **Email**: "user@example.com"
   - **Temporary password**: Generate a secure password
   - Check "Send an invitation to this new user?"
   - Check "Mark email as verified"
   - Click "Create user"

Step 5: Assign Users to Groups
==============================

1. **Assign Admin User to Admin Group**
   
   - Go to "Users and groups" → "Users" tab
   - Click on the admin user
   - Click "Add to group"
   - Select "admin" group
   - Click "Add to group"

2. **Assign Regular User to User Group**
   
   - Click on the regular user
   - Click "Add to group"
   - Select "user" group
   - Click "Add to group"

Step 6: Configure User Pool Settings
====================================

Advanced Configuration
----------------------

1. **App Client Settings** (if using Hosted UI)
   
   - Go to "App integration" → "App client settings"
   - Configure each app client:
     - **Enabled Identity Providers**: Cognito User Pool
     - **Callback URL(s)**: Your application's callback URLs
     - **Sign out URL(s)**: Your application's logout URLs
     - **Allowed OAuth Flows**: Based on your app client type
     - **Allowed OAuth Scopes**: email, openid, profile

2. **Domain Name** (if using Hosted UI)
   
   - Go to "App integration" → "Domain name"
   - Choose either:
     - **Amazon Cognito domain**: Use cognito subdomain
     - **Your own domain**: Use custom domain (requires SSL certificate)

3. **Triggers** (Optional)
   
   - Go to "General settings" → "Triggers"
   - Configure Lambda triggers for:
     - Pre sign-up validation
     - Post confirmation actions
     - Pre authentication validation
     - Post authentication actions
     - User migration

Step 7: Testing Your Setup
==========================

Using Bruno/API Testing
-----------------------

You can test your Cognito setup using the Bruno API client (as shown in your test files):

1. **Test User Authentication**:

   .. code-block:: json

      POST https://cognito-idp.{region}.amazonaws.com/
      Content-Type: application/x-amz-json-1.1
      X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth

      {
        "AuthParameters": {
          "USERNAME": "user@example.com",
          "PASSWORD": "user_password"
        },
        "AuthFlow": "USER_PASSWORD_AUTH",
        "ClientId": "{your_user_auth_client_id}"
      }

2. **Test Client Credentials**:

   .. code-block:: json

      POST https://cognito-idp.{region}.amazonaws.com/
      Content-Type: application/x-amz-json-1.1
      X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth

      {
        "AuthParameters": {
          "SECRET_HASH": "{calculated_secret_hash}"
        },
        "AuthFlow": "CLIENT_CREDENTIALS",
        "ClientId": "{your_client_credentials_client_id}"
      }

Configuration Summary
====================

After completing these steps, you'll have:

**User Pool Information**:

.. code-block:: yaml

   User Pool ID: us-east-1_XXXXXXXXX
   User Pool Region: us-east-1
   User Pool Domain: https://your-domain.auth.us-east-1.amazoncognito.com

**App Clients**:

.. code-block:: yaml

   Client Credentials App:
     Client ID: xxxxxxxxxxxxxxxxxxxx
     Client Secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
     Allowed Flows: ALLOW_ADMIN_USER_PASSWORD_AUTH

   User Authentication App:
     Client ID: yyyyyyyyyyyyyyyyyyyy
     Client Secret: yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
     Allowed Flows: ALLOW_USER_PASSWORD_AUTH, ALLOW_REFRESH_TOKEN_AUTH

**Groups Created**:

- admin (precedence: 1)
- user (precedence: 10)

**Test Users**:

- admin@example.com (member of admin group)
- user@example.com (member of user group)

Use these values to configure your auth-middleware as described in the :doc:`../cognito_provider` documentation.

Troubleshooting
===============

Common Issues
-------------

1. **Authentication Fails**
   
   - Verify the User Pool ID and region are correct
   - Check that the app client has the correct authentication flows enabled
   - Ensure users are confirmed (check email verification)

2. **Group Information Not Available**
   
   - Verify users are assigned to groups
   - Check that the groups were created successfully
   - Ensure your JWT tokens include group information

3. **Client Secret Issues**
   
   - For public clients (mobile/SPA), don't use client secrets
   - For confidential clients, ensure the secret is correctly configured
   - Verify the secret hasn't been regenerated

4. **Token Expiration Issues**
   
   - Check token expiration settings in app client configuration
   - Implement proper token refresh logic in your application
   - Consider adjusting token lifetimes based on security requirements

Security Best Practices
=======================

1. **Production Considerations**
   
   - Use custom domains for Hosted UI
   - Enable MFA for all users
   - Implement proper token refresh mechanisms
   - Use short-lived access tokens (15-60 minutes)
   - Configure appropriate CORS settings

2. **Monitoring and Logging**
   
   - Enable CloudTrail for Cognito API calls
   - Set up CloudWatch alarms for failed authentication attempts
   - Monitor user pool metrics
   - Implement application-level audit logging

3. **Backup and Recovery**
   
   - Export user data regularly
   - Document your configuration
   - Test user pool recovery procedures
   - Keep app client secrets secure

Step 8: Create Identity Pool (Optional)
=======================================

Identity Pools allow your users to obtain temporary AWS credentials to access AWS services (S3, DynamoDB, etc.) after authenticating through your User Pool.

Create Identity Pool
-------------------

1. **Navigate to Identity Pools**
   
   - In the AWS Console, go to Amazon Cognito
   - Click "Federated Identities" (or "Identity pools" in newer console)
   - Click "Create identity pool"

2. **Configure Identity Pool**
   
   - **Identity pool name**: "MyAppIdentityPool"
   - **Enable access to unauthenticated identities**: Uncheck (unless needed)
   - Click "Create pool"

3. **Configure Authentication Providers**
   
   - **Authentication providers** tab
   - Select "Cognito" tab
   - Add your User Pool:
     - **User Pool ID**: us-east-1_XXXXXXXXX (from Step 1)
     - **App client ID**: Use your User Authentication app client ID
   - Click "Save changes"

4. **Create IAM Roles**
   
   The console will prompt you to create IAM roles:
   
   **Authenticated role** (for logged-in users):
   
   - **Role name**: "Cognito_MyAppIdentityPoolAuth_Role"
   - **Trusted entities**: Cognito Identity Pool
   - **Permissions**: Add policies based on your needs:
     
     .. code-block:: json
     
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "s3:GetObject",
                "s3:PutObject"
              ],
              "Resource": "arn:aws:s3:::my-bucket/users/${cognito-identity.amazonaws.com:sub}/*"
            },
            {
              "Effect": "Allow",
              "Action": [
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem"
              ],
              "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable",
              "Condition": {
                "ForAllValues:StringEquals": {
                  "dynamodb:LeadingKeys": ["${cognito-identity.amazonaws.com:sub}"]
                }
              }
            }
          ]
        }
   
   **Unauthenticated role** (if enabled):
   
   - **Role name**: "Cognito_MyAppIdentityPoolUnauth_Role"
   - **Permissions**: Very restricted access or none

5. **Save Identity Pool Configuration**
   
   - Click "Allow" to create the IAM roles
   - **Save the Identity Pool ID** - you'll need this for configuration

Configure Enhanced Flow
-----------------------

For better security, use the enhanced (simplified) authflow:

1. **Edit Identity Pool**
   
   - Go to your Identity Pool settings
   - Click "Edit identity pool"
   - Check "Use enhanced flow"
   - Save changes

2. **Trust Relationships**
   
   Verify the authenticated role has the correct trust relationship:
   
   .. code-block:: json
   
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": {
              "Federated": "cognito-identity.amazonaws.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
              "StringEquals": {
                "cognito-identity.amazonaws.com:aud": "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              },
              "ForAnyValue:StringLike": {
                "cognito-identity.amazonaws.com:amr": "authenticated"
              }
            }
          }
        ]
      }

Test Identity Pool with AWS CLI
-------------------------------

1. **Get ID Token from User Pool** (from Step 7):

   .. code-block:: bash

      # Save the idToken from authentication response
      ID_TOKEN="eyJraWQ..."

2. **Get Identity ID**:

   .. code-block:: bash

      aws cognito-identity get-id \
        --identity-pool-id "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
        --logins "cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXXXXX=$ID_TOKEN" \
        --region us-east-1

   Response:

   .. code-block:: json

      {
        "IdentityId": "us-east-1:yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
      }

3. **Get AWS Credentials**:

   .. code-block:: bash

      aws cognito-identity get-credentials-for-identity \
        --identity-id "us-east-1:yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" \
        --logins "cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXXXXX=$ID_TOKEN" \
        --region us-east-1

   Response:

   .. code-block:: json

      {
        "IdentityId": "us-east-1:yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
        "Credentials": {
          "AccessKeyId": "ASIA...",
          "SecretKey": "...",
          "SessionToken": "...",
          "Expiration": 1735574400.0
        }
      }

4. **Use AWS Credentials**:

   .. code-block:: bash

      # Export credentials
      export AWS_ACCESS_KEY_ID="ASIA..."
      export AWS_SECRET_ACCESS_KEY="..."
      export AWS_SESSION_TOKEN="..."

      # Test access to S3
      aws s3 ls s3://my-bucket/users/

Test Identity Pool with Bruno
-----------------------------

1. **Request 1: Get Identity ID**

   .. code-block:: text

      POST https://cognito-identity.us-east-1.amazonaws.com/
      Content-Type: application/x-amz-json-1.1
      X-Amz-Target: AWSCognitoIdentityService.GetId

      {
        "IdentityPoolId": "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "Logins": {
          "cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXXXXX": "{{idToken}}"
        }
      }

   Save the `IdentityId` from the response.

2. **Request 2: Get AWS Credentials**

   .. code-block:: text

      POST https://cognito-identity.us-east-1.amazonaws.com/
      Content-Type: application/x-amz-json-1.1
      X-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity

      {
        "IdentityId": "{{identityId}}",
        "Logins": {
          "cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXXXXX": "{{idToken}}"
        }
      }

   Response contains temporary AWS credentials.

Configure auth-middleware Identity Pool Provider
-----------------------------------------------

If you're using the identity pool provider in auth-middleware:

.. code-block:: python

   from auth_middleware.providers.authn.cognito_authz_provider_settings import (
       CognitoAuthzProviderSettings
   )
   from auth_middleware.providers.authn.cognito_provider import CognitoProvider
   
   settings = CognitoAuthzProviderSettings(
       # User Pool settings
       user_pool_id="us-east-1_XXXXXXXXX",
       user_pool_region="us-east-1",
       user_pool_client_id="your-client-id",
       
       # Identity Pool settings (optional)
       identity_pool_id="us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
       identity_pool_region="us-east-1",
   )
   
   provider = CognitoProvider(settings=settings)

Then in your application, you can obtain AWS credentials:

.. code-block:: python

   from fastapi import Request, Depends
   from auth_middleware.functions import require_user
   
   @app.get("/aws-credentials")
   async def get_aws_credentials(
       request: Request,
       _: None = Depends(require_user())
   ):
       user = request.state.current_user
       
       # Get AWS credentials for the authenticated user
       # This would use the provider's identity pool integration
       credentials = await provider.get_aws_credentials(user.id_token)
       
       return {
           "access_key_id": credentials.access_key_id,
           "secret_access_key": credentials.secret_access_key,
           "session_token": credentials.session_token,
           "expiration": credentials.expiration,
       }

Identity Pool Configuration Summary
-----------------------------------

After completing Identity Pool setup:

.. code-block:: yaml

   Identity Pool ID: us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   Identity Pool Region: us-east-1
   
   Authentication Provider:
     Type: Cognito User Pool
     User Pool ID: us-east-1_XXXXXXXXX
     App Client ID: yyyyyyyyyyyyyyyyyyyy
   
   IAM Roles:
     Authenticated Role: Cognito_MyAppIdentityPoolAuth_Role
     Authenticated Role ARN: arn:aws:iam::123456789012:role/Cognito_MyAppIdentityPoolAuth_Role

Identity Pool Best Practices
----------------------------

1. **Principle of Least Privilege**
   
   - Grant only necessary permissions in IAM roles
   - Use resource-level permissions with user context
   - Leverage condition keys like ``${cognito-identity.amazonaws.com:sub}``

2. **Use Enhanced Flow**
   
   - Always enable enhanced (simplified) authflow
   - More secure than classic flow
   - Better integration with modern SDKs

3. **Credential Caching**
   
   - Cache AWS credentials until expiration
   - Refresh before expiration (e.g., at 80% of lifetime)
   - Don't request new credentials for every API call

4. **Resource Isolation**
   
   - Use Cognito identity ID in resource paths
   - Example S3 path: ``s3://bucket/users/${cognito-identity.amazonaws.com:sub}/``
   - Example DynamoDB key: Use identity ID as partition key

5. **Monitoring**
   
   - Monitor IAM role usage in CloudTrail
   - Set up alarms for unauthorized access attempts
   - Track credential request patterns

Next Steps
==========

Now that your Cognito infrastructure is set up:

1. Configure the auth-middleware with your Cognito settings
2. Implement the authentication flow in your application
3. Set up authorization rules based on user groups
4. Test the complete authentication and authorization flow
5. (Optional) Implement Identity Pool integration for AWS resource access
6. Deploy to production with appropriate security settings

For implementation details, see the :doc:`../cognito_provider` documentation.
