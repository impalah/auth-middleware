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
     - ✅ **Email** (recommended for most applications)
     - ✅ **Username** (optional, based on your needs)
     - ⚠️ **Phone number** (optional, requires SMS configuration)
   - Click "Next"

3. **Configure Security Requirements**
   
   - **Password policy**: Choose between "Cognito defaults" or "Custom"
     
     For custom policy, recommended settings:
     - Minimum length: 8 characters
     - ✅ Require numbers
     - ✅ Require special characters
     - ✅ Require uppercase letters
     - ✅ Require lowercase letters
   
   - **Multi-factor authentication**: 
     - **Optional** (recommended for production)
     - **Required** (for high-security applications)
   
   - **User account recovery**: Select preferred options:
     - ✅ **Email only** (most common)
     - **SMS and email** (if phone numbers are collected)
   
   - Click "Next"

4. **Configure Sign-up Experience**
   
   - **Self-service sign-up**: Enable if you want users to self-register
   - **Cognito-assisted verification**: Choose verification methods:
     - ✅ **Send email verification** (recommended)
     - **Send SMS verification** (if using phone numbers)
   
   - **Required attributes**: Select attributes to collect during sign-up:
     - ✅ **email** (strongly recommended)
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
   - **Client secret**: ✅ "Generate a client secret"
   - **Allowed callback URLs**: Not needed for client credentials
   - **Allowed sign-out URLs**: Not needed for client credentials

3. **Authentication Flows**
   
   - ❌ Uncheck "ALLOW_USER_SRP_AUTH"
   - ❌ Uncheck "ALLOW_USER_PASSWORD_AUTH" 
   - ❌ Uncheck "ALLOW_REFRESH_TOKEN_AUTH"
   - ✅ Check "ALLOW_ADMIN_USER_PASSWORD_AUTH" (for admin operations)
   - ✅ Check "ALLOW_CUSTOM_AUTH" (optional)

4. **OAuth 2.0 Settings**
   
   - **Allowed OAuth flows**: 
     - ✅ **Client credentials**
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
     - ❌ Don't generate for public clients (mobile/SPA)
     - ✅ Generate for confidential clients (server-side web apps)

3. **Authentication Flows**
   
   - ✅ Check "ALLOW_USER_PASSWORD_AUTH"
   - ✅ Check "ALLOW_REFRESH_TOKEN_AUTH"
   - ❌ Uncheck "ALLOW_USER_SRP_AUTH" (unless you need SRP)
   - ❌ Uncheck "ALLOW_ADMIN_USER_PASSWORD_AUTH"

4. **OAuth 2.0 Settings**
   
   - **Allowed OAuth flows**: 
     - ✅ **Authorization code grant**
     - ✅ **Implicit grant** (only if needed for legacy apps)
   - **Allowed OAuth scopes**: 
     - ✅ **email**
     - ✅ **openid**
     - ✅ **profile**
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
   - ✅ Check "Send an invitation to this new user?"
   - ✅ Check "Mark phone number as verified" (if applicable)
   - ✅ Check "Mark email as verified"
   - Click "Create user"

2. **Create Regular User**
   
   - Click "Create user" again
   - **Username**: "user@example.com"
   - **Email**: "user@example.com"
   - **Temporary password**: Generate a secure password
   - ✅ Check "Send an invitation to this new user?"
   - ✅ Check "Mark email as verified"
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
     - **Enabled Identity Providers**: ✅ Cognito User Pool
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

Next Steps
==========

Now that your Cognito infrastructure is set up:

1. Configure the auth-middleware with your Cognito settings
2. Implement the authentication flow in your application
3. Set up authorization rules based on user groups
4. Test the complete authentication and authorization flow
5. Deploy to production with appropriate security settings

For implementation details, see the :doc:`../cognito_provider` documentation.
