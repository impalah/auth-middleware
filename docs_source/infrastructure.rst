.. _infrastructure:

Infrastructure Setup
====================

This section provides detailed guides for setting up the infrastructure required by different identity providers. Each provider requires specific configuration and setup steps that must be completed before you can use them with the auth-middleware.

.. note::
   The following guides focus on manual setup through web consoles. For automated infrastructure deployment, consider using Infrastructure as Code tools like Terraform, AWS CloudFormation, or Azure Resource Manager templates.

Provider-Specific Setup Guides
==============================

.. toctree::
   :maxdepth: 2

   infrastructure/cognito-setup
   infrastructure/entra-id-setup
   infrastructure/google-setup

Overview
========

Each identity provider requires different infrastructure components:

**AWS Cognito**
   - User Pool for user management
   - App Clients for different authentication flows
   - User Groups for authorization
   - Optional: Custom attributes and triggers

**Azure Entra ID**
   - App Registration for your application
   - Service Principal configuration
   - Group assignments
   - API permissions

**Google Identity**
   - OAuth 2.0 Client IDs
   - Consent screen configuration
   - User management through Google Workspace (optional)

Security Considerations
======================

When setting up identity provider infrastructure, consider the following security best practices:

1. **Principle of Least Privilege**: Only grant the minimum permissions necessary
2. **Multi-Factor Authentication**: Enable MFA wherever possible
3. **Token Rotation**: Configure appropriate token expiration times
4. **Audit Logging**: Enable comprehensive logging for security monitoring
5. **Network Security**: Use HTTPS/TLS for all communications
6. **Secret Management**: Never hardcode secrets; use environment variables or secret management services

Next Steps
==========

After completing the infrastructure setup for your chosen provider:

1. Configure the auth-middleware with your provider settings
2. Test the authentication flow
3. Implement authorization rules using groups and permissions
4. Set up monitoring and logging
5. Configure production security settings

For implementation details, refer to the :doc:`middleware-configuration` and provider-specific documentation.
