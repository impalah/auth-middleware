################################################################################
# User pool
################################################################################

resource "aws_cognito_user_pool" "userpool" {
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = "1"
    }
  }

  admin_create_user_config {
    allow_admin_create_user_only = "true"

    invite_message_template {
      email_message = var.signup_email_message
      email_subject = var.signup_email_subject
      sms_message   = var.signup_sms_message
    }
  }

  auto_verified_attributes = ["email"]
  deletion_protection      = "INACTIVE"

  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  mfa_configuration = "OFF"
  name              = var.userpool_name

  password_policy {
    minimum_length                   = "8"
    require_lowercase                = "true"
    require_numbers                  = "true"
    require_symbols                  = "true"
    require_uppercase                = "true"
    temporary_password_validity_days = "7"
  }

  schema {
    attribute_data_type      = "String"
    developer_only_attribute = "false"
    mutable                  = "true"
    name                     = "user_manager"
    required                 = "false"

    string_attribute_constraints {
      max_length = "100"
      min_length = "5"
    }
  }

  schema {
    attribute_data_type      = "String"
    developer_only_attribute = "false"
    mutable                  = "true"
    name                     = "email"
    required                 = "true"

    string_attribute_constraints {
      max_length = "2048"
      min_length = "0"
    }
  }

  tags = merge(
    { "Name" = var.userpool_name },
    var.tags,
  )

  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }

  username_configuration {
    case_sensitive = "false"
  }

  verification_message_template {
    default_email_option  = "CONFIRM_WITH_LINK"
    email_message_by_link = var.verification_email_message
    email_subject_by_link = var.verification_email_subject
  }
}


# Basic authentication client
resource "aws_cognito_user_pool_client" "public_client" {
  name = format("%s-public-client", var.userpool_name)

  user_pool_id                  = aws_cognito_user_pool.userpool.id
  generate_secret               = false
  refresh_token_validity        = 90
  prevent_user_existence_errors = "ENABLED"
  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_ADMIN_USER_PASSWORD_AUTH"
  ]

  callback_urls                        = var.client_callback_urls
  allowed_oauth_flows_user_pool_client = true

  allowed_oauth_flows          = ["code", "implicit"]
  allowed_oauth_scopes         = ["email", "openid", "phone", "profile"]
  supported_identity_providers = ["COGNITO"]

}

# Something went wrong: An error occurred (InvalidParameterException) when calling the InitiateAuth operation: USER_PASSWORD_AUTH flow not enabled for this client


# Basic authentication client
resource "aws_cognito_user_pool_client" "api_client" {

  for_each = var.groups

  name = format("%s-api-client-%s", var.userpool_name, each.value)

  user_pool_id                  = aws_cognito_user_pool.userpool.id
  generate_secret               = true
  refresh_token_validity        = 90
  prevent_user_existence_errors = "ENABLED"
  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]

  callback_urls                        = ["http://localhost:8000"]
  allowed_oauth_flows_user_pool_client = true

  allowed_oauth_flows  = ["client_credentials"]
  allowed_oauth_scopes = [format("%s/%s", var.resource_server_identifier, each.value)]
  supported_identity_providers = ["COGNITO"]
}


# Basic domain for authentication
resource "aws_cognito_user_pool_domain" "cognito-domain" {
  domain       = var.userpool_domain
  user_pool_id = aws_cognito_user_pool.userpool.id
}


################################################################################
# Resource servers (for client id)
################################################################################

resource "aws_cognito_resource_server" "resource" {
  identifier = var.resource_server_identifier
  name       = var.resource_server_name

  dynamic "scope" {
    for_each = var.groups
    content {
      scope_name        = scope.value
      scope_description = "${scope.value} scope for API users"
    }
  }

  user_pool_id = aws_cognito_user_pool.userpool.id
}


################################################################################
# User groups
################################################################################


resource "aws_cognito_user_group" "main" {

  for_each = var.groups

  name         = each.key
  user_pool_id = aws_cognito_user_pool.userpool.id

}
