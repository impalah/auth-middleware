output "cognito_user_pool_id" {
  value = module.cognito.aws_cognito_user_pool-userpool_id
}

output "cognito_user_client_id" {
  value = module.cognito.aws_cognito_user_pool-user_client_id
}

output "cognito_domain" {
  value = module.cognito.aws_cognito_user_pool-domain
}

output "aws_cognito_user_pool-api_client_ids" {
  value = module.cognito.aws_cognito_user_pool-api_client_ids
}

output "aws_cognito_user_pool-api_client_secrets" {
  value = module.cognito.aws_cognito_user_pool-api_client_secrets
  sensitive = true
}

output "aws_cognito_user_pool-user_client_id" {
  value = module.cognito.aws_cognito_user_pool-user_client_id
}



