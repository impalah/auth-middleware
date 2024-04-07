output "aws_cognito_user_pool-userpool_id" {
  value = aws_cognito_user_pool.userpool.id
}

output "aws_cognito_user_pool-userpool_arn" {
  value = aws_cognito_user_pool.userpool.arn
}


output "aws_cognito_user_pool-api_client_ids" {
  value = { for k in keys(aws_cognito_user_pool_client.api_client) : k => aws_cognito_user_pool_client.api_client[k].id }
}

output "aws_cognito_user_pool-api_client_secrets" {
  value = { for k in keys(aws_cognito_user_pool_client.api_client) : k => aws_cognito_user_pool_client.api_client[k].client_secret }
}

output "aws_cognito_user_pool-user_client_id" {
  value = aws_cognito_user_pool_client.public_client.id
}

output "aws_cognito_user_pool-domain" {
  value = aws_cognito_user_pool_domain.cognito-domain.domain
}

