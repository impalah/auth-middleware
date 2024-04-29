# FastAPI Cognito Demo

Testing auth middleware with cognito and fastapi.

## Infrastructure

### Requirements

- Terraform.
- AWS CLI installed and configured.
- Postman.

### Create

Initialize terraform:

```bash
cd terraform
terraform init
```

Deploy infrastructure:

```bash
terraform apply -var-file="configuration.tfvars"
```

### Get generated variables

When terraform generates the infrastructure there is a series of variables that be output in the terminal. Some of these variables should be set in the .env file for later launching the API server.

Example output:

```bash
Apply complete! Resources: 0 added, 0 changed, 0 destroyed.

Outputs:

aws_cognito_user_pool-api_client_ids = {
  "administrator" = "1q0jq98ipjv5lcdla1gqvkr6ou"
  "customer" = "2giuiu9q8e6ritihintkecvni4"
}
aws_cognito_user_pool-api_client_secrets = <sensitive>
aws_cognito_user_pool-user_client_id = "6sjoq4idln1ih3c9fhne0hvc8d"
cognito_domain = "4d9ea9fec1b35d97-domain"
cognito_user_client_id = "6sjoq4idln1ih3c9fhne0hvc8d"
cognito_user_pool_id = "eu-west-1_TSIhhXWBR"

```

### Get private client secrets

Client secrets are protected variables, and special command should be used.

```bash
terraform output -json aws_cognito_user_pool-api_client_secrets
```

Example output:

```bash
{"administrator":"2kituq7betkqtdpi6556srhbhto95ct82shp1go99n77r1l0go7","customer":"1ea8icpkvg0o6npso66mgqa4gh7h06sbl1r0g9n6d1hg8j6mf3m2"}
```

## (Optional) Destroy infrastructure

When you finish you can destroy the test infrastrcuture using:

```bash
terraform destroy -var-file="configuration.tfvars"
```



## API server

### Create a configuration file

Rename or copy ".env.template" file to ".env" and set the values according with the data returned by terraform.

```bash

AUTH_MIDDLEWARE_LOG_LEVEL=DEBUG
AUTH_MIDDLEWARE_DISABLED=false
AUTH_PROVIDER_AWS_COGNITO_USER_POOL_ID=<cognito_user_pool_id>
AUTH_PROVIDER_AWS_COGNITO_USER_POOL_REGION=<pool-region>

# VARIABLES FOR CLIENT WEBPAGE CONFIGURATION
COGNITO_DOMAIN=<cognito_domain>
COGNITO_CLIENT_ID=<aws_cognito_user_pool-user_client_id>
AWS_REGION=<pool-region>



```

### Launch server

From the root folder launch the command:

```bash
poetry run dotenv run python -m uvicorn demo.main:app --host 0.0.0.0 --port 8000 --reload
```

("run dotenv" allows python te read and decode the .env file)



## Test the server

### Main page

- Access [http://localhost:8000](http://localhost:8000)
- Use the "Login" button to go to the login page.
- Use the credentials of a valid user to log-in.
- If everything goes ok Cognito will go back to the same page returning access and id tokens and they will be shown.
- You can use the copy buttons to cpy the token to the clipboard.

### Postman

A Postman collection is provided to test the API endpoints.

Import the collection. Edit the colelction, go to variables and set the apropriate values.

The authorization Bearer token can be get from the Main Page (see previous section) or using the "Cognito - Get access token" request on Postman.







