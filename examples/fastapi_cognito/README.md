# FastAPI Cognito Demo

Testing auth middleware with cognito and fastapi.

## Infrastructure

### Requirements

- Terraform.
- AWS CLI installed and configured.

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

### Get private client secrets

```bash
terraform output -json aws_cognito_user_pool-api_client_secrets
```





```bash
poetry run dotenv run python -m uvicorn demo.main:app --host 0.0.0.0 --port 8000 --reload
```
