# ################################################################
# Cognito user pool
# ################################################################

resource "random_id" "my_id" {
  byte_length = 8
}

locals {
  random_id_hex = random_id.my_id.hex
}


# Cognito user pool
module "cognito" {
  source                     = "./modules/cognito"
  environment                = var.environment
  project                    = var.project
  userpool_name              = format("%s", local.random_id_hex)
  userpool_domain            = format("%s-domain", local.random_id_hex)
  resource_server_identifier = format("%s-rsid", local.random_id_hex)
  resource_server_name       = format("%s-rs", local.random_id_hex)
  groups                     = var.userpool_groups
  client_callback_urls       = ["http://localhost:8000"]

    tags = {
      Environment  = upper(var.environment)
      Deployment   = lower("Terraform")
      CostCenter   = var.cost_center
      Project      = var.project
    }

}

