provider "aws" {
  region = var.region

  ignore_tags {
    keys = ["cloud", "entorno", "plataforma", "suscripcion"]
  }
}



