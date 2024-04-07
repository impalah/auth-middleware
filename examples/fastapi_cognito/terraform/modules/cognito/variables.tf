variable "environment" {
  description = "Set environment name"
  type        = string
  default     = ""
}

variable "userpool_name" {
  description = "User pool name"
  type        = string
  default     = null
}

variable "signup_email_message" {
  description = "Sign up email message"
  type        = string
  default     = "Your username is {username} and temporary password is {####}"
}
variable "signup_email_subject" {
  description = "Sign up email subject"
  type        = string
  default     = "Magenda: Your temporary password"
}
variable "signup_sms_message" {
  description = "Sign up sms message"
  type        = string
  default     = "Your username is {username} and temporary password is {####}"
}


variable "verification_email_message" {
  description = "Verification email message"
  type        = string
  default     = "Please click the link below to verify your email address. {##Verify Email##}"
}

variable "verification_email_subject" {
  description = "Verification email subject"
  type        = string
  default     = "Magenda: Your verification link"
}


variable "project" {
  description = "Project name"
  type        = string
  default     = ""
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}


variable "userpool_public_client" {
  description = "User pool public client"
  type        = string
  default     = null
}

variable "userpool_api_client" {
  description = "User pool API client"
  type        = string
  default     = null
}

variable "userpool_domain" {
  description = "User pool domain"
  type        = string
  default     = null
}

variable "resource_server_identifier" {
  description = "Resource server identifier"
  type        = string
  default     = null
}

variable "resource_server_name" {
  description = "Resource server name"
  type        = string
  default     = null
}

variable "groups" {
  description = "Cognito groups"
  type        = set(string)
  default     = []
}

variable "client_callback_urls" {
  description = "Callback urls"
  type        = set(string)
  default     = []
}

