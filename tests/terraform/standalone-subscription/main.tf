terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
  # Point ARM / metadata at the lab when running live smoke.
  # environment           = "public"
  # metadata_host         = var.noctaxris_az_endpoint
  skip_provider_registration = true
}

variable "noctaxris_az_endpoint" {
  type    = string
  default = ""
}

variable "subscription_id" {
  type    = string
  default = ""
}

variable "resource_group_name" {
  type    = string
  default = "noctaxris-az-standalone-rg"
}

variable "location" {
  type    = string
  default = "eastus"
}

resource "azurerm_resource_group" "standalone" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_storage_account" "standalone" {
  name                     = "noctaxrisstandalone"
  resource_group_name      = azurerm_resource_group.standalone.name
  location                 = azurerm_resource_group.standalone.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
