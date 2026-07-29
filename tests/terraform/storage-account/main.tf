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
  # Point ARM / metadata at the lab when running live smoke.
  # environment           = "public"
  # metadata_host         = var.noctaxris_az_endpoint
  skip_provider_registration = true
}

variable "noctaxris_az_endpoint" {
  type    = string
  default = ""
}

variable "resource_group_name" {
  type    = string
  default = "noctaxris-az-tf-rg"
}

variable "location" {
  type    = string
  default = "eastus"
}

resource "azurerm_resource_group" "lab" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_storage_account" "lab" {
  name                     = "noctaxristfsa01"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_table" "lab" {
  name                 = "noctaxristable"
  storage_account_name = azurerm_storage_account.lab.name
}
