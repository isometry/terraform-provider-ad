# AD Organizational Unit Examples

terraform {
  required_providers {
    ad = {
      source = "isometry/ad"
    }
  }
}

provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secure_password"
}

# Basic OU at domain root
resource "ad_ou" "departments" {
  name        = "Departments"
  path        = "dc=example,dc=com"
  description = "Company departments"
}

# Nested OU structure
resource "ad_ou" "it_department" {
  name        = "IT Department"
  path        = ad_ou.departments.dn
  description = "Information Technology Department"
}

resource "ad_ou" "it_groups" {
  name        = "Groups"
  path        = ad_ou.it_department.dn
  description = "IT Department groups"
}

# Protected OU (cannot be accidentally deleted)
resource "ad_ou" "service_accounts" {
  name                  = "Service Accounts"
  path                  = ad_ou.it_department.dn
  description           = "Critical service accounts"
  protect_from_deletion = true
}

# Using OU as container for groups
resource "ad_group" "it_admins" {
  name        = "IT Administrators"
  container   = ad_ou.it_groups.dn
  description = "IT Department administrators"
}
