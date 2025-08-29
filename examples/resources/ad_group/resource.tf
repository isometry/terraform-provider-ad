# AD Group Examples

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

# Security group (default scope: Global, category: Security)
resource "ad_group" "security_group" {
  name        = "IT Security Team"
  container   = "ou=Groups,dc=example,dc=com"
  description = "IT Security team members"
}

# Distribution group with Universal scope
resource "ad_group" "distribution_group" {
  name             = "Marketing Distribution List"
  sam_account_name = "MarketingList"
  container        = "ou=Groups,dc=example,dc=com"
  scope            = "Universal"
  category         = "Distribution"
  description      = "Marketing team email distribution list"
}

# Domain Local group for resource access
resource "ad_group" "resource_access" {
  name        = "File Share Access"
  container   = "cn=users,dc=example,dc=com"
  scope       = "DomainLocal"
  description = "Access to shared file resources"
}
