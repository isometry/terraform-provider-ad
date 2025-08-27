# Basic AD Group Example

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

# Basic security group
resource "ad_group" "basic_security" {
  name             = "IT Security Team"
  sam_account_name = "ITSecurity"
  container        = "ou=Security Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "IT Security team members"
}

# Distribution group for email
resource "ad_group" "marketing_list" {
  name             = "Marketing Distribution List"
  sam_account_name = "MarketingList"
  container        = "ou=Distribution Groups,dc=example,dc=com"
  scope            = "Universal"
  category         = "Distribution"
  description      = "Marketing team email distribution list"
}

# Domain Local group for resource access
resource "ad_group" "local_access" {
  name             = "Local Resource Access"
  sam_account_name = "LocalAccess"
  container        = "cn=users,dc=example,dc=com"
  scope            = "DomainLocal"
  category         = "Security"
  description      = "Local resource access group"
}

# Output group information
output "security_group_info" {
  value = {
    id         = ad_group.basic_security.id
    dn         = ad_group.basic_security.dn
    sid        = ad_group.basic_security.sid
    group_type = ad_group.basic_security.group_type
  }
}
