# AD Group Data Source Example

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

# Lookup group by name
data "ad_group" "existing_group" {
  name = "Domain Admins"
}

# Lookup group by Distinguished Name
data "ad_group" "by_dn" {
  dn = "cn=IT Team,ou=Groups,dc=example,dc=com"
}

# Lookup group by GUID
data "ad_group" "by_guid" {
  id = "12345678-1234-5678-9012-123456789012"
}

# Lookup group by SID
data "ad_group" "by_sid" {
  sid = "S-1-5-21-123456789-123456789-123456789-1001"
}

# Lookup group by SAM Account Name
data "ad_group" "by_sam" {
  sam_account_name = "ITTeam"
}

# Use group data in other resources
resource "ad_group_membership" "add_to_existing" {
  group_id = data.ad_group.existing_group.id
  members = [
    "newuser@example.com",
    "cn=service-account,cn=users,dc=example,dc=com"
  ]
}

# Create a nested group structure
resource "ad_group" "child_group" {
  name             = "IT Support Team"
  sam_account_name = "ITSupport"
  container        = dirname(data.ad_group.by_dn.dn)
  scope            = data.ad_group.by_dn.scope
  category         = data.ad_group.by_dn.category
  description      = "Support team within ${data.ad_group.by_dn.name}"
}

# Output group information
output "group_details" {
  value = {
    domain_admins = {
      name         = data.ad_group.existing_group.name
      dn           = data.ad_group.existing_group.dn
      sid          = data.ad_group.existing_group.sid
      scope        = data.ad_group.existing_group.scope
      category     = data.ad_group.existing_group.category
      member_count = data.ad_group.existing_group.member_count
    }
    it_team = {
      name        = data.ad_group.by_dn.name
      dn          = data.ad_group.by_dn.dn
      group_type  = data.ad_group.by_dn.group_type
      description = data.ad_group.by_dn.description
    }
  }
}
