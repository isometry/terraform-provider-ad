# AD Group Data Source Examples

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

# Lookup by Distinguished Name (most precise)
data "ad_group" "by_dn" {
  dn = "cn=IT Team,ou=Groups,dc=example,dc=com"
}

# Lookup by GUID (most reliable)
data "ad_group" "by_guid" {
  id = "12345678-1234-5678-9012-123456789012"
}

# Lookup by SAM Account Name (domain-wide search)
data "ad_group" "by_sam" {
  sam_account_name = "ITTeam"
}

# Use group data in membership resource
resource "ad_group_membership" "add_members" {
  group_id = data.ad_group.by_dn.id
  members = [
    "newuser@example.com",
    "cn=service-account,cn=users,dc=example,dc=com"
  ]
}

# Use group attributes in new resources
resource "ad_group" "support_team" {
  name        = "IT Support Team"
  container   = dirname(data.ad_group.by_dn.dn)
  description = "Support team within ${data.ad_group.by_dn.name}"
}
