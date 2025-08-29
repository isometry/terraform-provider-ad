# AD Group Membership Examples

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

# Create a group for membership examples
resource "ad_group" "project_team" {
  name        = "Project Alpha Team"
  container   = "ou=Groups,dc=example,dc=com"
  description = "Members of Project Alpha"
}

# Basic membership with different identifier formats
resource "ad_group_membership" "project_members" {
  group_id = ad_group.project_team.id
  members = [
    "user1@example.com",                             # UPN format
    "cn=service-account,cn=users,dc=example,dc=com", # DN format
    "12345678-1234-5678-9012-123456789012",          # GUID format
    "S-1-5-21-123456789-123456789-123456789-1002",   # SID format
    "EXAMPLE\\user3"                                 # SAM format
  ]
}

# Nested group membership (group containing other groups)
resource "ad_group" "admin_group" {
  name        = "Project Administrators"
  container   = "ou=Groups,dc=example,dc=com"
  description = "Administrators for projects"
}

resource "ad_group_membership" "admin_members" {
  group_id = ad_group.admin_group.id
  members = [
    "admin1@example.com",
    "admin2@example.com",
    # Include another group as a member
    ad_group.project_team.dn
  ]
}
