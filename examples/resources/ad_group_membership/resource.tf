# AD Group Membership Example

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

# Create a security group
resource "ad_group" "project_team" {
  name             = "Project Alpha Team"
  sam_account_name = "ProjectAlpha"
  container        = "ou=Project Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "Members of Project Alpha"
}

# Basic group membership with mixed identifier formats
resource "ad_group_membership" "project_team_members" {
  group_id = ad_group.project_team.id
  members = [
    "user1@example.com",                             # UPN format
    "user2@example.com",                             # UPN format
    "cn=service-account,cn=users,dc=example,dc=com", # DN format
    "12345678-1234-5678-9012-123456789012",          # GUID format
    "S-1-5-21-123456789-123456789-123456789-1002",   # SID format
    "EXAMPLE\\user3"                                 # SAM format
  ]
}

# Membership with data source lookup
data "ad_group" "existing_group" {
  name = "Existing Team"
}

resource "ad_group_membership" "add_to_existing" {
  group_id = data.ad_group.existing_group.id
  members = [
    "newuser@example.com",
    "cn=another-user,cn=users,dc=example,dc=com"
  ]
}

# Nested group membership (groups as members)
resource "ad_group" "admin_group" {
  name             = "Project Alpha Admins"
  sam_account_name = "ProjectAlphaAdmins"
  container        = "ou=Project Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "Administrators for Project Alpha"
}

resource "ad_group_membership" "admin_group_members" {
  group_id = ad_group.admin_group.id
  members = [
    "admin1@example.com",
    "admin2@example.com",
    # Include the project team group as a member
    ad_group.project_team.dn
  ]
}

# Output membership information
output "project_team_membership" {
  value = {
    group_id     = ad_group_membership.project_team_members.group_id
    member_count = length(ad_group_membership.project_team_members.members)
    members      = ad_group_membership.project_team_members.members
  }
}
