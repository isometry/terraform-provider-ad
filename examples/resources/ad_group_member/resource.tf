# AD Group Member Examples

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

resource "ad_group" "project_team" {
  name        = "Project Alpha Team"
  container   = "ou=Groups,dc=example,dc=com"
  description = "Members of Project Alpha"
}

# Each resource manages one member; other members of the group are left untouched.
resource "ad_group_member" "alice" {
  group_id = ad_group.project_team.id
  member   = "alice@example.com" # UPN format
}

resource "ad_group_member" "service_account" {
  group_id = ad_group.project_team.id
  member   = "EXAMPLE\\svc-project" # SAM format
}

# Nested group membership
resource "ad_group" "project_admins" {
  name      = "Project Alpha Administrators"
  container = "ou=Groups,dc=example,dc=com"
}

resource "ad_group_member" "admins_in_team" {
  group_id = ad_group.project_team.id
  member   = ad_group.project_admins.id # GUID format
}

# Add the same user to several existing groups
variable "groups" {
  type = map(string) # name => group objectGUID
}

resource "ad_group_member" "bob" {
  for_each = var.groups

  group_id = each.value
  member   = "cn=Bob Smith,ou=Users,dc=example,dc=com" # DN format
}
