# AD User Data Source Example

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

# Lookup user by SAM Account Name
data "ad_user" "by_sam" {
  sam_account_name = "jdoe"
}

# Lookup user by Distinguished Name
data "ad_user" "by_dn" {
  distinguished_name = "cn=John Doe,cn=users,dc=example,dc=com"
}

# Lookup user by User Principal Name (UPN)
data "ad_user" "by_upn" {
  user_principal_name = "john.doe@example.com"
}

# Lookup user by GUID
data "ad_user" "by_guid" {
  id = "12345678-1234-5678-9012-123456789012"
}

# Lookup user by SID
data "ad_user" "by_sid" {
  sid = "S-1-5-21-123456789-123456789-123456789-1001"
}

# Use user data for group membership
resource "ad_group_membership" "user_groups" {
  group_id = data.ad_group.it_team.id
  members = [
    data.ad_user.by_sam.distinguished_name,
    data.ad_user.by_upn.distinguished_name
  ]
}

# Reference to group for the membership example
data "ad_group" "it_team" {
  name = "IT Team"
}

# Create groups based on user attributes
resource "ad_group" "department_group" {
  name             = "${data.ad_user.by_sam.department} Department"
  sam_account_name = "${replace(data.ad_user.by_sam.department, " ", "")}Dept"
  container        = "ou=Department Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "Group for ${data.ad_user.by_sam.department} department members"
}

# Output user information
output "user_details" {
  value = {
    by_sam = {
      name                = data.ad_user.by_sam.display_name
      sam_account_name    = data.ad_user.by_sam.sam_account_name
      user_principal_name = data.ad_user.by_sam.user_principal_name
      distinguished_name  = data.ad_user.by_sam.distinguished_name
      email               = data.ad_user.by_sam.email
      department          = data.ad_user.by_sam.department
      title               = data.ad_user.by_sam.title
      office              = data.ad_user.by_sam.office
      telephone           = data.ad_user.by_sam.telephone
      enabled             = data.ad_user.by_sam.enabled
      sid                 = data.ad_user.by_sam.sid
    }
    by_upn = {
      name               = data.ad_user.by_upn.display_name
      sam_account_name   = data.ad_user.by_upn.sam_account_name
      distinguished_name = data.ad_user.by_upn.distinguished_name
      manager            = data.ad_user.by_upn.manager
      department         = data.ad_user.by_upn.department
      company            = data.ad_user.by_upn.company
    }
  }
}

# Conditional logic based on user attributes
locals {
  is_manager = data.ad_user.by_sam.title != null ? contains(split(" ", lower(data.ad_user.by_sam.title)), "manager") : false
}

# Create manager-specific group if user is a manager
resource "ad_group" "managers_group" {
  count = local.is_manager ? 1 : 0

  name             = "Department Managers"
  sam_account_name = "DeptManagers"
  container        = "ou=Management Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "All department managers"
}

resource "ad_group_membership" "manager_membership" {
  count = local.is_manager ? 1 : 0

  group_id = ad_group.managers_group[0].id
  members  = [data.ad_user.by_sam.distinguished_name]
}