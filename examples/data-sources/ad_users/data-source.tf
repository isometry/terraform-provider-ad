# AD Users Data Source Example

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

# Find all users in a specific OU
data "ad_users" "it_users" {
  container = "ou=IT Department,ou=Users,dc=example,dc=com"
  scope     = "subtree"
}

# Find users by department
data "ad_users" "hr_department" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    department = "Human Resources"
  }
}

# Find enabled users only
data "ad_users" "active_users" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    enabled = true
  }
}

# Find disabled users for cleanup
data "ad_users" "disabled_users" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    enabled = false
  }
}

# Find users by title containing "Manager"
data "ad_users" "managers" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    title_contains = "Manager"
    enabled        = true
  }
}

# Find users by company
data "ad_users" "company_users" {
  container = "dc=example,dc=com"
  scope     = "subtree"

  filter = {
    company = "Example Corp"
  }
}

# Find users with specific attributes
data "ad_users" "users_with_email" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    has_email = true
    enabled   = true
  }
}

# Complex search combining multiple filters
data "ad_users" "it_managers" {
  container = "ou=IT Department,ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    department     = "Information Technology"
    title_contains = "Manager"
    enabled        = true
    has_email      = true
  }
}

# Search across multiple OUs
variable "search_ous" {
  type = list(string)
  default = [
    "ou=IT,ou=Users,dc=example,dc=com",
    "ou=HR,ou=Users,dc=example,dc=com",
    "ou=Finance,ou=Users,dc=example,dc=com"
  ]
}

data "ad_users" "department_users" {
  for_each = toset(var.search_ous)

  container = each.value
  scope     = "onelevel"

  filter = {
    enabled = true
  }
}

# Create department-specific groups based on user search results
resource "ad_group" "department_groups" {
  for_each = data.ad_users.department_users

  name             = "${basename(each.key)} Users"
  sam_account_name = "${replace(basename(each.key), " ", "")}Users"
  container        = "ou=Department Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "All users in ${basename(each.key)}"
}

# Add users to their respective department groups
resource "ad_group_membership" "department_memberships" {
  for_each = data.ad_users.department_users

  group_id = ad_group.department_groups[each.key].id
  members  = each.value.users[*].distinguished_name
}

# Create manager groups automatically
resource "ad_group" "managers_group" {
  name             = "All Managers"
  sam_account_name = "AllManagers"
  container        = "ou=Management Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "All users with manager titles"
}

resource "ad_group_membership" "managers_membership" {
  group_id = ad_group.managers_group.id
  members  = data.ad_users.managers.users[*].distinguished_name
}

# Generate comprehensive user reports
locals {
  all_users = flatten([
    for ou, users_data in data.ad_users.department_users : users_data.users
  ])

  user_analysis = {
    total_users = length(local.all_users)

    by_department = {
      for dept, users in {
        for user in local.all_users :
        user.department => user.department
        if user.department != null
        } : dept => length([
          for user in local.all_users :
          user if user.department == dept
      ])
    }

    by_title = {
      for title, users in {
        for user in local.all_users :
        user.title => user.title
        if user.title != null
        } : title => length([
          for user in local.all_users :
          user if user.title == title
      ])
    }

    enabled_count  = length([for u in local.all_users : u if u.enabled == true])
    disabled_count = length([for u in local.all_users : u if u.enabled == false])
    with_email     = length([for u in local.all_users : u if u.email != null && u.email != ""])
  }
}

# Output search results and analysis
output "search_results" {
  value = {
    it_users = {
      count = data.ad_users.it_users.user_count
      users = data.ad_users.it_users.users[*].sam_account_name
    }
    hr_users = {
      count = length(data.ad_users.hr_department.users)
      users = data.ad_users.hr_department.users[*].sam_account_name
    }
    managers = {
      count = length(data.ad_users.managers.users)
      users = data.ad_users.managers.users[*].display_name
    }
    disabled_users = {
      count = length(data.ad_users.disabled_users.users)
      users = data.ad_users.disabled_users.users[*].sam_account_name
    }
  }
}

output "user_statistics" {
  value = local.user_analysis
}

# Sample users for reference
output "sample_users" {
  value = {
    for idx, user in slice(data.ad_users.active_users.users, 0, min(5, length(data.ad_users.active_users.users))) :
    idx => {
      name       = user.display_name
      sam        = user.sam_account_name
      upn        = user.user_principal_name
      department = user.department
      title      = user.title
      email      = user.email
    }
  }
}