# AD Groups Data Source Example

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

# Find all groups in a specific OU
data "ad_groups" "department_groups" {
  container = "ou=Departments,dc=example,dc=com"
  scope     = "subtree"
}

# Find security groups with "Admin" in the name
data "ad_groups" "admin_groups" {
  container = "dc=example,dc=com"
  scope     = "subtree"

  filter = {
    name_contains = "Admin"
    category      = "Security"
  }
}

# Find all Global Security groups in IT OU
data "ad_groups" "it_security_groups" {
  container = "ou=IT,ou=Departments,dc=example,dc=com"
  scope     = "onelevel" # Only direct children

  filter = {
    category = "Security"
    scope    = "Global"
  }
}

# Find all Distribution groups for email
data "ad_groups" "email_lists" {
  container = "ou=Email Groups,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    category = "Distribution"
  }
}

# Groups that start with "APP-"
data "ad_groups" "application_groups" {
  container = "ou=Applications,dc=example,dc=com"

  filter = {
    name_prefix = "APP-"
    category    = "Security"
  }
}

# Groups that end with "-Users"
data "ad_groups" "user_groups" {
  container = "ou=Access Groups,dc=example,dc=com"

  filter = {
    name_suffix = "-Users"
    scope       = "Global"
  }
}

# Find empty groups (no members)
data "ad_groups" "empty_groups" {
  container = "ou=Cleanup,dc=example,dc=com"

  filter = {
    has_members = false
  }
}

# Find groups with members (active groups)
data "ad_groups" "active_groups" {
  container = "ou=Active Groups,dc=example,dc=com"

  filter = {
    has_members = true
    category    = "Security"
  }
}

# Complex filtering - application security groups with members
data "ad_groups" "app_security_groups" {
  container = "dc=example,dc=com"
  scope     = "subtree"

  filter = {
    name_prefix = "APP-"
    name_suffix = "-SEC"
    category    = "Security"
    scope       = "Global"
    has_members = true
  }
}

# Use results to create related resources
resource "ad_group" "app_admin_groups" {
  for_each = {
    for group in data.ad_groups.app_security_groups.groups :
    group.sam_account_name => group
  }

  name             = "${each.value.name} Administrators"
  sam_account_name = "${each.value.sam_account_name}Admin"
  container        = dirname(each.value.distinguished_name)
  scope            = each.value.scope
  category         = "Security"
  description      = "Administrators for ${each.value.display_name}"
}

# Generate comprehensive reports
locals {
  group_analysis = {
    total_groups = data.ad_groups.department_groups.group_count

    by_category = {
      security     = length([for g in data.ad_groups.department_groups.groups : g if g.category == "Security"])
      distribution = length([for g in data.ad_groups.department_groups.groups : g if g.category == "Distribution"])
    }

    by_scope = {
      global      = length([for g in data.ad_groups.department_groups.groups : g if g.scope == "Global"])
      universal   = length([for g in data.ad_groups.department_groups.groups : g if g.scope == "Universal"])
      domainlocal = length([for g in data.ad_groups.department_groups.groups : g if g.scope == "DomainLocal"])
    }

    empty_groups = length([for g in data.ad_groups.department_groups.groups : g if g.member_count == 0])
    large_groups = length([for g in data.ad_groups.department_groups.groups : g if g.member_count > 100])
  }
}

# Output search results and analysis
output "search_results" {
  value = {
    department_groups = {
      count  = data.ad_groups.department_groups.group_count
      groups = data.ad_groups.department_groups.groups[*].name
    }
    admin_groups = {
      count  = length(data.ad_groups.admin_groups.groups)
      groups = data.ad_groups.admin_groups.groups[*].name
    }
    application_groups = {
      count  = length(data.ad_groups.application_groups.groups)
      groups = data.ad_groups.application_groups.groups[*].name
    }
  }
}

output "group_statistics" {
  value = local.group_analysis
}