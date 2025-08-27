# Complete AD Provider Example
# This example demonstrates comprehensive usage of the AD provider
# including organizational structure, groups, and memberships

terraform {
  required_providers {
    ad = {
      source  = "isometry/ad"
      version = "~> 1.0"
    }
  }
}

# Provider configuration with production settings
provider "ad" {
  domain   = "example.com"
  username = "svc-terraform@example.com"
  password = "secure_service_password"

  # Production connection settings
  use_tls         = true
  skip_tls_verify = false
  max_connections = 10
  connect_timeout = 30
  max_retries     = 3
}

# Create organizational structure
resource "ad_ou" "departments" {
  name        = "Departments"
  path        = "dc=example,dc=com"
  description = "Top-level departments"
}

resource "ad_ou" "it_department" {
  name        = "IT Department"
  path        = ad_ou.departments.dn
  description = "Information Technology Department"
}

resource "ad_ou" "hr_department" {
  name        = "HR Department"
  path        = ad_ou.departments.dn
  description = "Human Resources Department"
}

# IT Department sub-structure
resource "ad_ou" "it_teams" {
  name        = "Teams"
  path        = ad_ou.it_department.dn
  description = "IT Department teams"
}

resource "ad_ou" "it_groups" {
  name        = "Groups"
  path        = ad_ou.it_department.dn
  description = "IT Department groups"
}

resource "ad_ou" "it_service_accounts" {
  name                  = "Service Accounts"
  path                  = ad_ou.it_department.dn
  description           = "IT service accounts"
  protect_from_deletion = true
}

# Create IT teams
resource "ad_ou" "it_team_ous" {
  for_each = toset([
    "Development",
    "Operations",
    "Security",
    "Support"
  ])

  name        = each.key
  path        = ad_ou.it_teams.dn
  description = "${each.key} team"
}

# Create security groups for each IT team
resource "ad_group" "it_team_groups" {
  for_each = ad_ou.it_team_ous

  name             = "IT ${each.value.name} Team"
  sam_account_name = "IT${each.value.name}Team"
  container        = ad_ou.it_groups.dn
  scope            = "Global"
  category         = "Security"
  description      = "Members of the IT ${each.value.name} team"
}

# Create application-specific groups
resource "ad_group" "app_groups" {
  for_each = {
    web_servers = {
      name = "Web Server Access"
      sam  = "WebServerAccess"
      desc = "Access to web servers"
    }
    database_admins = {
      name = "Database Administrators"
      sam  = "DatabaseAdmins"
      desc = "Database administration rights"
    }
    backup_operators = {
      name = "Backup Operators"
      sam  = "BackupOps"
      desc = "Backup system operators"
    }
  }

  name             = each.value.name
  sam_account_name = each.value.sam
  container        = ad_ou.it_groups.dn
  scope            = "Global"
  category         = "Security"
  description      = each.value.desc
}

# Create distribution groups for email
resource "ad_group" "distribution_groups" {
  for_each = {
    all_staff = {
      name = "All Staff"
      sam  = "AllStaff"
      desc = "All company staff members"
    }
    it_announcements = {
      name = "IT Announcements"
      sam  = "ITAnnouncements"
      desc = "IT department announcements"
    }
    managers = {
      name = "All Managers"
      sam  = "AllManagers"
      desc = "All department managers"
    }
  }

  name             = each.value.name
  sam_account_name = each.value.sam
  container        = ad_ou.it_groups.dn
  scope            = "Universal"
  category         = "Distribution"
  description      = each.value.desc
}

# Lookup existing users for group membership examples
data "ad_users" "it_users" {
  container = "ou=IT,ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    department = "Information Technology"
    enabled    = true
  }
}

data "ad_users" "managers" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    title_contains = "Manager"
    enabled        = true
  }
}

# Add IT users to their respective team groups based on title/role
resource "ad_group_membership" "dev_team" {
  group_id = ad_group.it_team_groups["Development"].id

  # Add users with "Developer" in their title
  members = [
    for user in data.ad_users.it_users.users :
    user.dn
    if user.title != null && contains(split(" ", lower(user.title)), "developer")
  ]
}

resource "ad_group_membership" "ops_team" {
  group_id = ad_group.it_team_groups["Operations"].id

  # Add users with "Operations" or "Engineer" in their title
  members = [
    for user in data.ad_users.it_users.users :
    user.dn
    if user.title != null && (
      contains(split(" ", lower(user.title)), "operations") ||
      contains(split(" ", lower(user.title)), "engineer")
    )
  ]
}

resource "ad_group_membership" "security_team" {
  group_id = ad_group.it_team_groups["Security"].id

  # Add users with "Security" in their title
  members = [
    for user in data.ad_users.it_users.users :
    user.dn
    if user.title != null && contains(split(" ", lower(user.title)), "security")
  ]
}

# Add all IT users to general IT groups
resource "ad_group_membership" "all_it_staff" {
  group_id = ad_group.distribution_groups["all_staff"].id
  members  = data.ad_users.it_users.users[*].dn
}

# Add managers to managers group
resource "ad_group_membership" "all_managers" {
  group_id = ad_group.distribution_groups["managers"].id
  members  = data.ad_users.managers.users[*].dn
}

# Create nested group structure for database access
resource "ad_group" "database_access_levels" {
  for_each = {
    read_only = {
      name = "Database Read Only"
      sam  = "DatabaseReadOnly"
      desc = "Read-only database access"
    }
    read_write = {
      name = "Database Read Write"
      sam  = "DatabaseReadWrite"
      desc = "Read-write database access"
    }
  }

  name             = each.value.name
  sam_account_name = each.value.sam
  container        = ad_ou.it_groups.dn
  scope            = "Global"
  category         = "Security"
  description      = each.value.desc
}

# Nested group membership - add read-only group to read-write group
resource "ad_group_membership" "database_nesting" {
  group_id = ad_group.database_access_levels["read_write"].id
  members = [
    ad_group.database_access_levels["read_only"].dn
  ]
}

# Add database admins to read-write group
resource "ad_group_membership" "database_admins" {
  group_id = ad_group.app_groups["database_admins"].id
  members = [
    ad_group.database_access_levels["read_write"].dn
  ]
}

# Comprehensive outputs for monitoring and validation
output "organizational_structure" {
  value = {
    departments = {
      it = {
        dn         = ad_ou.it_department.dn
        teams_ou   = ad_ou.it_teams.dn
        groups_ou  = ad_ou.it_groups.dn
        service_ou = ad_ou.it_service_accounts.dn
      }
      hr = {
        dn = ad_ou.hr_department.dn
      }
    }
  }
}

output "group_structure" {
  value = {
    team_groups = {
      for name, group in ad_group.it_team_groups :
      name => {
        name = group.name
        dn   = group.dn
        sid  = group.sid
      }
    }

    app_groups = {
      for name, group in ad_group.app_groups :
      name => {
        name = group.name
        dn   = group.dn
        sid  = group.sid
      }
    }

    distribution_groups = {
      for name, group in ad_group.distribution_groups :
      name => {
        name = group.name
        dn   = group.dn
        sid  = group.sid
      }
    }
  }
}

output "membership_summary" {
  value = {
    it_users_found   = length(data.ad_users.it_users.users)
    managers_found   = length(data.ad_users.managers.users)
    dev_team_members = length(ad_group_membership.dev_team.members)
    ops_team_members = length(ad_group_membership.ops_team.members)
    security_members = length(ad_group_membership.security_team.members)
  }
}

# Example of conditional resource creation
locals {
  create_test_resources = false # Set to true to create test resources
}

resource "ad_group" "test_group" {
  count = local.create_test_resources ? 1 : 0

  name             = "Test Group"
  sam_account_name = "TestGroup"
  container        = ad_ou.it_groups.dn
  scope            = "Global"
  category         = "Security"
  description      = "Temporary test group"
}
