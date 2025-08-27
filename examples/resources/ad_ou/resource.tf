# AD Organizational Unit Example

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

# Basic OU
resource "ad_ou" "departments" {
  name        = "Departments"
  path        = "dc=example,dc=com"
  description = "Organizational units for company departments"
}

# Nested OU structure
resource "ad_ou" "it_department" {
  name        = "IT Department"
  path        = ad_ou.departments.dn
  description = "Information Technology Department"
}

resource "ad_ou" "it_teams" {
  name        = "Teams"
  path        = ad_ou.it_department.dn
  description = "IT Department teams"
}

# Protected OU (cannot be accidentally deleted)
resource "ad_ou" "critical_systems" {
  name                  = "Critical Systems"
  path                  = ad_ou.it_department.dn
  description           = "Critical system accounts and groups"
  protect_from_deletion = true
}

# OU for different purposes
resource "ad_ou" "service_accounts" {
  name        = "Service Accounts"
  path        = ad_ou.it_department.dn
  description = "Service accounts for applications"
}

resource "ad_ou" "security_groups" {
  name        = "Security Groups"
  path        = ad_ou.it_department.dn
  description = "Security groups for IT resources"
}

resource "ad_ou" "distribution_groups" {
  name        = "Distribution Groups"
  path        = ad_ou.it_department.dn
  description = "Distribution groups for email"
}

# Use OU as container for other resources
resource "ad_group" "it_admins" {
  name             = "IT Administrators"
  sam_account_name = "ITAdmins"
  container        = ad_ou.security_groups.dn
  scope            = "Global"
  category         = "Security"
  description      = "IT Department administrators"
}

# Complex OU hierarchy for applications
resource "ad_ou" "applications" {
  name        = "Applications"
  path        = "dc=example,dc=com"
  description = "Application-specific organizational units"
}

resource "ad_ou" "web_applications" {
  name        = "Web Applications"
  path        = ad_ou.applications.dn
  description = "Web application resources"
}

resource "ad_ou" "database_applications" {
  name        = "Database Applications"
  path        = ad_ou.applications.dn
  description = "Database application resources"
}

# Output OU information
output "ou_structure" {
  value = {
    departments = {
      name = ad_ou.departments.name
      dn   = ad_ou.departments.dn
    }
    it_department = {
      name = ad_ou.it_department.name
      dn   = ad_ou.it_department.dn
    }
    protected_ou = {
      name      = ad_ou.critical_systems.name
      dn        = ad_ou.critical_systems.dn
      protected = ad_ou.critical_systems.protect_from_deletion
    }
  }
}
