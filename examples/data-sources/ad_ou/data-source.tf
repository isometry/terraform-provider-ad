# AD OU Data Source Example

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

# Lookup OU by name
data "ad_ou" "departments" {
  name = "Departments"
}

# Lookup OU by Distinguished Name
data "ad_ou" "by_dn" {
  dn = "ou=IT Department,ou=Departments,dc=example,dc=com"
}

# Lookup OU by GUID
data "ad_ou" "by_guid" {
  id = "12345678-1234-5678-9012-123456789012"
}

# Lookup OU by path (alternative to DN)
data "ad_ou" "by_path" {
  path = "ou=Security Groups,ou=IT Department,ou=Departments,dc=example,dc=com"
}

# Use OU data to create resources in the correct container
resource "ad_group" "department_group" {
  name             = "IT Department Staff"
  sam_account_name = "ITStaff"
  container        = data.ad_ou.by_dn.dn
  scope            = "Global"
  category         = "Security"
  description      = "All IT Department staff members"
}

# Create nested OU structure based on existing OU
resource "ad_ou" "nested_ou" {
  name        = "Contractors"
  path        = data.ad_ou.by_dn.dn
  description = "Contractor accounts within ${data.ad_ou.by_dn.name}"
}

# Use OU information to organize resources
resource "ad_ou" "sub_departments" {
  for_each = toset([
    "Development",
    "Operations",
    "Support"
  ])

  name        = each.key
  path        = data.ad_ou.by_dn.dn
  description = "${each.key} team within ${data.ad_ou.by_dn.name}"
}

# Create groups for each sub-department
resource "ad_group" "sub_department_groups" {
  for_each = ad_ou.sub_departments

  name             = "${each.value.name} Team"
  sam_account_name = "${each.value.name}Team"
  container        = each.value.dn
  scope            = "Global"
  category         = "Security"
  description      = "Members of the ${each.value.name} team"
}

# Output OU information
output "ou_details" {
  value = {
    departments = {
      name        = data.ad_ou.departments.name
      dn          = data.ad_ou.departments.dn
      description = data.ad_ou.departments.description
      protected   = data.ad_ou.departments.protect_from_deletion
    }
    it_department = {
      name        = data.ad_ou.by_dn.name
      dn          = data.ad_ou.by_dn.dn
      description = data.ad_ou.by_dn.description
      protected   = data.ad_ou.by_dn.protect_from_deletion
    }
  }
}

output "created_structure" {
  value = {
    sub_departments = {
      for name, ou in ad_ou.sub_departments :
      name => {
        dn          = ou.dn
        description = ou.description
      }
    }
    groups = {
      for name, group in ad_group.sub_department_groups :
      name => {
        dn        = group.dn
        container = group.container
      }
    }
  }
}
