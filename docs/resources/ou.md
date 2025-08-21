---
page_title: "Resource ad_ou"
description: |-
  Manages an Active Directory organizational unit (OU). OUs are used to organize other Active Directory objects in a hierarchical structure for administrative purposes.
---

# Resource (ad_ou)

Manages an Active Directory organizational unit (OU). OUs are used to organize other Active Directory objects in a hierarchical structure for administrative purposes.

Organizational Units provide a hierarchical structure for organizing Active Directory objects, enabling delegation of administrative authority and application of Group Policy. This resource allows you to create and manage OUs with full control over their placement and protection settings.

## Key Features

- **Hierarchical Organization**: Create nested OU structures for logical organization
- **Administrative Delegation**: Enable delegation of administrative tasks at the OU level
- **Protection Management**: Control whether OUs can be accidentally deleted
- **Group Policy Integration**: OUs serve as containers for Group Policy application
- **Import Support**: Import existing organizational units using multiple identifier formats
- **Automatic Attributes**: Computed attributes like Distinguished Name and GUID

## Example Usage

### Basic Organizational Unit

```terraform
resource "ad_ou" "departments" {
  name        = "Departments"
  path        = "dc=example,dc=com"
  description = "Container for all department OUs"
  protected   = true
}
```

### Nested Organizational Structure

```terraform
# Root OU for company structure
resource "ad_ou" "company" {
  name        = "Acme Corporation"
  path        = "dc=example,dc=com"
  description = "Root OU for Acme Corporation"
  protected   = true
}

# Department OUs under company
resource "ad_ou" "it_department" {
  name        = "IT Department"
  path        = ad_ou.company.dn
  description = "Information Technology Department"
  protected   = true
}

resource "ad_ou" "hr_department" {
  name        = "HR Department"
  path        = ad_ou.company.dn
  description = "Human Resources Department"
  protected   = true
}

# Sub-departments
resource "ad_ou" "it_servers" {
  name        = "Servers"
  path        = ad_ou.it_department.dn
  description = "Server computer accounts"
  protected   = false
}

resource "ad_ou" "it_workstations" {
  name        = "Workstations"
  path        = ad_ou.it_department.dn
  description = "User workstation accounts"
  protected   = false
}
```

### Administrative Delegation Structure

```terraform
# Create regional OUs for administrative delegation
resource "ad_ou" "north_america" {
  name        = "North America"
  path        = "dc=example,dc=com"
  description = "North American operations"
  protected   = true
}

resource "ad_ou" "europe" {
  name        = "Europe"
  path        = "dc=example,dc=com"
  description = "European operations"
  protected   = true
}

# Site-specific OUs within regions
resource "ad_ou" "new_york" {
  name        = "New York"
  path        = ad_ou.north_america.dn
  description = "New York office"
  protected   = false
}

resource "ad_ou" "london" {
  name        = "London"
  path        = ad_ou.europe.dn
  description = "London office"
  protected   = false
}

# Functional OUs within sites
resource "ad_ou" "ny_users" {
  name        = "Users"
  path        = ad_ou.new_york.dn
  description = "New York user accounts"
  protected   = false
}

resource "ad_ou" "ny_computers" {
  name        = "Computers"
  path        = ad_ou.new_york.dn
  description = "New York computer accounts"
  protected   = false
}
```

### Complete Infrastructure Organization

```terraform
# Root infrastructure OU
resource "ad_ou" "infrastructure" {
  name        = "Infrastructure"
  path        = "dc=example,dc=com"
  description = "IT Infrastructure organization"
  protected   = true
}

# Service-specific OUs
resource "ad_ou" "servers" {
  name        = "Servers"
  path        = ad_ou.infrastructure.dn
  description = "Server computer accounts"
  protected   = true
}

resource "ad_ou" "service_accounts" {
  name        = "Service Accounts"
  path        = ad_ou.infrastructure.dn
  description = "Service and application accounts"
  protected   = true
}

resource "ad_ou" "groups" {
  name        = "Groups"
  path        = ad_ou.infrastructure.dn
  description = "Security and distribution groups"
  protected   = true
}

# Application-specific nested structure
resource "ad_ou" "web_servers" {
  name        = "Web Servers"
  path        = ad_ou.servers.dn
  description = "Web server computer accounts"
  protected   = false
}

resource "ad_ou" "database_servers" {
  name        = "Database Servers"
  path        = ad_ou.servers.dn
  description = "Database server computer accounts"
  protected   = false
}

# Create groups within the groups OU
resource "ad_group" "web_admins" {
  name             = "Web Administrators"
  sam_account_name = "WebAdmins"
  container        = ad_ou.groups.dn
  scope            = "Global"
  category         = "Security"
  description      = "Web server administrators"
}
```

### Environment-Based Organization

```terraform
# Environment separation
resource "ad_ou" "environments" {
  name        = "Environments"
  path        = "dc=example,dc=com"
  description = "Environment-based organization"
  protected   = true
}

resource "ad_ou" "production" {
  name        = "Production"
  path        = ad_ou.environments.dn
  description = "Production environment resources"
  protected   = true
}

resource "ad_ou" "staging" {
  name        = "Staging"
  path        = ad_ou.environments.dn
  description = "Staging environment resources"
  protected   = false
}

resource "ad_ou" "development" {
  name        = "Development"
  path        = ad_ou.environments.dn
  description = "Development environment resources"
  protected   = false
}

# Resource type OUs within each environment
resource "ad_ou" "prod_servers" {
  name        = "Servers"
  path        = ad_ou.production.dn
  description = "Production servers"
  protected   = true
}

resource "ad_ou" "prod_service_accounts" {
  name        = "Service Accounts"
  path        = ad_ou.production.dn
  description = "Production service accounts"
  protected   = true
}
```

## Import Examples

Organizational Units can be imported using various identifier formats:

### Import by Distinguished Name
```bash
terraform import ad_ou.example "ou=IT Department,dc=example,dc=com"
```

### Import by GUID
```bash
terraform import ad_ou.example "12345678-1234-5678-9012-123456789012"
```

## OU Protection Explained

The `protected` attribute controls whether the OU has the "Protect object from accidental deletion" flag set:

### Protected OU (Recommended for Root OUs)
```terraform
resource "ad_ou" "important_ou" {
  name        = "Critical Infrastructure"
  path        = "dc=example,dc=com"
  description = "Contains critical infrastructure objects"
  protected   = true  # Prevents accidental deletion
}
```

### Unprotected OU (For Dynamic OUs)
```terraform
resource "ad_ou" "temporary_projects" {
  name        = "Temporary Projects"
  path        = "ou=Projects,dc=example,dc=com"
  description = "Container for temporary project resources"
  protected   = false  # Allows easier deletion when projects end
}
```

## Integration with Other Resources

### Using OUs with Groups

```terraform
resource "ad_ou" "department_groups" {
  name        = "Department Groups"
  path        = "dc=example,dc=com"
  description = "Security and distribution groups by department"
  protected   = true
}

resource "ad_group" "it_security" {
  name             = "IT Security Team"
  sam_account_name = "ITSecurity"
  container        = ad_ou.department_groups.dn
  scope            = "Global"
  category         = "Security"
  description      = "IT Security team members"
}

resource "ad_group" "hr_staff" {
  name             = "HR Staff"
  sam_account_name = "HRStaff"
  container        = ad_ou.department_groups.dn
  scope            = "Global"
  category         = "Security"
  description      = "Human Resources staff members"
}
```

### Dynamic OU Structure from Variables

```terraform
variable "departments" {
  type = list(object({
    name        = string
    description = string
    protected   = bool
  }))
  default = [
    {
      name        = "Engineering"
      description = "Engineering department"
      protected   = true
    },
    {
      name        = "Sales"
      description = "Sales department"
      protected   = true
    },
    {
      name        = "Marketing"
      description = "Marketing department"
      protected   = true
    }
  ]
}

# Create department OUs dynamically
resource "ad_ou" "departments" {
  for_each = {
    for dept in var.departments : dept.name => dept
  }

  name        = each.value.name
  path        = "dc=example,dc=com"
  description = each.value.description
  protected   = each.value.protected
}

# Create sub-OUs for each department
resource "ad_ou" "department_users" {
  for_each = {
    for dept in var.departments : dept.name => dept
  }

  name        = "Users"
  path        = ad_ou.departments[each.key].dn
  description = "${each.value.description} user accounts"
  protected   = false
}

resource "ad_ou" "department_groups" {
  for_each = {
    for dept in var.departments : dept.name => dept
  }

  name        = "Groups"
  path        = ad_ou.departments[each.key].dn
  description = "${each.value.description} security groups"
  protected   = false
}
```

## Best Practices

### Naming Conventions

```terraform
# Use clear, descriptive names
resource "ad_ou" "good_naming" {
  name        = "Application Servers"        # Clear and descriptive
  path        = "ou=Infrastructure,dc=example,dc=com"
  description = "Servers hosting business applications"
  protected   = true
}

# Avoid generic or cryptic names
# Don't do this:
# name = "Stuff"  # Too generic
# name = "AS"     # Too cryptic
```

### Hierarchical Organization

```terraform
# Plan your OU hierarchy carefully
# Root level - major organizational divisions
resource "ad_ou" "company_root" {
  name = "Acme Corp"
  path = "dc=example,dc=com"
  protected = true
}

# Second level - functional areas
resource "ad_ou" "it_operations" {
  name = "IT Operations"
  path = ad_ou.company_root.dn
  protected = true
}

# Third level - specific functions
resource "ad_ou" "server_management" {
  name = "Server Management"
  path = ad_ou.it_operations.dn
  protected = false
}

# Fourth level - resource types
resource "ad_ou" "web_servers" {
  name = "Web Servers"
  path = ad_ou.server_management.dn
  protected = false
}
```

### Protection Strategy

```terraform
# Protect important root-level OUs
resource "ad_ou" "protected_root" {
  name      = "Corporate Infrastructure"
  path      = "dc=example,dc=com"
  protected = true  # Root-level OUs should be protected
}

# Don't protect leaf OUs that might be deleted frequently
resource "ad_ou" "temporary_projects" {
  name      = "Project Alpha"
  path      = "ou=Projects,dc=example,dc=com"
  protected = false  # Project OUs can be deleted when projects end
}
```

### Administrative Delegation

```terraform
# Structure OUs to support administrative delegation
resource "ad_ou" "regional_ops" {
  name        = "Regional Operations"
  path        = "dc=example,dc=com"
  description = "Regional IT operations teams"
  protected   = true
}

# Regional OUs for delegation
resource "ad_ou" "west_region" {
  name        = "West Region"
  path        = ad_ou.regional_ops.dn
  description = "West region IT operations"
  protected   = false
}

# Create admin groups for delegation
resource "ad_group" "west_region_admins" {
  name             = "West Region Admins"
  sam_account_name = "WestRegionAdmins"
  container        = ad_ou.west_region.dn
  scope            = "Global"
  category         = "Security"
  description      = "Administrators for west region OU"
}
```

## Troubleshooting

### Common Issues

1. **Parent Container Not Found**
   ```
   Error: Parent container 'ou=NonExistent,dc=example,dc=com' not found
   ```
   Ensure the parent container exists before creating the OU.

2. **Protected OU Deletion**
   ```
   Error: Cannot delete protected OU
   ```
   Set `protected = false` before attempting to delete, or manually remove protection in AD.

3. **Invalid Characters in Name**
   ```
   Error: OU name contains invalid characters
   ```
   Avoid special characters like quotes, backslashes, commas, etc.

4. **Circular Dependencies**
   ```
   Error: Cycle detected in resource dependencies
   ```
   Ensure your OU hierarchy doesn't create circular references.

### Debug Configuration

```terraform
# For debugging, create a simple test OU first
resource "ad_ou" "test_ou" {
  name        = "Test OU"
  path        = "dc=example,dc=com"
  description = "Test organizational unit"
  protected   = false
}

# Then build more complex structures
output "test_ou_info" {
  value = {
    id   = ad_ou.test_ou.id
    dn   = ad_ou.test_ou.dn
    guid = ad_ou.test_ou.guid
  }
}
```

### Validation Examples

```terraform
# Validate OU creation before using in other resources
resource "ad_ou" "validated_ou" {
  name        = "Validated OU"
  path        = "dc=example,dc=com"
  description = "OU with validation"
  protected   = true
}

# Use depends_on to ensure OU exists
resource "ad_group" "ou_dependent_group" {
  name             = "OU Group"
  sam_account_name = "OUGroup"
  container        = ad_ou.validated_ou.dn
  scope            = "Global"
  category         = "Security"

  depends_on = [ad_ou.validated_ou]
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) The name of the organizational unit. This becomes the CN component of the distinguished name.
- `path` (String) The distinguished name of the parent container where the OU will be created (e.g., `dc=example,dc=com` or `ou=Parent,dc=example,dc=com`).

### Optional

- `description` (String) A description for the organizational unit. This is optional and can be used to provide additional context about the OU's purpose.
- `protected` (Boolean) Whether the OU is protected from accidental deletion. When true, the OU cannot be deleted until protection is disabled. Defaults to `false`.

### Read-Only

- `dn` (String) The distinguished name of the OU. This is automatically generated based on the name and path.
- `guid` (String) The objectGUID of the OU in string format. This is the same value as the `id` attribute.
- `id` (String) The objectGUID of the OU. This is automatically assigned by Active Directory and used as the unique identifier.