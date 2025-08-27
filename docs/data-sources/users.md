---
page_title: "Data Source ad_users"
description: |-
  Retrieves a list of Active Directory users based on search criteria. Supports filtering by name patterns, organizational information, account status, and email properties.
---

# Data Source (ad_users)

Retrieves a list of Active Directory users based on search criteria. Supports filtering by name patterns, organizational information, account status, and email properties.

This data source enables comprehensive searching and filtering of Active Directory user acuser_counts, making it easy to find users based on various criteria such as organizational attributes, acuser_count status, name patterns, and container locations.

## Key Features

- **Flexible Search Criteria**: Search by department, title, name patterns, and acuser_count status
- **Container-Based Search**: Search within specific OUs or containers
- **Scope Control**: Choose between base, one-level, or subtree searches
- **Acuser_count Status Filtering**: Filter by enabled/disabled status, lockout status, and password settings
- **Organizational Filtering**: Search by department, company, manager, and job title
- **Performance Optimized**: Efficient LDAP queries with proper filtering

## Example Usage

### Basic User Search

```terraform
# Find all users in a specific OU
data "ad_users" "department_users" {
  container = "ou=IT Department,ou=Departments,dc=example,dc=com"
  scope     = "subtree"
}

output "department_users" {
  value = {
    user_count = data.ad_users.department_users.user_count
    users = data.ad_users.department_users.users[*].display_name
  }
}
```

### Filtered User Search

```terraform
# Find all IT managers
data "ad_users" "it_managers" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    department = "IT"
    title      = "*Manager*"
    enabled    = true
  }
}

# Create management group
resource "ad_group" "it_managers" {
  name             = "IT Managers"
  sam_account_name = "ITManagers"
  container        = "ou=Management Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "All IT department managers"
}

# Add managers to the group
resource "ad_group_membership" "it_managers" {
  group_id = ad_group.it_managers.id
  members  = data.ad_users.it_managers.users[*].dn
}
```

### Search by Acuser_count Status

```terraform
# Find disabled user acuser_counts
data "ad_users" "disabled_users" {
  container = "dc=example,dc=com"
  scope     = "subtree"

  filter = {
    enabled = false
  }
}

# Find locked out acuser_counts
data "ad_users" "locked_users" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    locked_out = true
    enabled    = true  # Only enabled but locked acuser_counts
  }
}

# Generate security report
output "security_report" {
  value = {
    disabled_acuser_counts = {
      user_count = data.ad_users.disabled_users.user_count
      users = data.ad_users.disabled_users.users[*].sam_account_name
    }
    locked_acuser_counts = {
      user_count = data.ad_users.locked_users.user_count
      users = data.ad_users.locked_users.users[*].sam_account_name
    }
  }
}
```

### Search by Name Patterns

```terraform
# Users whose names start with "Admin"
data "ad_users" "admin_users" {
  container = "ou=Administrative Users,dc=example,dc=com"

  filter = {
    name_prefix = "Admin"
    enabled     = true
  }
}

# Service acuser_counts (names ending with "Service")
data "ad_users" "service_acuser_counts" {
  container = "ou=Service Acuser_counts,dc=example,dc=com"

  filter = {
    name_suffix = "Service"
    enabled     = true
  }
}

# Users with "Test" in their name
data "ad_users" "test_users" {
  filter = {
    name_contains = "Test"
  }
}
```

### Organizational Filtering

```terraform
# Find all users by department
data "ad_users" "by_department" {
  for_each = toset(["IT", "HR", "Finance", "Marketing"])

  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    department = each.value
    enabled    = true
  }
}

# Create department-based groups
resource "ad_group" "department_groups" {
  for_each = data.ad_users.by_department

  name             = "${each.key} Department"
  sam_account_name = "${each.key}Dept"
  container        = "ou=Department Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "${each.key} department members"
}

# Add department users to their groups
resource "ad_group_membership" "department_memberships" {
  for_each = data.ad_users.by_department

  group_id = ad_group.department_groups[each.key].id
  members  = each.value.users[*].dn
}
```

### Manager-Based Searches

```terraform
# Find users reporting to a specific manager
data "ad_user" "department_manager" {
  upn = "dept.manager@example.com"
}

data "ad_users" "direct_reports" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    manager = data.ad_user.department_manager.dn
    enabled = true
  }
}

# Create team group
resource "ad_group" "team_group" {
  name             = "${data.ad_user.department_manager.display_name} Team"
  sam_account_name = "${data.ad_user.department_manager.sam_account_name}Team"
  container        = "ou=Team Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "Team members reporting to ${data.ad_user.department_manager.display_name}"
}

resource "ad_group_membership" "team_membership" {
  group_id = ad_group.team_group.id
  members = concat(
    [data.ad_user.department_manager.dn],
    data.ad_users.direct_reports.users[*].dn
  )
}
```

### Complex Multi-Criteria Search

```terraform
# Find senior IT staff (managers and seniors)
data "ad_users" "senior_it_staff" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    department    = "IT"
    title         = "*Senior*,*Manager*,*Director*"  # Multiple title patterns
    enabled       = true
    has_manager   = true  # Must have a manager (not CEO level)
  }
}

# Find new employees (created in last 30 days)
data "ad_users" "new_employees" {
  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    enabled      = true
    created_days_ago = 30  # Created within last 30 days
  }
}
```

### Search Scope Examples

```terraform
# Base search - only the container itself
data "ad_users" "base_search" {
  container = "cn=specific-user,ou=users,dc=example,dc=com"
  scope     = "base"
}

# One level search - direct children only
data "ad_users" "direct_children" {
  container = "ou=Department Users,dc=example,dc=com"
  scope     = "onelevel"
}

# Subtree search - all descendants (default)
data "ad_users" "all_descendants" {
  container = "ou=Company,dc=example,dc=com"
  scope     = "subtree"
}
```

### Dynamic User Management

```terraform
# Find users needing access based on job title
data "ad_users" "privileged_users" {
  container = "dc=example,dc=com"
  scope     = "subtree"

  filter = {
    title   = "*Admin*,*Manager*,*Director*"
    enabled = true
  }
}

# Create privileged access group
resource "ad_group" "privileged_access" {
  name             = "Privileged Access Users"
  sam_account_name = "PrivilegedAccess"
  container        = "ou=Security Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "Users with privileged access requirements"
}

# Add privileged users
resource "ad_group_membership" "privileged_membership" {
  group_id = ad_group.privileged_access.id
  members  = data.ad_users.privileged_users.users[*].dn
}
```

### Reporting and Analysis

```terraform
# Comprehensive user analysis
data "ad_users" "all_users" {
  container = "dc=example,dc=com"
  scope     = "subtree"
}

# Generate detailed report
locals {
  user_analysis = {
    total_users = data.ad_users.all_users.user_count

    by_status = {
      enabled  = length([for u in data.ad_users.all_users.users : u if u.enabled])
      disabled = length([for u in data.ad_users.all_users.users : u if !u.enabled])
      locked   = length([for u in data.ad_users.all_users.users : u if u.locked_out])
    }

    by_department = {
      for dept in distinct([for u in data.ad_users.all_users.users : u.department if u.department != ""]) :
      dept => length([for u in data.ad_users.all_users.users : u if u.department == dept])
    }

    password_issues = {
      expired = length([for u in data.ad_users.all_users.users : u if u.password_expired])
      never_expires = length([for u in data.ad_users.all_users.users : u if u.password_never_expires])
    }
  }
}

output "user_statistics" {
  value = local.user_analysis
}
```

### Integration with External Systems

```terraform
# Find users based on external criteria
variable "target_departments" {
  type = list(string)
  default = ["Engineering", "Product", "Design"]
}

data "ad_users" "target_users" {
  for_each = toset(var.target_departments)

  container = "ou=Users,dc=example,dc=com"
  scope     = "subtree"

  filter = {
    department = each.value
    enabled    = true
  }
}

# Create application access groups
resource "ad_group" "app_access_groups" {
  for_each = data.ad_users.target_users

  name             = "${each.key} App Access"
  sam_account_name = "${replace(each.key, " ", "")}AppAccess"
  container        = "ou=Application Groups,dc=example,dc=com"
  scope            = "Global"
  category         = "Security"
  description      = "${each.key} department application access"
}

resource "ad_group_membership" "app_access_membership" {
  for_each = data.ad_users.target_users

  group_id = ad_group.app_access_groups[each.key].id
  members  = each.value.users[*].dn
}
```

## Available Filter Options

The `filter` block supports these search criteria:

### Name Pattern Filters
- `name_prefix`: Users whose display name starts with the specified string
- `name_suffix`: Users whose display name ends with the specified string
- `name_contains`: Users whose display name contains the specified string

### Acuser_count Status Filters
- `enabled`: Boolean filter for enabled/disabled acuser_counts
- `locked_out`: Boolean filter for locked out acuser_counts
- `password_expired`: Boolean filter for expired passwords
- `password_never_expires`: Boolean filter for password never expires flag

### Organizational Filters
- `department`: Filter by department attribute
- `company`: Filter by company attribute
- `title`: Filter by job title (supports wildcards)
- `manager`: Filter by manager's Distinguished Name
- `has_manager`: Boolean filter for users with/without managers

### Time-Based Filters
- `created_days_ago`: Users created within specified days (e.g., 30)
- `last_logon_days_ago`: Users who logged in within specified days

## Search Scope Options

- `base`: Search only the specified container itself
- `onelevel`: Search direct children of the container only
- `subtree`: Search the container and all descendants (default)

## Available Attributes

Each user in the results includes comprehensive user information:

### Identification
- `id`: ObjectGUID of the user
- `dn`: Full Distinguished Name
- `upn`: UPN (email-like identifier)
- `sam_account_name`: SAM acuser_count name
- `display_name`: Display name
- `sid`: Security Identifier

### Personal Information
- `given_name`: First name
- `surname`: Last name
- `email_address`: Email address
- `initials`: User initials

### Organizational Information
- `department`: Department name
- `company`: Company name
- `title`: Job title
- `manager`: Manager's Distinguished Name
- `office`: Office location
- `telephone_number`: Phone number

### Acuser_count Status
- `enabled`: Acuser_count enabled status
- `locked_out`: Acuser_count lockout status
- `password_expired`: Password expiration status
- `password_never_expires`: Password never expires flag
- `cannot_change_password`: Cannot change password flag

### Timestamps
- `created`: Acuser_count creation date
- `modified`: Last modification date
- `last_logon`: Last logon timestamp
- `last_password_set`: Last password change date

## Best Practices

### Efficient Searching
```terraform
# Use specific containers to limit scope
data "ad_users" "efficient_search" {
  container = "ou=IT Users,dc=example,dc=com"  # Not entire domain
  scope     = "onelevel"                       # Not subtree unless needed

  filter = {
    enabled = true  # Be specific about requirements
  }
}
```

### Combining Multiple Filters
```terraform
# Stack multiple criteria for precise results
data "ad_users" "precise_search" {
  container = "ou=Users,dc=example,dc=com"

  filter = {
    department = "IT"           # Specific department
    title      = "*Admin*"      # Admin roles
    enabled    = true           # Active acuser_counts only
    has_manager = true          # Must have manager
  }
}
```

### Handling Large Result Sets
```terraform
# For large domains, use specific filters
data "ad_users" "manageable_search" {
  container = "ou=Department,dc=example,dc=com"
  scope     = "onelevel"

  filter = {
    enabled = true
  }
}

# Process in batches if needed
locals {
  first_batch = slice(data.ad_users.manageable_search.users, 0, min(100, data.ad_users.manageable_search.user_count))
}
```

## Troubleshooting

### Common Issues

1. **No Results Found**
   ```
   # Check container and filters
   data "ad_users" "debug_search" {
     container = "ou=NonExistent,dc=example,dc=com"
   }
   ```
   Verify container DN and filter criteria.

2. **Too Many Results**
   ```
   # Use more specific filters
   filter = {
     department = "Specific Dept"  # Instead of searching all users
     enabled    = true
   }
   ```

3. **Permission Issues**
   ```
   Error: Insufficient permissions to search container
   ```
   Ensure service acuser_count has read permissions.

### Debug Configuration

```terraform
# Debug search with verbose output
data "ad_users" "debug_users" {
  container = "dc=example,dc=com"
  scope     = "onelevel"

  filter = {
    enabled = true
  }
}

output "debug_info" {
  value = {
    total_found = data.ad_users.debug_users.user_count
    container   = data.ad_users.debug_users.id
    sample_users = slice(data.ad_users.debug_users.users, 0, min(5, data.ad_users.debug_users.user_count))
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `container` (String) The DN of the container to search within. If not specified, searches from the base DN. Example: `OU=Users,DC=example,DC=com`
- `filter` (Block, Optional) Filter criteria for searching users. All specified criteria must match (AND logic). (see [below for nested schema](#nestedblock--filter))
- `scope` (String) The search scope to use. Valid values: `base`, `onelevel`, `subtree`. Defaults to `subtree`.

### Read-Only

- `id` (String) A computed identifier for this data source instance.
- `user_count` (Number) The total number of users found matching the search criteria.
- `users` (Attributes List) List of users matching the search criteria. (see [below for nested schema](#nestedatt--users))

<a id="nestedblock--filter"></a>
### Nested Schema for `filter`

Optional:

- `company` (String) Filter by company name (exact match, case-insensitive).
- `department` (String) Filter by department. Case-insensitive partial match.
- `email_domain` (String) Filter by email domain (e.g., `example.com`). Only returns users whose email addresses end with the specified domain.
- `enabled` (Boolean) Filter by account status. `true` returns only enabled accounts, `false` returns only disabled accounts. If not specified, returns all accounts.
- `has_email` (Boolean) Filter by email presence. `true` returns only users with email addresses, `false` returns only users without email addresses. If not specified, returns all users.
- `manager` (String) Filter by manager. Accepts Distinguished Name, GUID, UPN, or SAM account name.
- `member_of` (String) Filter by group membership. Only returns users who are members of the specified group (Distinguished Name). Includes nested group membership. Example: `CN=Domain Users,CN=Users,DC=example,DC=com`
- `name_contains` (String) Users whose common name contains this string. Case-insensitive.
- `name_prefix` (String) Users whose common name starts with this string. Case-insensitive.
- `name_suffix` (String) Users whose common name ends with this string. Case-insensitive.
- `not_member_of` (String) Filter by group non-membership. Only returns users who are NOT members of the specified group (Distinguished Name). Includes nested group membership. Example: `CN=Disabled Users,CN=Users,DC=example,DC=com`
- `office` (String) Filter by office location (exact match, case-insensitive).
- `title` (String) Filter by job title. Case-insensitive partial match.


<a id="nestedatt--users"></a>
### Nested Schema for `users`

Read-Only:

- `account_enabled` (Boolean) Whether the user account is enabled.
- `company` (String) The company name of the user.
- `department` (String) The department of the user.
- `display_name` (String) The display name of the user.
- `dn` (String) The full Distinguished Name of the user.
- `email_address` (String) The primary email address of the user.
- `given_name` (String) The first name (given name) of the user.
- `id` (String) The objectGUID of the user.
- `last_logon` (String) When the user last logged on (RFC3339 format).
- `manager` (String) The Distinguished Name of the user's manager.
- `name` (String) The common name (cn) of the user.
- `office` (String) The physical office location of the user.
- `sam_account_name` (String) The SAM account name (pre-Windows 2000 name) of the user.
- `surname` (String) The last name (surname) of the user.
- `title` (String) The job title of the user.
- `upn` (String) The User Principal Name (UPN) of the user.
- `when_created` (String) When the user was created (RFC3339 format).
