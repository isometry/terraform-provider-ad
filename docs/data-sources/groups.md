---
page_title: "Data Source ad_groups"
description: |-
  Retrieves a list of Active Directory groups based on search criteria. Supports filtering by name patterns, group type, location, and membership status.
---

# Data Source (ad_groups)

Retrieves a list of Active Directory groups based on search criteria. Supports filtering by name patterns, group type, location, and membership status.

This data source enables comprehensive searching and filtering of Active Directory groups, making it easy to find groups based on various criteria such as name patterns, group types, container locations, and membership status.

## Key Features

- **Flexible Search Criteria**: Search by name patterns, group type, scope, and membership status
- **Container-Based Search**: Search within specific OUs or containers
- **Scope Control**: Choose between base, one-level, or subtree searches
- **Comprehensive Results**: Get complete group information including member group_counts
- **Performance Optimized**: Efficient LDAP queries with proper filtering

## Example Usage

### Basic Group Search

```terraform
# Find all groups in a specific OU
data "ad_groups" "department_groups" {
  container = "ou=Departments,dc=example,dc=com"
  scope     = "subtree"
}

output "department_groups" {
  value = {
    group_count  = data.ad_groups.department_groups.group_count
    groups = data.ad_groups.department_groups.groups[*].name
  }
}
```

### Filtered Group Search

```terraform
# Find security groups with "Admin" in the name
data "ad_groups" "admin_groups" {
  container = "dc=example,dc=com"
  scope     = "subtree"

  filter = {
    name_contains = "Admin"
    category      = "Security"
  }
}

# Create a summary of admin groups
output "admin_groups_summary" {
  value = {
    for group in data.ad_groups.admin_groups.groups : group.sam_acgroup_count_name => {
      name         = group.display_name
      dn           = group.dn
      scope        = group.scope
      member_group_count = group.member_group_count
    }
  }
}
```

### Search by Group Type and Location

```terraform
# Find all Global Security groups in IT OU
data "ad_groups" "it_security_groups" {
  container = "ou=IT,ou=Departments,dc=example,dc=com"
  scope     = "onelevel"  # Only direct children

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
```

### Search by Name Patterns

```terraform
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

# Groups containing "Project"
data "ad_groups" "project_groups" {
  filter = {
    name_contains = "Project"
    has_members   = true  # Only groups with members
  }
}
```

### Membership-Based Filtering

```terraform
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
```

### Complex Filtering Scenarios

```terraform
# Find all application-related security groups with members
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

# Use the results to create related resources
resource "ad_group" "app_admin_groups" {
  for_each = {
    for group in data.ad_groups.app_security_groups.groups :
    group.sam_acgroup_count_name => group
  }

  name             = "${each.value.name} Administrators"
  sam_acgroup_count_name = "${each.value.sam_acgroup_count_name}Admin"
  container        = dirname(each.value.dn)
  scope            = each.value.scope
  category         = "Security"
  description      = "Administrators for ${each.value.display_name}"
}
```

### Search Scope Examples

```terraform
# Base search - only the container itself (if it's a group)
data "ad_groups" "base_search" {
  container = "cn=specific-group,ou=groups,dc=example,dc=com"
  scope     = "base"
}

# One level search - direct children only
data "ad_groups" "direct_children" {
  container = "ou=Department Groups,dc=example,dc=com"
  scope     = "onelevel"
}

# Subtree search - all descendants (default)
data "ad_groups" "all_descendants" {
  container = "dc=example,dc=com"
  scope     = "subtree"  # This is the default
}
```

### Dynamic Group Management

```terraform
# Find all groups in multiple OUs
variable "search_ous" {
  type = list(string)
  default = [
    "ou=IT,dc=example,dc=com",
    "ou=HR,dc=example,dc=com",
    "ou=Finance,dc=example,dc=com"
  ]
}

data "ad_groups" "department_groups" {
  for_each = toset(var.search_ous)

  container = each.value
  scope     = "onelevel"

  filter = {
    category = "Security"
  }
}

# Combine all results
locals {
  all_department_groups = flatten([
    for ou, groups_data in data.ad_groups.department_groups : groups_data.groups
  ])
}

output "all_departments_summary" {
  value = {
    total_groups = length(local.all_department_groups)
    groups_by_ou = {
      for ou, groups_data in data.ad_groups.department_groups :
      ou => length(groups_data.groups)
    }
  }
}
```

### Integration with Other Resources

```terraform
# Find service acgroup_count groups
data "ad_groups" "service_groups" {
  container = "ou=Service Acgroup_counts,dc=example,dc=com"

  filter = {
    name_suffix = "-Service"
    category    = "Security"
    has_members = true
  }
}

# Create corresponding admin groups
resource "ad_group" "service_admin_groups" {
  for_each = {
    for group in data.ad_groups.service_groups.groups :
    group.sam_acgroup_count_name => group
  }

  name             = replace(each.value.name, "-Service", "-Admin")
  sam_acgroup_count_name = replace(each.value.sam_acgroup_count_name, "Service", "Admin")
  container        = dirname(each.value.dn)
  scope            = each.value.scope
  category         = "Security"
  description      = "Administrators for ${each.value.display_name}"
}

# Add service groups as members of their admin groups
resource "ad_group_membership" "service_to_admin" {
  for_each = ad_group.service_admin_groups

  group_id = each.value.id
  members  = [data.ad_groups.service_groups.groups[index(data.ad_groups.service_groups.groups[*].sam_acgroup_count_name, replace(each.key, "Admin", "Service"))].dn]
}
```

### Reporting and Analysis

```terraform
# Comprehensive group analysis
data "ad_groups" "all_groups" {
  container = "dc=example,dc=com"
  scope     = "subtree"
}

# Generate detailed report
locals {
  group_analysis = {
    total_groups = data.ad_groups.all_groups.group_count

    by_category = {
      security     = length([for g in data.ad_groups.all_groups.groups : g if g.category == "Security"])
      distribution = length([for g in data.ad_groups.all_groups.groups : g if g.category == "Distribution"])
    }

    by_scope = {
      global       = length([for g in data.ad_groups.all_groups.groups : g if g.scope == "Global"])
      universal    = length([for g in data.ad_groups.all_groups.groups : g if g.scope == "Universal"])
      domainlocal  = length([for g in data.ad_groups.all_groups.groups : g if g.scope == "DomainLocal"])
    }

    empty_groups = length([for g in data.ad_groups.all_groups.groups : g if g.member_group_count == 0])
    large_groups = length([for g in data.ad_groups.all_groups.groups : g if g.member_group_count > 100])
  }
}

output "group_statistics" {
  value = local.group_analysis
}
```

## Available Filter Options

The `filter` block supports these search criteria:

### Name Pattern Filters
- `name_prefix`: Groups whose name starts with the specified string
- `name_suffix`: Groups whose name ends with the specified string
- `name_contains`: Groups whose name contains the specified string

### Group Type Filters
- `category`: Filter by group category (`Security` or `Distribution`)
- `scope`: Filter by group scope (`Global`, `Universal`, or `DomainLocal`)

### Membership Filters
- `has_members`: Boolean filter for groups with or without members
  - `true`: Only groups that have members
  - `false`: Only empty groups (no members)

## Search Scope Options

- `base`: Search only the specified container itself
- `onelevel`: Search direct children of the container only
- `subtree`: Search the container and all descendants (default)

## Available Attributes

Each group in the results includes these attributes:

### Identification
- `id`: ObjectGUID of the group
- `name`: Common name (cn) of the group
- `display_name`: Display name (same as name)
- `sam_acgroup_count_name`: SAM acgroup_count name
- `dn`: Full Distinguished Name
- `sid`: Security Identifier

### Classification
- `scope`: Group scope (Global, Universal, DomainLocal)
- `category`: Group category (Security, Distribution)
- `group_type`: Numeric Active Directory group type

### Details
- `description`: Group description if set
- `member_group_count`: Number of direct members

## Best Practices

### Efficient Searching
```terraform
# Use specific containers to limit search scope
data "ad_groups" "efficient_search" {
  container = "ou=Specific OU,dc=example,dc=com"  # Not the entire domain
  scope     = "onelevel"                          # Not subtree if unnecessary

  filter = {
    category = "Security"  # Be as specific as possible
  }
}
```

### Combining Multiple Filters
```terraform
# Stack multiple filter criteria for precise results
data "ad_groups" "precise_search" {
  container = "ou=Applications,dc=example,dc=com"

  filter = {
    name_prefix = "APP-"      # Application groups
    name_suffix = "-PROD"     # Production environment
    category    = "Security"  # Security groups only
    scope       = "Global"    # Global scope
    has_members = true        # Must have members
  }
}
```

### Handling Large Result Sets
```terraform
# For large domains, use specific searches
data "ad_groups" "manageable_search" {
  container = "ou=Department,dc=example,dc=com"
  scope     = "onelevel"

  filter = {
    category = "Security"
  }
}

# Process results in batches if needed
locals {
  first_batch = slice(data.ad_groups.manageable_search.groups, 0, min(50, data.ad_groups.manageable_search.group_count))
}
```

## Troubleshooting

### Common Issues

1. **No Results Found**
   ```
   # Check if container exists and filters are correct
   data "ad_groups" "debug_search" {
     container = "ou=NonExistent,dc=example,dc=com"
   }
   ```
   Verify the container DN is correct and accessible.

2. **Too Many Results**
   ```
   # Use more specific filters
   filter = {
     name_prefix = "SPECIFIC-"  # Instead of searching all groups
     category    = "Security"
   }
   ```

3. **Permission Issues**
   ```
   Error: Insufficient permissions to search container
   ```
   Ensure the service acgroup_count has read permissions for the specified container.

### Debug Configuration

```terraform
# Debug search with verbose output
data "ad_groups" "debug_groups" {
  container = "dc=example,dc=com"
  scope     = "onelevel"
}

output "debug_info" {
  value = {
    total_found    = data.ad_groups.debug_groups.group_count
    container_used = data.ad_groups.debug_groups.id
    sample_groups  = slice(data.ad_groups.debug_groups.groups, 0, min(5, data.ad_groups.debug_groups.group_count))
  }
}
```

### Performance Testing

```terraform
# Compare different search strategies
data "ad_groups" "broad_search" {
  container = "dc=example,dc=com"
  scope     = "subtree"
}

data "ad_groups" "narrow_search" {
  container = "ou=Specific,dc=example,dc=com"
  scope     = "onelevel"

  filter = {
    category = "Security"
  }
}

output "search_comparison" {
  value = {
    broad_group_count  = data.ad_groups.broad_search.group_count
    narrow_group_count = data.ad_groups.narrow_search.group_count
    # Narrow search is typically much faster
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `container` (String) The DN of the container to search within. If not specified, searches from the base DN. Example: `OU=Groups,DC=example,DC=com`
- `filter` (Block, Optional) Filter criteria for searching groups. All specified criteria must match (AND logic). (see [below for nested schema](#nestedblock--filter))
- `scope` (String) The search scope to use. Valid values: `base`, `onelevel`, `subtree`. Defaults to `subtree`.

### Read-Only

- `group_count` (Number) The total number of groups found matching the search criteria.
- `groups` (Attributes List) List of groups matching the search criteria. (see [below for nested schema](#nestedatt--groups))
- `id` (String) A computed identifier for this data source instance.

<a id="nestedblock--filter"></a>
### Nested Schema for `filter`

Optional:

- `category` (String) Filter by group category. Valid values: `security`, `distribution`.
- `has_members` (Boolean) Filter by membership status. `true` returns only groups with members, `false` returns only empty groups. If not specified, returns all groups.
- `name_contains` (String) Groups whose name contains this string. Case-insensitive.
- `name_prefix` (String) Groups whose name starts with this string. Case-insensitive.
- `name_suffix` (String) Groups whose name ends with this string. Case-insensitive.
- `scope` (String) Filter by group scope. Valid values: `global`, `domainlocal`, `universal`.


<a id="nestedatt--groups"></a>
### Nested Schema for `groups`

Read-Only:

- `category` (String) The category of the group (Security, Distribution).
- `description` (String) The description of the group.
- `display_name` (String) The display name of the group (equivalent to name).
- `dn` (String) The full Distinguished Name of the group.
- `group_type` (Number) The raw Active Directory groupType value.
- `id` (String) The objectGUID of the group.
- `member_count` (Number) The total number of members in the group.
- `name` (String) The common name (cn) of the group.
- `sam_account_name` (String) The SAM account name (pre-Windows 2000 name) of the group.
- `scope` (String) The scope of the group (Global, Universal, DomainLocal).
- `sid` (String) The Security Identifier (SID) of the group.
