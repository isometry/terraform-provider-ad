---
page_title: "Data Source ad_group"
description: |-
  Retrieves information about an Active Directory group. Supports multiple lookup methods: objectGUID, Distinguished Name, common name with container, or SAM account name.
---

# Data Source (ad_group)

Retrieves information about an Active Directory group. Supports multiple lookup methods: objectGUID, Distinguished Name, common name with container, or SAM account name.

This data source provides comprehensive information about Active Directory groups, including membership details, security attributes, and group properties. It supports multiple lookup methods for maximum flexibility in identifying groups.

## Key Features

- **Multiple Lookup Methods**: Find groups by GUID, Distinguished Name, common name, or SAM account name
- **Complete Group Information**: Retrieve all group attributes including scope, category, and type
- **Membership Details**: Get complete member lists and member counts
- **Flexible Identification**: Support for various identifier formats in your Terraform configurations
- **Security Attributes**: Access to SID and other security-related properties

## Lookup Methods

### By Object GUID (Recommended)
Most reliable method as GUIDs are immutable and unique:

```terraform
data "ad_group" "by_guid" {
  id = "550e8400-e29b-41d4-a716-446655440000"
}
```

### By Distinguished Name
Direct lookup using the full LDAP path:

```terraform
data "ad_group" "by_dn" {
  dn = "CN=Domain Admins,CN=Users,DC=example,DC=com"
}
```

### By Common Name with Container
Lookup by name within a specific container:

```terraform
data "ad_group" "by_name" {
  name      = "IT Security Team"
  container = "OU=Security Groups,DC=example,DC=com"
}
```

### By SAM Account Name
Lookup using the pre-Windows 2000 group name:

```terraform
data "ad_group" "by_sam" {
  sam_account_name = "ITSecurity"
}
```

## Example Usage

### Basic Group Information Retrieval

```terraform
# Get information about Domain Admins group
data "ad_group" "domain_admins" {
  name      = "Domain Admins"
  container = "CN=Users,DC=example,DC=com"
}

# Output group information
output "domain_admins_info" {
  value = {
    id                = data.ad_group.domain_admins.id
    dn = data.ad_group.domain_admins.dn
    sid               = data.ad_group.domain_admins.sid
    scope             = data.ad_group.domain_admins.scope
    category          = data.ad_group.domain_admins.category
    member_count      = data.ad_group.domain_admins.member_count
  }
}
```

### Using Group Information for Resource Creation

```terraform
# Find an existing group
data "ad_group" "existing_group" {
  sam_account_name = "ExistingGroup"
}

# Create a new group in the same container
resource "ad_group" "new_group" {
  name             = "New Related Group"
  sam_account_name = "NewRelatedGroup"
  container        = dirname(data.ad_group.existing_group.dn)
  scope            = data.ad_group.existing_group.scope
  category         = data.ad_group.existing_group.category
}

# Add the existing group as a member of the new group
resource "ad_group_membership" "nested_membership" {
  group_id = ad_group.new_group.id
  members  = [data.ad_group.existing_group.dn]
}
```

### Conditional Logic Based on Group Properties

```terraform
data "ad_group" "application_group" {
  name      = "Application Users"
  container = "OU=Applications,DC=example,DC=com"
}

# Create additional resources based on group properties
resource "ad_group" "admin_group" {
  count = data.ad_group.application_group.category == "Security" ? 1 : 0

  name             = "Application Administrators"
  sam_account_name = "AppAdmins"
  container        = dirname(data.ad_group.application_group.dn)
  scope            = data.ad_group.application_group.scope
  category         = "Security"
  description      = "Administrators for ${data.ad_group.application_group.display_name}"
}
```

### Group Membership Analysis

```terraform
data "ad_group" "large_group" {
  sam_account_name = "AllEmployees"
}

# Create a local value to check if group is large
locals {
  is_large_group = data.ad_group.large_group.member_count > 1000
}

# Output membership information
output "group_analysis" {
  value = {
    group_name    = data.ad_group.large_group.display_name
    member_count  = data.ad_group.large_group.member_count
    is_large      = local.is_large_group
    group_type    = data.ad_group.large_group.group_type
    security_id   = data.ad_group.large_group.sid
  }
}

# Show first 10 members for reference (if needed)
output "sample_members" {
  value = slice(tolist(data.ad_group.large_group.members), 0, min(10, data.ad_group.large_group.member_count))
}
```

### Multiple Groups Lookup Pattern

```terraform
# Define multiple groups to lookup
variable "group_names" {
  type = list(string)
  default = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins"
  ]
}

# Lookup all admin groups
data "ad_group" "admin_groups" {
  for_each = toset(var.group_names)

  name      = each.value
  container = "CN=Users,DC=example,DC=com"
}

# Create a summary of all admin groups
output "admin_groups_summary" {
  value = {
    for name, group in data.ad_group.admin_groups : name => {
      id           = group.id
      sid          = group.sid
      member_count = group.member_count
      scope        = group.scope
    }
  }
}
```

### Integration with Other Data Sources

```terraform
# Find a specific OU
data "ad_ou" "security_groups_ou" {
  name = "Security Groups"
  path = "DC=example,DC=com"
}

# Find groups within that OU
data "ad_groups" "security_groups" {
  container = data.ad_ou.security_groups_ou.dn
  category  = "Security"
}

# Get detailed information about each security group
data "ad_group" "detailed_security_groups" {
  for_each = toset(data.ad_groups.security_groups.groups[*].sam_account_name)

  sam_account_name = each.value
}

# Create a comprehensive security groups report
locals {
  security_groups_report = {
    for sam_name, group in data.ad_group.detailed_security_groups : sam_name => {
      display_name      = group.display_name
      dn = group.dn
      description       = group.description
      scope            = group.scope
      member_count     = group.member_count
      sid              = group.sid
    }
  }
}

output "security_groups_report" {
  value = local.security_groups_report
}
```

### Validation and Error Handling

```terraform
# Lookup a group that might not exist
data "ad_group" "optional_group" {
  sam_account_name = var.optional_group_name

  # This will fail if the group doesn't exist
  # Consider using try() function for optional resources
}

# Using try() for optional group lookup
locals {
  optional_group_exists = try(data.ad_group.optional_group.id, null) != null
}

# Conditional resource creation based on group existence
resource "ad_group_membership" "conditional_membership" {
  count = local.optional_group_exists ? 1 : 0

  group_id = data.ad_group.optional_group.id
  members  = ["user@example.com"]
}

output "group_status" {
  value = {
    group_exists = local.optional_group_exists
    group_id     = try(data.ad_group.optional_group.id, "not_found")
  }
}
```

## Available Attributes

All attributes are computed (read-only) and provide comprehensive group information:

### Identification Attributes
- `id`: ObjectGUID of the group
- `dn`: Full Distinguished Name
- `sid`: Security Identifier
- `display_name`: Display name (from cn attribute)
- `sam_account_name`: SAM account name

### Group Classification
- `scope`: Group scope (`Global`, `Universal`, or `DomainLocal`)
- `category`: Group category (`Security` or `Distribution`)
- `group_type`: Numeric Active Directory group type

### Membership Information
- `members`: Set of all member Distinguished Names
- `member_count`: Total number of members

### Description
- `description`: Group description if set

## Best Practices

### Efficient Lookups
```terraform
# Prefer GUID lookups when possible (most efficient)
data "ad_group" "efficient_lookup" {
  id = "550e8400-e29b-41d4-a716-446655440000"
}

# Use SAM account name for human-readable configurations
data "ad_group" "readable_lookup" {
  sam_account_name = "ITAdmins"
}

# Use DN when you know the exact path
data "ad_group" "precise_lookup" {
  dn = "CN=Web Admins,OU=IT Groups,DC=example,DC=com"
}
```

### Caching and Performance
```terraform
# For repeated access to the same group, use locals
data "ad_group" "frequently_used" {
  sam_account_name = "CommonGroup"
}

locals {
  common_group_dn = data.ad_group.frequently_used.dn
  common_group_scope = data.ad_group.frequently_used.scope
}

# Use the cached values in multiple places
resource "ad_group" "related_group_1" {
  name      = "Related Group 1"
  container = dirname(local.common_group_dn)
  scope     = local.common_group_scope
  # ... other attributes
}

resource "ad_group" "related_group_2" {
  name      = "Related Group 2"
  container = dirname(local.common_group_dn)
  scope     = local.common_group_scope
  # ... other attributes
}
```

### Error Handling Patterns
```terraform
# Pattern 1: Required group (will fail if not found)
data "ad_group" "required_group" {
  sam_account_name = "MustExist"
}

# Pattern 2: Optional group with try()
locals {
  optional_group_info = try({
    id = data.ad_group.optional_group.id
    dn = data.ad_group.optional_group.dn
  }, {
    id = null
    dn = null
  })
}

# Pattern 3: Validation with postcondition
data "ad_group" "validated_group" {
  sam_account_name = "ValidatedGroup"

  lifecycle {
    postcondition {
      condition     = self.category == "Security"
      error_message = "Group must be a Security group."
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **Group Not Found**
   ```
   Error: Group with sam_account_name 'NonExistent' not found
   ```
   Verify the group exists and the identifier is correct.

2. **Multiple Lookup Methods**
   ```
   Error: Only one lookup method can be specified
   ```
   Use only one of: `id`, `dn`, `name` (with `container`), or `sam_account_name`.

3. **Name Lookup Without Container**
   ```
   Error: Container is required when looking up by name
   ```
   Specify the `container` attribute when using `name` lookup.

4. **Permission Issues**
   ```
   Error: Insufficient permissions to read group
   ```
   Ensure the service account has read permissions for the group.

### Debug Examples

```terraform
# Debug group lookup
data "ad_group" "debug_group" {
  sam_account_name = "DebugGroup"
}

# Output all available information
output "debug_group_info" {
  value = {
    id                = data.ad_group.debug_group.id
    dn                = data.ad_group.debug_group.dn
    display_name      = data.ad_group.debug_group.display_name
    description       = data.ad_group.debug_group.description
    scope            = data.ad_group.debug_group.scope
    category         = data.ad_group.debug_group.category
    group_type       = data.ad_group.debug_group.group_type
    sid              = data.ad_group.debug_group.sid
    member_count     = data.ad_group.debug_group.member_count
    first_few_members = slice(tolist(data.ad_group.debug_group.members), 0, min(5, data.ad_group.debug_group.member_count))
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `container` (String) The container DN where the group is located. Required when using the `name` lookup method. Example: `CN=Users,DC=example,DC=com`
- `dn` (String) The Distinguished Name of the group to retrieve. Example: `CN=Domain Admins,CN=Users,DC=example,DC=com`
- `id` (String) The objectGUID of the group to retrieve. This is the most reliable lookup method as objectGUIDs are immutable and unique. Format: `550e8400-e29b-41d4-a716-446655440000`
- `name` (String) The common name (cn) of the group to retrieve. When using this lookup method, the `container` attribute must also be specified to avoid ambiguity. Example: `Domain Admins`
- `sam_account_name` (String) The SAM account name (pre-Windows 2000 name) of the group to retrieve. This performs a domain-wide search. Example: `Domain Admins`

### Read-Only

- `category` (String) The category of the group. Valid values: `Security`, `Distribution`.
- `description` (String) The description of the group.
- `display_name` (String) The display name of the group (equivalent to common name).
- `group_type` (Number) The raw Active Directory groupType value as an integer.
- `member_count` (Number) The total number of members in the group.
- `members` (Set of String) A set of Distinguished Names of all group members. Includes users, groups, and other objects.
- `scope` (String) The scope of the group. Valid values: `Global`, `Universal`, `DomainLocal`.
- `sid` (String) The Security Identifier (SID) of the group.
