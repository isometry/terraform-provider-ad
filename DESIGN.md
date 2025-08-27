# terraform-provider-ad

## Overview

A modern Terraform provider for managing Active Directory resources via LDAP/LDAPS. This provider offers native LDAP connectivity with automatic domain controller discovery, comprehensive Kerberos authentication support, and efficient connection management.

## Architecture

This provider uses:
* **github.com/hashicorp/terraform-plugin-framework** - Modern Terraform plugin framework
* **github.com/hashicorp/terraform-plugin-docs** - Automatic documentation generation
* **github.com/go-ldap/v3/ldap** - Pure Go LDAP client
* **Modern Go 1.25+ idioms** - Latest language features and patterns
* **SRV-based domain controller discovery** - Automatic DC discovery via DNS SRV records
* **Full Kerberos authentication support** - Including keytab and password authentication

## Provider Configuration

### Connection Settings

```hcl
provider "ad" {
  # Primary connection method - domain name for SRV record discovery
  domain = "example.com"  # Uses _ldap._tcp.example.com SRV records

  # Alternative: Direct LDAP server specification
  # ldap_url = "ldaps://dc1.example.com:636"

  # Authentication
  username = "cn=terraform,ou=service accounts,dc=example,dc=com"
  password = var.ad_password

  # Optional Kerberos authentication
  # krb_realm      = "EXAMPLE.COM"
  # krb_config     = "/etc/krb5.conf"
  # krb_keytab     = "/etc/terraform.keytab"
  # krb_ccache     = "/tmp/krb5cc_terraform"

  # TLS Configuration
  tls_insecure_skip_verify = false
  tls_server_name         = "dc1.example.com"
  ca_cert_file           = "/etc/ssl/certs/ca-certificates.crt"

  # Connection settings
  bind_timeout       = "30s"
  search_timeout     = "60s"
  connection_timeout = "10s"
  max_connections    = 10
  max_idle_time      = "300s"

  # Search base DN (auto-discovered if not specified)
  base_dn = "dc=example,dc=com"
}
```

### Environment Variables

- `AD_DOMAIN` - Domain name for SRV discovery
- `AD_LDAP_URL` - Direct LDAP URL
- `AD_USERNAME` - Bind username
- `AD_PASSWORD` - Bind password
- `AD_KRB_REALM` - Kerberos realm
- `AD_KRB_CONFIG` - Kerberos config file path
- `AD_KRB_KEYTAB` - Kerberos keytab file path
- `AD_BASE_DN` - Base DN for searches
- `AD_TLS_INSECURE` - Skip TLS verification (development only)

## Resources

**Resource Identification**: All resources use the Active Directory `objectGUID` as their Terraform resource ID. This ensures reliable tracking even when objects are renamed or moved within the directory.

### Resource: ad_group

Manages Active Directory security and distribution groups with full support for group scope and nested memberships.

#### Schema

```hcl
resource "ad_group" "example" {
  # Required
  name             = "Engineers"                    # Group name
  sam_account_name = "engineers"                   # Pre-Windows 2000 name
  container        = "ou=groups,dc=example,dc=com" # Parent container DN

  # Optional
  description = "Engineering team group"
  scope       = "global"     # "global", "domainlocal", "universal"
  category    = "security"   # "security", "distribution"

  # Advanced options
  notes           = "Created by Terraform"
  managed_by      = "cn=admin,ou=users,dc=example,dc=com"
  mail            = "engineers@example.com"
  display_name    = "Engineering Team"

  # Computed (read-only)
  # id              = "550e8400-e29b-41d4-a716-446655440000" (objectGUID - Terraform resource ID)
  # dn              = "cn=Engineers,ou=groups,dc=example,dc=com"
  # guid            = "550e8400-e29b-41d4-a716-446655440000" (same as id)
  # sid             = "S-1-5-21-123456789-123456789-123456789-1001"
  # when_created    = "2023-01-01T00:00:00Z"
  # when_changed    = "2023-01-01T00:00:00Z"
}
```

#### LDAP Attribute Mapping

| Terraform Attribute | LDAP Attribute | Type | Description |
|---------------------|----------------|------|-------------|
| `name` | `cn` | string | Common name |
| `sam_account_name` | `sAMAccountName` | string | Pre-Windows 2000 name |
| `description` | `description` | string | Group description |
| `scope` | `groupType` | string | Group scope (mapped to AD constants) |
| `category` | `groupType` | string | Security vs distribution |
| `container` | `distinguishedName` | string | Parent container |
| `mail` | `mail` | string | Email address |
| `display_name` | `displayName` | string | Display name |
| `managed_by` | `managedBy` | string | Manager DN |
| `notes` | `info` | string | Notes field |

### Resource: ad_group_membership

Manages membership of an Active Directory group, supporting users, groups, and computer objects as members.

#### Schema

```hcl
resource "ad_group_membership" "engineers" {
  group_id = ad_group.engineers.id

  # Members can be specified by any identifier
  group_members = [
    "cn=john.doe,ou=users,dc=example,dc=com",        # Distinguished Name
    "john.doe@example.com",                          # User Principal Name
    "EXAMPLE\\jane.doe",                             # SAM Account Name with domain
    "550e8400-e29b-41d4-a716-446655440001",         # GUID
    "S-1-5-21-123456789-123456789-123456789-1002",  # SID
    ad_group.contractors.id,                         # Another group (nested)
  ]
}
```

#### Membership Normalization

**Key Behavior**: All member identifiers are internally normalized to Distinguished Names (DNs) before comparison and storage. This prevents drift detection when the same member is specified using different identifier types.

**How it works**:
1. **Input Flexibility**: You can specify members using DN, GUID, SID, UPN, or SAM Account Name
2. **Internal Normalization**: All identifiers are resolved to DNs during the plan phase
3. **Drift Prevention**: State comparison uses the normalized DNs, preventing spurious diffs
4. **Unordered Sets**: Member lists are treated as unordered sets - order changes don't trigger updates

**Example**: These configurations are equivalent and won't cause drift:
```hcl
# Configuration A
resource "ad_group_membership" "example" {
  group_id = ad_group.engineers.id
  group_members = [
    "john.doe@example.com",
    "EXAMPLE\\jane.doe"
  ]
}

# Configuration B (equivalent - no drift)
resource "ad_group_membership" "example" {
  group_id = ad_group.engineers.id
  group_members = [
    "cn=jane doe,ou=users,dc=example,dc=com",  # Different order
    "cn=john doe,ou=users,dc=example,dc=com"   # Different identifier type
  ]
}
```

### Resource: ad_ou

Manages Active Directory Organizational Units with full support for nested structures and delegation.

#### Schema

```hcl
resource "ad_ou" "engineering" {
  # Required
  name = "Engineering"
  path = "dc=example,dc=com"  # Parent container DN

  # Optional
  description = "Engineering department organizational unit"
  protected   = true          # Protect from accidental deletion
  managed_by  = "cn=eng-admin,ou=users,dc=example,dc=com"

  # Computed (read-only)
  # id           = "550e8400-e29b-41d4-a716-446655440000" (objectGUID - Terraform resource ID)
  # dn           = "ou=Engineering,dc=example,dc=com"
  # guid         = "550e8400-e29b-41d4-a716-446655440000" (same as id)
  # when_created = "2023-01-01T00:00:00Z"
  # when_changed = "2023-01-01T00:00:00Z"
}

# Nested OU example
resource "ad_ou" "engineering_teams" {
  name = "Teams"
  path = ad_ou.engineering.dn  # Use parent OU as path
  description = "Engineering teams"
}
```

## Data Sources

### Data Source: ad_group

Retrieves information about a single Active Directory group using specific identifiers.

#### Schema

```hcl
# Lookup by Distinguished Name
data "ad_group" "by_dn" {
  dn = "cn=Domain Admins,cn=Users,dc=example,dc=com"
}

# Lookup by objectGUID
data "ad_group" "by_guid" {
  guid = "550e8400-e29b-41d4-a716-446655440000"
}

# Lookup by SID
data "ad_group" "by_sid" {
  sid = "S-1-5-21-123456789-123456789-123456789-512"
}

# Output all available attributes
output "group_info" {
  value = {
    # Computed attributes (all read-only)
    id               = data.ad_group.by_dn.id               # objectGUID (resource ID)
    dn               = data.ad_group.by_dn.dn
    guid             = data.ad_group.by_dn.guid             # Same as id
    sid              = data.ad_group.by_dn.sid
    sam_account_name = data.ad_group.by_dn.sam_account_name
    display_name     = data.ad_group.by_dn.display_name
    description      = data.ad_group.by_dn.description
    scope            = data.ad_group.by_dn.scope            # "global", "domainlocal", "universal"
    category         = data.ad_group.by_dn.category         # "security", "distribution"
    mail             = data.ad_group.by_dn.mail
    managed_by       = data.ad_group.by_dn.managed_by
    members          = data.ad_group.by_dn.members          # List of member DNs
    member_of        = data.ad_group.by_dn.member_of        # List of parent group DNs
    when_created     = data.ad_group.by_dn.when_created
    when_changed     = data.ad_group.by_dn.when_changed
  }
}
```

#### Lookup Attributes (mutually exclusive)

Only one of these attributes should be specified:

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `dn` | string | Distinguished Name | `cn=Engineers,ou=Groups,dc=example,dc=com` |
| `guid` | string | objectGUID | `550e8400-e29b-41d4-a716-446655440000` |
| `sid` | string | Security Identifier | `S-1-5-21-123456789-123456789-123456789-1001` |

### Data Source: ad_search

Performs flexible LDAP searches to find multiple objects matching specified criteria. Returns an array of matching objects with basic identifying information.

#### Schema

```hcl
# Find all security groups in engineering OU
data "ad_search" "eng_security_groups" {
  search_base   = "ou=engineering,dc=example,dc=com"
  search_filter = "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))"
  search_scope  = "subtree"  # "base", "onelevel", "subtree"

  # Optional: limit returned attributes for performance
  attributes = ["cn", "distinguishedName", "objectGUID", "sAMAccountName"]
}

# Find all users with email addresses in a specific OU
data "ad_search" "users_with_email" {
  search_base   = "ou=users,dc=example,dc=com"
  search_filter = "(&(objectClass=user)(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
  search_scope  = "onelevel"
}

# Find all organizational units
data "ad_search" "all_ous" {
  search_base   = "dc=example,dc=com"
  search_filter = "(objectClass=organizationalUnit)"
  search_scope  = "subtree"
}

# Access search results
output "found_groups" {
  value = [
    for group in data.ad_search.eng_security_groups.results : {
      name = group.cn
      dn   = group.distinguishedName
      guid = group.objectGUID
      sam  = group.sAMAccountName
    }
  ]
}
```

#### Search Attributes

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `search_base` | string | Yes | Base DN to start the search from |
| `search_filter` | string | Yes | LDAP search filter (e.g., `(&(objectClass=user)(mail=*))`) |
| `search_scope` | string | No | Search scope: `base`, `onelevel`, or `subtree` (default: `subtree`) |
| `attributes` | list(string) | No | Specific attributes to retrieve (default: all available) |
| `size_limit` | number | No | Maximum number of entries to return (default: 1000) |

#### Output Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `results` | list(object) | Array of matching objects with requested attributes |
| `count` | number | Number of objects found |

Each object in `results` contains the requested attributes as key-value pairs. Common attributes include:
- `distinguishedName` - Object's DN
- `objectGUID` - Object's GUID
- `cn` - Common name
- `sAMAccountName` - SAM account name
- `objectClass` - Object class (user, group, organizationalUnit, etc.)

### Data Source: ad_ou

Retrieves information about a single Active Directory Organizational Unit using specific identifiers.

#### Schema

```hcl
# Lookup by Distinguished Name
data "ad_ou" "by_dn" {
  dn = "ou=Engineering,dc=example,dc=com"
}

# Lookup by objectGUID
data "ad_ou" "by_guid" {
  guid = "550e8400-e29b-41d4-a716-446655440000"
}

# Lookup by name and path (for convenience)
data "ad_ou" "by_name_path" {
  name = "Engineering"
  path = "dc=example,dc=com"
}

# Output all available attributes
output "ou_info" {
  value = {
    # Computed attributes (all read-only)
    id           = data.ad_ou.by_dn.id           # objectGUID (resource ID)
    dn           = data.ad_ou.by_dn.dn
    guid         = data.ad_ou.by_dn.guid         # Same as id
    name         = data.ad_ou.by_dn.name
    description  = data.ad_ou.by_dn.description
    protected    = data.ad_ou.by_dn.protected
    managed_by   = data.ad_ou.by_dn.managed_by
    when_created = data.ad_ou.by_dn.when_created
    when_changed = data.ad_ou.by_dn.when_changed
  }
}
```

#### Lookup Attributes (mutually exclusive)

Only one of these lookup methods should be specified:

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `dn` | string | Distinguished Name | `ou=Engineering,dc=example,dc=com` |
| `guid` | string | objectGUID | `550e8400-e29b-41d4-a716-446655440000` |
| `name` + `path` | string | Name and parent path | `name = "Engineering"`, `path = "dc=example,dc=com"` |

**Note**: When using `name` + `path`, both attributes must be specified together.

### Data Source: ad_user

Retrieves comprehensive information about a single Active Directory user using specific identifiers.

#### Schema

```hcl
# Lookup by Distinguished Name
data "ad_user" "by_dn" {
  dn = "cn=john doe,ou=users,dc=example,dc=com"
}

# Lookup by objectGUID
data "ad_user" "by_guid" {
  guid = "550e8400-e29b-41d4-a716-446655440000"
}

# Lookup by SID
data "ad_user" "by_sid" {
  sid = "S-1-5-21-123456789-123456789-123456789-1001"
}

# Lookup by User Principal Name
data "ad_user" "by_upn" {
  upn = "john.doe@example.com"
}

# Lookup by SAM Account Name
data "ad_user" "by_sam" {
  sam_account_name = "john.doe"
}

# Output all available user attributes
output "user_info" {
  value = {
    # Identity (computed - read-only)
    id                    = data.ad_user.by_dn.id                    # objectGUID (resource ID)
    dn                    = data.ad_user.by_dn.dn
    guid                  = data.ad_user.by_dn.guid                  # Same as id
    sid                   = data.ad_user.by_dn.sid
    sam_account_name      = data.ad_user.by_dn.sam_account_name
    upn   = data.ad_user.by_dn.upn

    # Personal Information
    display_name          = data.ad_user.by_dn.display_name
    given_name           = data.ad_user.by_dn.given_name
    surname              = data.ad_user.by_dn.surname
    initials             = data.ad_user.by_dn.initials
    description          = data.ad_user.by_dn.description

    # Contact Information
    email_address        = data.ad_user.by_dn.email_address
    home_phone           = data.ad_user.by_dn.home_phone
    mobile_phone         = data.ad_user.by_dn.mobile_phone
    office_phone         = data.ad_user.by_dn.office_phone
    fax                  = data.ad_user.by_dn.fax
    home_page            = data.ad_user.by_dn.home_page

    # Address Information
    street_address       = data.ad_user.by_dn.street_address
    city                 = data.ad_user.by_dn.city
    state                = data.ad_user.by_dn.state
    postal_code          = data.ad_user.by_dn.postal_code
    country              = data.ad_user.by_dn.country
    po_box               = data.ad_user.by_dn.po_box

    # Organizational Information
    title                = data.ad_user.by_dn.title
    department           = data.ad_user.by_dn.department
    company              = data.ad_user.by_dn.company
    manager              = data.ad_user.by_dn.manager
    employee_id          = data.ad_user.by_dn.employee_id
    employee_number      = data.ad_user.by_dn.employee_number
    office               = data.ad_user.by_dn.office
    division             = data.ad_user.by_dn.division
    organization         = data.ad_user.by_dn.organization

    # System Information
    home_directory       = data.ad_user.by_dn.home_directory
    home_drive           = data.ad_user.by_dn.home_drive
    profile_path         = data.ad_user.by_dn.profile_path
    logon_script         = data.ad_user.by_dn.logon_script

    # Security & Access
    account_enabled      = data.ad_user.by_dn.account_enabled
    password_never_expires = data.ad_user.by_dn.password_never_expires
    password_not_required = data.ad_user.by_dn.password_not_required
    change_password_at_logon = data.ad_user.by_dn.change_password_at_logon
    cannot_change_password = data.ad_user.by_dn.cannot_change_password
    smart_card_logon_required = data.ad_user.by_dn.smart_card_logon_required
    trusted_for_delegation = data.ad_user.by_dn.trusted_for_delegation
    account_locked_out   = data.ad_user.by_dn.account_locked_out

    # Group Memberships
    member_of            = data.ad_user.by_dn.member_of
    primary_group        = data.ad_user.by_dn.primary_group

    # Timestamps
    when_created         = data.ad_user.by_dn.when_created
    when_changed         = data.ad_user.by_dn.when_changed
    last_logon           = data.ad_user.by_dn.last_logon
    password_last_set    = data.ad_user.by_dn.password_last_set
    account_expires      = data.ad_user.by_dn.account_expires
  }
}
```

#### Lookup Attributes (mutually exclusive)

Only one of these attributes should be specified:

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `dn` | string | Distinguished Name | `cn=john doe,ou=users,dc=example,dc=com` |
| `guid` | string | objectGUID | `550e8400-e29b-41d4-a716-446655440000` |
| `sid` | string | Security Identifier | `S-1-5-21-123456789-123456789-123456789-1001` |
| `upn` | string | User Principal Name | `john.doe@example.com` |
| `sam_account_name` | string | SAM Account Name | `john.doe` |

## LDAP-Specific Features

### Automatic Domain Controller Discovery

The provider supports automatic discovery of domain controllers using DNS SRV records:

1. Query `_ldap._tcp.<domain>` for LDAP servers
2. Query `_ldaps._tcp.<domain>` for LDAPS servers (preferred)
3. Query `_gc._tcp.<domain>` for Global Catalog servers
4. Sort by priority and weight according to SRV record standards
5. Attempt connections in order with automatic failover

### Search Capabilities

#### Flexible Object Identification

All resources and data sources support multiple identification methods:
- **Distinguished Name (DN)**: `cn=Engineers,ou=groups,dc=example,dc=com`
- **GUID**: `550e8400-e29b-41d4-a716-446655440000`
- **SID**: `S-1-5-21-123456789-123456789-123456789-1001`
- **SAM Account Name**: `engineers` or `DOMAIN\engineers`
- **User Principal Name**: `user@domain.com` (users only)

#### Advanced Search Examples

```hcl
# Find all security groups in engineering OU using ad_search
data "ad_search" "eng_security_groups" {
  search_base   = "ou=engineering,dc=example,dc=com"
  search_filter = "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))"
  search_scope  = "subtree"
}

# Find all users with email addresses using ad_search
data "ad_search" "users_with_email" {
  search_base   = "dc=example,dc=com"
  search_filter = "(&(objectClass=user)(mail=*))"
  attributes    = ["mail", "displayName", "department"]
}

# Then look up specific users found from search
data "ad_user" "specific_user" {
  dn = data.ad_search.users_with_email.results[0].distinguishedName
}
```

### Connection Management

#### Connection Pooling

The provider maintains a pool of LDAP connections for efficient resource usage:
- Configurable maximum connections (`max_connections`)
- Automatic connection reuse and recycling
- Idle connection timeout (`max_idle_time`)
- Connection health checks

#### Error Handling and Retry Logic

- Automatic retry on transient failures
- Exponential backoff with jitter
- Circuit breaker pattern for failing servers
- Graceful failover between domain controllers

### Security Features

#### TLS/SSL Configuration

```hcl
provider "ad" {
  domain = "example.com"

  # TLS configuration
  tls_insecure_skip_verify = false
  tls_server_name         = "dc1.example.com"
  tls_min_version         = "1.2"
  tls_max_version         = "1.3"
  ca_cert_file           = "/etc/ssl/certs/ca-bundle.crt"
  client_cert_file       = "/etc/ssl/client.crt"
  client_key_file        = "/etc/ssl/client.key"
}
```

#### Kerberos Authentication

```hcl
provider "ad" {
  domain = "example.com"

  # Kerberos with keytab
  krb_realm  = "EXAMPLE.COM"
  krb_keytab = "/etc/terraform.keytab"
  username   = "terraform"

  # Alternative: Kerberos with password
  # username   = "terraform@EXAMPLE.COM"
  # password   = var.ad_password
  # krb_config = "/etc/krb5.conf"
}
```

## Performance Considerations

### Efficient Queries

- Use specific search bases to limit scope
- Employ indexed attributes in search filters
- Request only needed attributes
- Use paging for large result sets

### Bulk Operations

```hcl
# Find all engineers using search
data "ad_search" "all_engineers" {
  search_base   = "ou=engineering,dc=example,dc=com"
  search_filter = "(objectClass=user)"
  search_scope  = "subtree"
  attributes    = ["distinguishedName"]
}

# Efficient group membership management
resource "ad_group_membership" "engineering" {
  group_id = ad_group.engineering.id

  # Bulk member addition using search results
  group_members = [
    for user in data.ad_search.all_engineers.results : user.distinguishedName
  ]
}
```

### Caching and State Management

- Efficient state refresh with change detection
- Minimal LDAP queries during plan phase
- Intelligent attribute caching
- Delta-based updates for group memberships

## Examples

### Complete Organization Setup

```hcl
terraform {
  required_providers {
    ad = {
      source  = "isometry/ad"
      version = "~> 1.0"
    }
  }
}

provider "ad" {
  domain   = "example.com"
  username = var.ad_username
  password = var.ad_password
}

# Create organizational structure
resource "ad_ou" "departments" {
  name        = "Departments"
  path        = "dc=example,dc=com"
  description = "Departmental organizational units"
  protected   = true
}

resource "ad_ou" "engineering" {
  name        = "Engineering"
  path        = ad_ou.departments.dn
  description = "Engineering department"
  city        = "San Francisco"
  state       = "CA"
}

resource "ad_ou" "groups" {
  name        = "Groups"
  path        = "dc=example,dc=com"
  description = "Security and distribution groups"
  protected   = true
}

# Create groups
resource "ad_group" "engineers" {
  name             = "Engineers"
  sam_account_name = "engineers"
  container        = ad_ou.groups.dn
  description      = "Engineering team members"
  scope            = "global"
  category         = "security"
  mail             = "engineers@example.com"
}

resource "ad_group" "senior_engineers" {
  name             = "Senior Engineers"
  sam_account_name = "senior-engineers"
  container        = ad_ou.groups.dn
  description      = "Senior engineering team members"
  scope            = "global"
  category         = "security"
  mail             = "senior-engineers@example.com"
}

# Nested group membership
resource "ad_group_membership" "senior_in_engineers" {
  group_id      = ad_group.engineers.id
  group_members = [ad_group.senior_engineers.id]
}

# Find existing users in engineering OU using search
data "ad_search" "engineering_users" {
  search_base   = ad_ou.engineering.dn
  search_filter = "(objectClass=user)"
  search_scope  = "subtree"
  attributes    = ["distinguishedName"]
}

# Add found users to engineering group
resource "ad_group_membership" "all_engineers" {
  group_id = ad_group.engineers.id
  group_members = [
    for user in data.ad_search.engineering_users.results : user.distinguishedName
  ]
}
```

### Multi-Domain Environment

```hcl
# Primary domain
provider "ad" {
  alias    = "primary"
  domain   = "corp.example.com"
  username = var.primary_ad_username
  password = var.primary_ad_password
}

# Child domain
provider "ad" {
  alias    = "child"
  domain   = "dev.corp.example.com"
  username = var.child_ad_username
  password = var.child_ad_password
}

# Create group in primary domain
resource "ad_group" "global_admins" {
  provider         = ad.primary
  name             = "Global Administrators"
  sam_account_name = "global-admins"
  container        = "cn=users,dc=corp,dc=example,dc=com"
  scope            = "universal"
  category         = "security"
}

# Find admin users from child domain
data "ad_search" "dev_admin_search" {
  provider      = ad.child
  search_base   = "dc=dev,dc=corp,dc=example,dc=com"
  search_filter = "(&(objectClass=user)(memberOf=cn=Administrators,cn=builtin,dc=dev,dc=corp,dc=example,dc=com))"
  attributes    = ["distinguishedName", "sAMAccountName"]
}

# Add child domain admins to parent domain global group
resource "ad_group_membership" "global_admin_membership" {
  provider  = ad.primary
  group_id  = ad_group.global_admins.id
  group_members = [
    for admin in data.ad_search.dev_admin_search.results : admin.distinguishedName
  ]
}
```
