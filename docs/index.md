---
page_title: "ad Provider"
description: |-
  The Active Directory provider enables management of Active Directory resources via LDAP/LDAPS. It supports SRV-based domain controller discovery, connection pooling, and multiple authentication methods.
---

# ad Provider

The Active Directory provider enables management of Active Directory resources via LDAP/LDAPS. It supports SRV-based domain controller discovery, connection pooling, and multiple authentication methods including password, Kerberos, and certificate-based authentication.

## Key Features

- **Multiple Authentication Methods**: Support for username/password, Kerberos (GSSAPI), and certificate-based authentication
- **Automatic Discovery**: SRV-based domain controller discovery or direct LDAP URL configuration
- **Connection Pooling**: Built-in connection pooling with configurable limits and timeouts
- **TLS Security**: Full TLS/LDAPS support with custom certificate validation
- **Flexible Identification**: Resources can be identified by DN, GUID, SID, UPN, or SAM account name
- **Comprehensive Management**: Full CRUD operations for groups, organizational units, and group memberships
- **Production Ready**: Enterprise-grade error handling, retry logic, and connection management

## Supported Resources

- **Groups** (`ad_group`): Create and manage security and distribution groups with full Active Directory attributes
- **Organizational Units** (`ad_ou`): Create and manage organizational units with protection settings
- **Group Memberships** (`ad_group_membership`): Manage group memberships with flexible member identification

## Supported Data Sources

- **Group Lookup** (`ad_group`): Retrieve single group information by various identifiers
- **Groups Search** (`ad_groups`): Search and filter multiple groups with advanced criteria
- **OU Lookup** (`ad_ou`): Retrieve organizational unit information
- **User Lookup** (`ad_user`): Retrieve user information and attributes
- **Users Search** (`ad_users`): Search and filter multiple users with advanced criteria

## Authentication Methods

### Username/Password Authentication

The most common authentication method using a username and password:

```terraform
provider "ad" {
  domain   = "example.com"          # Domain for SRV discovery
  username = "admin@example.com"    # UPN format
  password = "secure_password"      # Can use environment variable
}
```

### Kerberos Authentication

For environments using Kerberos/GSSAPI authentication:

```terraform
provider "ad" {
  domain          = "example.com"
  kerberos_realm  = "EXAMPLE.COM"
  kerberos_keytab = "/etc/krb5.keytab"
  kerberos_config = "/etc/krb5.conf"
}
```

### Certificate-Based Authentication

For mutual TLS authentication:

```terraform
provider "ad" {
  ldap_url             = "ldaps://dc1.example.com:636"
  tls_client_cert_file = "/path/to/client-cert.pem"
  tls_client_key_file  = "/path/to/client-key.pem"
  tls_ca_cert_file     = "/path/to/ca-cert.pem"
}
```

## Connection Methods

### SRV-Based Discovery (Recommended)

Automatically discover domain controllers using DNS SRV records:

```terraform
provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secure_password"
  
  # Optional: Override auto-discovered base DN
  base_dn = "dc=example,dc=com"
}
```

### Direct LDAP URL

Connect directly to specific domain controllers:

```terraform
provider "ad" {
  ldap_url = "ldaps://dc1.example.com:636"
  base_dn  = "dc=example,dc=com"
  username = "cn=admin,cn=users,dc=example,dc=com"
  password = "secure_password"
}
```

## Environment Variables

All provider configuration can be specified using environment variables:

| Configuration Attribute | Environment Variable | Description |
|-------------------------|---------------------|-------------|
| `domain` | `AD_DOMAIN` | Active Directory domain |
| `ldap_url` | `AD_LDAP_URL` | Direct LDAP/LDAPS URL |
| `base_dn` | `AD_BASE_DN` | Base DN for searches |
| `username` | `AD_USERNAME` | Authentication username |
| `password` | `AD_PASSWORD` | Authentication password |
| `kerberos_realm` | `AD_KERBEROS_REALM` | Kerberos realm |
| `kerberos_keytab` | `AD_KERBEROS_KEYTAB` | Path to Kerberos keytab |
| `kerberos_config` | `AD_KERBEROS_CONFIG` | Path to Kerberos config |
| `use_tls` | `AD_USE_TLS` | Force TLS usage |
| `skip_tls_verify` | `AD_SKIP_TLS_VERIFY` | Skip TLS verification |
| `tls_ca_cert_file` | `AD_TLS_CA_CERT_FILE` | CA certificate file |
| `tls_ca_cert` | `AD_TLS_CA_CERT` | CA certificate content |
| `tls_client_cert_file` | `AD_TLS_CLIENT_CERT_FILE` | Client certificate file |
| `tls_client_key_file` | `AD_TLS_CLIENT_KEY_FILE` | Client private key file |

## Example Usage

### Basic Configuration

```terraform
provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secure_password"
}

# Create a security group
resource "ad_group" "example" {
  name         = "TerraformGroup"
  sam_name     = "TerraformGroup"
  scope        = "global"
  category     = "security"
  description  = "Group created by Terraform"
  container    = "cn=users,dc=example,dc=com"
}

# Add members to the group
resource "ad_group_membership" "example" {
  group_id = ad_group.example.id
  members = [
    "user1@example.com",
    "user2@example.com",
    "cn=user3,cn=users,dc=example,dc=com"
  ]
}
```

### Environment Variable Configuration

```bash
export AD_DOMAIN=example.com
export AD_USERNAME=admin@example.com
export AD_PASSWORD=secure_password
```

```terraform
provider "ad" {
  # Configuration read from environment variables
}

data "ad_group" "existing" {
  name = "Existing Group"
}

data "ad_users" "department" {
  filter = "department=IT"
}
```

## Security Considerations

### TLS Configuration

Always use TLS in production environments:

```terraform
provider "ad" {
  domain          = "example.com"
  username        = "admin@example.com"
  password        = "secure_password"
  use_tls         = true
  skip_tls_verify = false  # Never skip in production
  
  # Use custom CA if needed
  tls_ca_cert_file = "/path/to/corporate-ca.pem"
}
```

### Authentication Security

- Use service accounts with minimal required permissions
- Rotate passwords regularly
- Prefer Kerberos authentication in domain environments
- Use environment variables for sensitive values
- Consider certificate-based authentication for service-to-service scenarios

### Connection Security

```terraform
provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secure_password"
  
  # Security settings
  use_tls         = true
  skip_tls_verify = false
  
  # Connection limits
  max_connections = 5    # Limit concurrent connections
  connect_timeout = 30   # Connection timeout in seconds
  
  # Retry settings for resilience
  max_retries     = 3
  initial_backoff = 500
  max_backoff     = 30
}
```

## Performance Optimization

### Connection Pooling

```terraform
provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secure_password"
  
  # Optimize for your workload
  max_connections = 10   # Increase for high concurrency
  max_idle_time   = 300  # Keep connections alive longer
  connect_timeout = 15   # Faster timeout for quick feedback
}
```

### Resource Planning

- Use data sources for lookups instead of hardcoding values
- Group related operations together
- Use `depends_on` to control resource creation order
- Leverage Terraform's parallel execution where possible

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify username format (DN, UPN, or SAM)
   - Check password or Kerberos configuration
   - Ensure service account has necessary permissions

2. **Connection Issues**
   - Verify domain controller accessibility
   - Check DNS resolution for SRV records
   - Validate TLS certificate configuration

3. **Permission Errors**
   - Ensure service account has required AD permissions
   - Check organizational unit permissions
   - Verify group management rights

### Debug Configuration

```terraform
provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secure_password"
  
  # Increase timeouts for debugging
  connect_timeout = 60
  max_retries     = 1
  
  # Disable TLS verification if needed for testing
  # skip_tls_verify = true  # Only for debugging!
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `base_dn` (String) Base DN for LDAP searches (e.g., `dc=example,dc=com`). If not specified, will be automatically discovered from the root DSE. Can be set via the `AD_BASE_DN` environment variable.
- `connect_timeout` (Number) Connection timeout in seconds. Defaults to `30`. Can be set via the `AD_CONNECT_TIMEOUT` environment variable.
- `domain` (String) Active Directory domain name for SRV-based discovery (e.g., `example.com`). Mutually exclusive with `ldap_url`. Can be set via the `AD_DOMAIN` environment variable.
- `initial_backoff` (Number) Initial backoff delay in milliseconds for retry attempts. Defaults to `500`. Can be set via the `AD_INITIAL_BACKOFF` environment variable.
- `kerberos_ccache` (String) Path to Kerberos credential cache file for authentication. When specified, existing Kerberos tickets will be used for authentication. Can be set via the `AD_KERBEROS_CCACHE` environment variable.
- `kerberos_config` (String) Path to Kerberos configuration file. Defaults to system default. Can be set via the `AD_KERBEROS_CONFIG` environment variable.
- `kerberos_keytab` (String) Path to Kerberos keytab file for authentication. Can be set via the `AD_KERBEROS_KEYTAB` environment variable.
- `kerberos_realm` (String) Kerberos realm for GSSAPI authentication (e.g., `EXAMPLE.COM`). Can be set via the `AD_KERBEROS_REALM` environment variable.
- `kerberos_spn` (String) Override Service Principal Name (SPN) for Kerberos authentication. Use when connecting to a domain controller by IP address where the SPN doesn't match the IP. Format: `ldap/<hostname>` (e.g., `ldap/dc1.example.com`). Can be set via the `AD_KERBEROS_SPN` environment variable.
- `ldap_url` (String) Direct LDAP/LDAPS URL (e.g., `ldaps://dc1.example.com:636`). Mutually exclusive with `domain`. Can be set via the `AD_LDAP_URL` environment variable.
- `max_backoff` (Number) Maximum backoff delay in seconds for retry attempts. Defaults to `30`. Can be set via the `AD_MAX_BACKOFF` environment variable.
- `max_connections` (Number) Maximum number of connections in the connection pool. Defaults to `10`. Can be set via the `AD_MAX_CONNECTIONS` environment variable.
- `max_idle_time` (Number) Maximum idle time for connections in seconds. Defaults to `300` (5 minutes). Can be set via the `AD_MAX_IDLE_TIME` environment variable.
- `max_retries` (Number) Maximum number of retry attempts for failed operations. Defaults to `3`. Can be set via the `AD_MAX_RETRIES` environment variable.
- `password` (String, Sensitive) Password for LDAP authentication. Can be set via the `AD_PASSWORD` environment variable.
- `skip_tls_verify` (Boolean) Skip TLS certificate verification. Not recommended for production. Defaults to `false`. Can be set via the `AD_SKIP_TLS_VERIFY` environment variable.
- `tls_ca_cert` (String, Sensitive) Custom CA certificate content for TLS verification. Can be set via the `AD_TLS_CA_CERT` environment variable.
- `tls_ca_cert_file` (String) Path to custom CA certificate file for TLS verification. Can be set via the `AD_TLS_CA_CERT_FILE` environment variable.
- `tls_client_cert_file` (String) Path to client certificate file for mutual TLS authentication. Can be set via the `AD_TLS_CLIENT_CERT_FILE` environment variable.
- `tls_client_key_file` (String, Sensitive) Path to client private key file for mutual TLS authentication. Can be set via the `AD_TLS_CLIENT_KEY_FILE` environment variable.
- `use_tls` (Boolean) Force TLS/LDAPS connection. Defaults to `true`. Can be set via the `AD_USE_TLS` environment variable.
- `username` (String) Username for LDAP authentication. Supports DN, UPN, or SAM account name formats. Can be set via the `AD_USERNAME` environment variable.
- `warm_cache` (Boolean) Pre-populate cache with all users and groups on provider initialization. Significantly improves performance for large group memberships. Defaults to `false`. Can be set via the `AD_WARM_CACHE` environment variable.