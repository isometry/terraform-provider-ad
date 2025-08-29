# Active Directory Provider Configuration Examples

# Example 1: Basic SRV-based discovery with username/password
provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secure_password"
}

# Example 2: Direct LDAP URL with environment variables
provider "ad" {
  ldap_url = "ldaps://dc1.example.com:636"
  base_dn  = "dc=example,dc=com"
  username = "cn=terraform,cn=users,dc=example,dc=com"
  password = "secure_password"

  # TLS configuration
  use_tls          = true
  skip_tls_verify  = false
  tls_ca_cert_file = "/etc/ssl/certs/corporate-ca.pem"
}

# Example 3: Kerberos authentication
provider "ad" {
  domain          = "example.com"
  kerberos_realm  = "EXAMPLE.COM"
  kerberos_keytab = "/etc/krb5.keytab"
  kerberos_config = "/etc/krb5.conf"
}

# Example 4: Certificate-based authentication
provider "ad" {
  ldap_url             = "ldaps://dc1.example.com:636"
  base_dn              = "dc=example,dc=com"
  tls_client_cert_file = "/path/to/client-cert.pem"
  tls_client_key_file  = "/path/to/client-key.pem"
  tls_ca_cert_file     = "/path/to/ca-cert.pem"
}

# Example 5: Production configuration with connection pooling
provider "ad" {
  domain   = "example.com"
  username = "svc-terraform@example.com"
  password = "secure_service_password"

  # Connection pooling settings
  max_connections = 10
  max_idle_time   = 300
  connect_timeout = 30

  # Retry configuration
  max_retries     = 3
  initial_backoff = 500
  max_backoff     = 30

  # Security settings
  use_tls         = true
  skip_tls_verify = false
}

# Example 6: Performance optimization with cache warming (for large deployments)
provider "ad" {
  domain     = "example.com"
  username   = "admin@example.com"
  password   = "secure_password"
  warm_cache = true # Pre-populate cache with all users and groups
}

# Example 7: Environment variable configuration (recommended for CI/CD)
# Set these environment variables:
# export AD_DOMAIN=example.com
# export AD_USERNAME=admin@example.com  
# export AD_PASSWORD=secure_password
# export AD_USE_TLS=true
# export AD_WARM_CACHE=true  # Enable cache warming via environment
provider "ad" {
  # Configuration read from environment variables
}