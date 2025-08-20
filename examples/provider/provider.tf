# Example configurations for the Active Directory provider

# Example 1: Domain-based configuration with SRV discovery
provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secret123"

  # Optional TLS settings
  use_tls         = true
  skip_tls_verify = false

  # Optional connection pool settings
  max_connections = 10
  connect_timeout = 30

  # Optional retry settings
  max_retries     = 3
  initial_backoff = 500
  max_backoff     = 30
}

# Example 2: Direct LDAP URL configuration
provider "ad" {
  ldap_url = "ldaps://dc1.example.com:636"
  base_dn  = "dc=example,dc=com"
  username = "cn=admin,cn=users,dc=example,dc=com"
  password = "secret123"
}

# Example 3: Kerberos authentication
provider "ad" {
  domain          = "example.com"
  kerberos_realm  = "EXAMPLE.COM"
  kerberos_keytab = "/etc/krb5.keytab"
  kerberos_config = "/etc/krb5.conf"
}

# Example 4: Environment variable configuration
# Set these environment variables instead of explicit configuration:
# export AD_DOMAIN=example.com
# export AD_USERNAME=admin@example.com
# export AD_PASSWORD=secret123
# export AD_USE_TLS=true
provider "ad" {
  # Configuration will be read from environment variables
}

# Example 5: Custom TLS configuration
provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secret123"

  # Custom CA certificate file
  tls_ca_cert_file = "/path/to/ca-cert.pem"

  # Or provide CA certificate content directly
  # tls_ca_cert = file("/path/to/ca-cert.pem")

  # Client certificate for mutual TLS
  tls_client_cert_file = "/path/to/client-cert.pem"
  tls_client_key_file  = "/path/to/client-key.pem"
}
