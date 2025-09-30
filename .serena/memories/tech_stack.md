# Tech Stack

## Core Dependencies
- **Go**: 1.25.0
- **Terraform Plugin Framework**: v1.15.1 (github.com/hashicorp/terraform-plugin-framework)
- **Terraform Plugin Docs**: v0.22.0 (github.com/hashicorp/terraform-plugin-docs)
- **LDAP Library**: github.com/go-ldap/ldap/v3 v3.4.11
- **Kerberos Library**: github.com/jcmturner/gokrb5/v8 v8.4.4

## Key Libraries
- **SID Handling**: github.com/bwmarrin/go-objectsid
- **Defaults**: github.com/creasty/defaults
- **UUID**: github.com/google/uuid
- **Testing**: github.com/hashicorp/terraform-plugin-testing v1.13.3
- **Testing Assertions**: github.com/stretchr/testify

## Development Tools
- **Linter**: golangci-lint (configured in .golangci.yml)
- **Formatter**: gofmt
- **Documentation Generator**: terraform-plugin-docs (tfplugindocs)

## Protocol & Standards
- **Terraform Protocol**: Version 6.0
- **LDAP**: Full LDAP v3 support with LDAPS (TLS/SSL)
- **Kerberos**: GSSAPI/Kerberos authentication
- **DNS**: SRV record based service discovery