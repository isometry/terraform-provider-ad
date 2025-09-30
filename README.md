# Terraform Provider for Active Directory

A modern Terraform provider for managing Active Directory resources via LDAP/LDAPS with native connectivity, automatic domain controller discovery, and comprehensive Kerberos authentication support.

## Features

- 🔐 **Multiple Authentication Methods**: Password, Kerberos (keytab/ccache/password)
- 🌐 **Automatic DC Discovery**: DNS SRV record-based domain controller discovery
- 🔄 **Connection Pooling**: Efficient connection management with health checks and failover
- 🎯 **Flexible Resource Identification**: Support for DN, GUID, SID, UPN, and SAM account names
- ⚡ **Performance Optimized**: Connection pooling, retry logic, and optional cache warming
- 📦 **Terraform Plugin Framework**: Built with modern terraform-plugin-framework (v1.15.1)

## Resources

- `ad_group` - Security and distribution groups with scope management
- `ad_ou` - Organizational Units with nesting and protection
- `ad_group_membership` - Group membership with flexible member identification

## Data Sources

- `ad_group` / `ad_groups` - Query groups by DN, GUID, SID, or other attributes
- `ad_ou` - Query organizational units
- `ad_user` / `ad_users` - Query user information
- `ad_whoami` - Current authentication identity

## Provider Functions (Terraform 1.8+)

- `provider::ad::build_hierarchy` - Build DN hierarchy from list
- `provider::ad::normalize_roles` - Normalize role identifiers

## Quick Start

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
  domain   = "example.com"  # Automatic DC discovery via SRV records
  username = "terraform@example.com"
  password = var.ad_password
}

resource "ad_group" "engineers" {
  name             = "Engineers"
  sam_account_name = "engineers"
  container        = "ou=groups,dc=example,dc=com"
  scope            = "global"
  category         = "security"
}
```

## Documentation

Full documentation is available in the [docs/](./docs/) directory and on the [Terraform Registry](https://registry.terraform.io/providers/isometry/ad/latest/docs).

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.25 (for development)

## Developing the Provider

If you wish to work on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (see [Requirements](#requirements) above).

### Building

```shell
make install          # Build and install to $GOPATH/bin
make build            # Build without installing
```

### Testing

```shell
make test             # Run unit tests
make testacc          # Run acceptance tests (requires TF_ACC=1)
```

For acceptance tests, configure the provider with environment variables:

```shell
export TF_ACC=1
export AD_DOMAIN=example.com
export AD_USERNAME=terraform
export AD_PASSWORD=secret
make testacc
```

### Code Quality

```shell
make fmt              # Format code with gofmt
make lint             # Run golangci-lint
make generate         # Generate documentation
make                  # Run all checks: fmt, lint, install, generate
```

### Documentation

To generate or update documentation:

```shell
make generate
```

Documentation is automatically generated from schema descriptions and examples using [terraform-plugin-docs](https://github.com/hashicorp/terraform-plugin-docs).

## Architecture

- **Framework**: terraform-plugin-framework v1.15.1 (NOT SDK v2)
- **LDAP Library**: github.com/go-ldap/ldap/v3 v3.4.11
- **Kerberos Support**: github.com/jcmturner/gokrb5/v8 v8.4.4
- **Protocol**: Terraform protocol version 6.0

See [CLAUDE.md](./CLAUDE.md) for comprehensive developer documentation and [DESIGN.md](./DESIGN.md) for architecture details.

## License

See [LICENSE](./LICENSE) file for details.
