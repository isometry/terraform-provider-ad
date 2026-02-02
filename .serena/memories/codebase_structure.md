# Codebase Structure

## Directory Layout

```
terraform-provider-ad/
├── internal/
│   ├── ldap/              # LDAP client and Active Directory logic
│   │   ├── client.go      # Main LDAP client with connection pooling
│   │   ├── pool.go        # Connection pool implementation
│   │   ├── password.go    # Password generation and encoding
│   │   ├── dn_escape.go   # DN escaping utilities
│   │   ├── discovery.go   # SRV record domain controller discovery
│   │   ├── kerberos*.go   # Kerberos authentication
│   │   ├── guid.go        # GUID encoding/decoding
│   │   ├── sid.go         # SID handling
│   │   ├── normalizer.go  # Member identifier normalization
│   │   ├── dn_normalizer.go  # DN normalization
│   │   ├── group.go       # Group operations
│   │   ├── user.go        # User operations
│   │   ├── ou.go          # Organizational Unit operations
│   │   ├── membership.go  # Group membership management
│   │   ├── cache_manager.go  # Cache warming
│   │   ├── provider_data.go  # Provider data wrapper
│   │   ├── types.go       # LDAP type definitions
│   │   └── *_test.go      # Unit tests
│   │
│   ├── provider/          # Terraform provider implementation
│   │   ├── provider.go    # Provider schema and Configure()
│   │   ├── resource_group.go      # ad_group resource
│   │   ├── resource_ou.go         # ad_ou resource
│   │   ├── resource_user.go       # ad_user resource
│   │   ├── resource_group_membership.go  # ad_group_membership resource
│   │   ├── data_source_*.go  # Data source implementations
│   │   ├── function_*.go  # Provider function implementations
│   │   ├── types/         # Custom Terraform types
│   │   │   ├── dn_string.go
│   │   │   └── dn_string_set.go
│   │   ├── validators/    # Custom validators
│   │   │   └── dn_validator.go
│   │   ├── planmodifiers/ # Custom plan modifiers
│   │   │   └── use_name_for_sam.go
│   │   ├── helpers/       # Helper utilities
│   │   │   └── terraform_conversions.go
│   │   └── *_test.go      # Tests
│   │
│   └── utils/
│       └── logging.go     # Logging utilities
│
├── tools/
│   └── tools.go           # Tool dependencies (tfplugindocs)
│
├── docs/                  # Generated documentation
├── examples/              # Example configurations
├── templates/             # Documentation templates
├── .github/               # GitHub workflows
├── main.go                # Provider entry point
├── GNUmakefile            # Build automation
├── .golangci.yml          # Linting configuration
├── go.mod                 # Go dependencies
├── CLAUDE.md              # Developer guidance
├── DESIGN.md              # Architecture documentation
└── TESTING.md             # Testing strategy

## Key Files

- **main.go**: Provider entry point, minimal boilerplate
- **GNUmakefile**: Build, test, lint, format, generate targets
- **.golangci.yml**: Linting rules and exclusions
- **go.mod**: Go 1.25.0, terraform-plugin-framework v1.15.1
- **CLAUDE.md**: Comprehensive developer documentation
- **DESIGN.md**: Architecture and design decisions
- **TESTING.md**: Testing patterns and strategies

## Package Boundaries

**internal/ldap**: Pure LDAP/AD logic, no Terraform framework dependencies
**internal/provider**: Terraform framework code, uses internal/ldap as interface
**internal/utils**: Shared utilities across packages