# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Essential Commands

### Development Workflow

```bash
# Build and install the provider
make install          # Builds and installs to $GOPATH/bin

# Run linting
make lint             # Uses golangci-lint with .golangci.yml config
make fmt              # Format Go code with gofmt

# Generate documentation
make generate         # Runs tfplugindocs from tools/ directory

# Testing
make test             # Unit tests with coverage (-cover -timeout=120s -parallel=10)
make testacc          # Acceptance tests (requires TF_ACC=1, timeout 120m)

# Default target
make                  # Runs fmt, lint, install, generate
```

### Single Test Execution

```bash
# Run specific unit test
go test -v ./internal/ldap -run TestGUIDParsing
go test -v ./internal/provider -run TestGroupResource

# Run specific acceptance test
TF_ACC=1 go test -v ./internal/provider -run TestAccGroupResource_basic

# Run tests with coverage output
go test -v -cover -coverprofile=coverage.out ./internal/...
```

## Architecture Overview

### Provider Structure

This is a **Terraform Plugin Framework** provider (not SDK v2) with these key characteristics:

- **Registry Address**: `registry.terraform.io/isometry/ad`
- **Provider Type Name**: `ad` (provider.go:86)
- **Framework Version**: terraform-plugin-framework v1.15.1
- **Go Version**: 1.25.0
- **Protocol**: Terraform protocol version 6.0
- **LDAP Library**: github.com/go-ldap/ldap/v3 v3.4.11
- **Kerberos Support**: github.com/jcmturner/gokrb5/v8 v8.4.4

### Project Structure

```
internal/
├── ldap/                   # LDAP client and Active Directory logic (33 files)
│   ├── client.go           # Main LDAP client with connection pooling
│   ├── pool.go             # Connection pool implementation
│   ├── discovery.go        # SRV record domain controller discovery
│   ├── kerberos.go         # Kerberos authentication implementation
│   ├── kerberos_discovery.go  # Kerberos realm auto-discovery
│   ├── guid.go             # GUID encoding/decoding for LDAP
│   ├── sid.go              # SID handling and conversion
│   ├── normalizer.go       # Member identifier normalization
│   ├── dn_normalizer.go    # DN normalization utilities
│   ├── group.go            # Group operations
│   ├── user.go             # User operations
│   ├── ou.go               # Organizational Unit operations
│   ├── membership.go       # Group membership management
│   ├── cache_manager.go    # Cache warming and management
│   ├── provider_data.go    # Provider data wrapper
│   ├── types.go            # LDAP type definitions
│   ├── errors.go           # Custom error types
│   ├── doc.go              # Package documentation
│   └── *_test.go           # Comprehensive unit tests (15 test files)
│
├── provider/               # Terraform provider implementation (27 files)
│   ├── provider.go         # Provider schema and Configure()
│   ├── resource_group.go   # ad_group resource
│   ├── resource_ou.go      # ad_ou resource
│   ├── resource_group_membership.go  # ad_group_membership resource
│   ├── data_source_group.go          # ad_group data source
│   ├── data_source_groups.go         # ad_groups data source
│   ├── data_source_ou.go             # ad_ou data source
│   ├── data_source_user.go           # ad_user data source
│   ├── data_source_users.go          # ad_users data source
│   ├── data_source_whoami.go         # ad_whoami data source
│   ├── function_build_hierarchy.go   # build_hierarchy function
│   ├── function_normalize_roles.go   # normalize_roles function
│   ├── types/              # Custom Terraform types
│   │   ├── dn_string.go    # DN-validated string type
│   │   └── dn_string_set.go # Set of DN strings
│   ├── validators/         # Custom validators
│   │   └── dn_validator.go # DN format validation
│   ├── planmodifiers/      # Custom plan modifiers
│   │   └── use_name_for_sam.go # Auto-generate sAMAccountName
│   ├── helpers/            # Helper utilities
│   │   └── terraform_conversions.go
│   └── *_test.go           # Tests (unit and acceptance, 13 test files)
│
└── utils/
    └── logging.go          # Logging utilities
```

### LDAP Integration Architecture

**Connection Management**:
- **SRV Discovery**: Automatic domain controller discovery via `_ldap._tcp.<domain>` DNS SRV records
- **Connection Pooling**: Configurable connection pool (default: 10 connections, 5 min idle timeout)
- **Health Checks**: Automatic connection validation and failover
- **Retry Logic**: Exponential backoff retry mechanism (default: 3 retries, 500ms-30s backoff)

**Authentication**:
- **Password Auth**: Standard LDAP bind with DN, UPN, or SAM account name formats
- **Kerberos Auth**: Full Kerberos/GSSAPI support with multiple methods:
  - Keytab file authentication
  - Credential cache (ccache) authentication
  - Password-based Kerberos authentication
  - DNS-based KDC auto-discovery when krb5.conf not present
  - Custom SPN override support for IP-based connections

**Resource Identification**:
- All resources use `objectGUID` as Terraform resource ID for reliable tracking
- GUIDs stored as binary in LDAP, converted to string format for Terraform
- Prevents ID conflicts when objects are renamed or moved

**Member Normalization**:
- Group memberships accept flexible identifier formats: DN, GUID, SID, UPN, SAM account name
- All identifiers normalized to DNs internally to prevent drift
- Cache warming available for improved performance with large group memberships

### Resource Implementation Patterns

Each resource follows these patterns:

1. **Schema Definition**: terraform-plugin-framework schema with validators and plan modifiers
2. **CRUD Operations**: Full Create, Read, Update, Delete with error handling and logging
3. **State Management**: objectGUID as resource ID, computed DN attribute
4. **LDAP Operations**: Direct LDAP client calls in internal/ldap package
5. **Testing**: Both unit tests (mock LDAP) and acceptance tests (real AD)

### Implemented Resources

**Resources**:
- `ad_group` - Security/distribution groups with scope (global/domainlocal/universal) and category
- `ad_ou` - Organizational Units with protection and nesting support
- `ad_group_membership` - Group membership management with flexible member identification

**Data Sources**:
- `ad_group` / `ad_groups` - Query groups by various attributes
- `ad_ou` - Query organizational units
- `ad_user` / `ad_users` - Query user information
- `ad_whoami` - Current authentication identity

**Provider Functions** (Terraform 1.8+):
- `provider::ad::build_hierarchy` - Build DN hierarchy from list
- `provider::ad::normalize_roles` - Normalize role identifiers

### Documentation Generation

- **Tool**: `terraform-plugin-docs` imported in tools/tools.go
- **Command**: `make generate` runs tfplugindocs
- **Templates**: Located in templates/ directory
- **Output**: Generated docs go to docs/ directory
- **Integration**: Automatically generates from schema descriptions and examples/

### Testing Strategy

**Unit Tests**:
- Located alongside implementation files (*_test.go)
- Mock LDAP connections using test doubles
- Fast feedback for logic testing
- Run with: `make test` or `go test ./...`

**Acceptance Tests**:
- Prefix: `TestAcc*` (e.g., TestAccGroupResource_basic)
- Require real Active Directory connection
- Environment: `TF_ACC=1` enables acceptance tests
- Run with: `make testacc` or `TF_ACC=1 go test ./...`
- Configure via environment variables (AD_DOMAIN, AD_USERNAME, etc.)

**Test Configuration**:
- Coverage enabled by default in Makefile
- Parallel execution: 10 concurrent tests
- Timeouts: 120s for unit tests, 120m for acceptance tests

## Active Directory Specific Patterns

### LDAP Attribute Mapping

Common LDAP ↔ Terraform mappings used throughout resources:

- `objectGUID` → Terraform resource ID (all resources) - binary GUID converted to string
- `distinguishedName` → `dn` attribute (computed)
- `sAMAccountName` → `sam_account_name` (Pre-Windows 2000 name)
- `displayName` → `display_name`
- `description` → `description`
- `objectSid` → `sid` (computed) - binary SID converted to string format
- `groupType` → combines `scope` and `category` attributes (groups)
- `managedBy` → `managed_by` (DN of manager)

### Provider Configuration

**Connection Methods** (mutually exclusive):
- `domain = "example.com"` - Uses SRV records for DC discovery
- `ldap_url = "ldaps://dc.example.com:636"` - Direct LDAP server connection

**Authentication Methods**:
1. **Password**: `username` + `password`
2. **Kerberos Keytab**: `username` + `kerberos_realm` + `kerberos_keytab`
3. **Kerberos CCache**: `kerberos_realm` + `kerberos_ccache`
4. **Kerberos Password**: `username` + `password` + `kerberos_realm`

**Username Formats** (all supported):
- DN: `cn=terraform,ou=service accounts,dc=example,dc=com`
- UPN: `terraform@example.com`
- SAM: `DOMAIN\terraform`

**Environment Variables**:
All provider configuration can be set via `AD_*` environment variables (see provider.go schema)

### Cache Warming

Performance optimization for large environments:

```hcl
provider "ad" {
  domain     = "example.com"
  warm_cache = true  # Pre-loads all users/groups on initialization
}
```

- Significantly improves performance for large group memberships
- Caches DN → GUID/SID mappings for member normalization
- Optional, defaults to false
- Set via `AD_WARM_CACHE=true` environment variable

### Logging

Structured logging with multiple levels:

- **Provider level**: General provider operations
- **LDAP subsystem**: Connection, authentication, operations
- **Environment variables**:
  - `TF_LOG=DEBUG` - Provider-wide debug logging
  - `TF_LOG_PROVIDER_AD_LDAP=TRACE` - LDAP subsystem trace logging

## Main Agent as Coordinator

The main agent in this project acts as a **coordinator and arbiter**, NOT as an implementer.

### Coordinator Responsibilities

**Progress Tracking**:
- Maintain PROGRESS.md with current implementation status
- Track which phases and tasks are complete
- Identify next tasks to delegate

**Work Delegation**:
- ALL development work must be delegated to expert agents
- Provide clear specifications and boundaries
- Never implement code directly

**Integration Coordination**:
- When work spans multiple experts, coordinate handoffs
- Ensure experts don't overlap or conflict
- Delegate integration work to appropriate expert

### Delegation Examples

✅ **CORRECT - Main agent delegates**:
```
Main Agent: "I need Phase 1.2 authentication implemented. Delegating to active-directory-ldap-expert:
Please implement authentication layer in internal/ldap/ with:
- Password and Kerberos authentication
- DN/UPN/SAM format support  
- Comprehensive tests
Files to create/modify: [specific list]"
```

❌ **INCORRECT - Main agent implements**:
```
Main Agent: "I'll implement the authentication layer myself using the specifications from the expert."
```

### Expert Implementation Responsibilities

**active-directory-ldap-expert**:
- Implements ALL LDAP/AD related code
- Writes ALL LDAP client code and tests
- Handles ALL authentication, GUID, normalization logic

**terraform-provider-expert**:
- Implements ALL Terraform provider code
- Writes ALL resource/data source code and tests
- Handles ALL schema, validators, plan modifiers

**Main Agent**:
- Coordinates between experts
- Tracks progress
- NEVER writes implementation code

## Expert Coordination Patterns

This project uses specialized expert agents that must be coordinated properly to prevent duplicate work and maintain clear boundaries.

### Expert Roles and Responsibilities

#### `active-directory-ldap-expert`
**Domain**: LDAP/Active Directory operations, connection management, authentication
**Responsibilities**:
- LDAP client architecture and connection pooling
- SRV record discovery and domain controller failover
- Authentication methods (password, Kerberos, certificate)
- GUID handling and byte encoding for LDAP operations
- Member identifier normalization (DN, GUID, SID, UPN, SAM)
- Active Directory-specific LDAP operations and attributes
- Error handling for LDAP operations

**Boundaries**: Does NOT implement Terraform provider schema, resource lifecycle, or plan modifiers

#### `terraform-provider-expert`
**Domain**: terraform-plugin-framework patterns, resource/data source implementation
**Responsibilities**:
- Provider schema design and validation
- Resource and data source lifecycle (CRUD operations)
- State management and plan modifiers
- Custom validators and plan modifiers
- Testing strategies and acceptance tests
- Import functionality and state migration

**Boundaries**: Does NOT implement LDAP connection logic, authentication, or Active Directory-specific operations

### Coordination Workflows

#### Design Consultation (Recommended)
When you need technical guidance:

```
// Good: Specific design consultation
"I need technical specifications from active-directory-ldap-expert for implementing 
connection pooling with the go-ldap/ldap/v3 library. Please provide patterns for:
- Connection pool structure and lifecycle
- Health check implementation  
- Retry logic with exponential backoff
- SRV record discovery for domain controllers"

// Good: Framework-specific consultation  
"I need schema design patterns from terraform-provider-expert for implementing 
the ad_group resource. Please provide guidance on:
- Resource model structure for group attributes
- Validators for group scope and category  
- Plan modifiers for computed attributes
- Import functionality patterns"
```

#### Implementation Delegation (When Needed)
When delegating implementation to an expert:

```
// Good: Clear delegation with boundaries
"Please implement the LDAP client connection pool in the internal/ldap/ package.
Files to create:
- internal/ldap/pool.go (connection pool implementation)
- internal/ldap/pool_test.go (unit tests)
Requirements:
- Use go-ldap/ldap/v3 library
- Max 10 connections with configurable timeout
- Health checks and automatic failover
- Do not modify any files outside internal/ldap/"

// Good: Resource implementation with integration points
"Please implement the ad_group resource schema and CRUD operations.
Files to modify:
- internal/provider/resource_group.go 
- internal/provider/resource_group_test.go
Integration points:
- Use ldapClient interface from internal/ldap package for LDAP operations
- Follow existing provider patterns in internal/provider/"
```

#### Cross-Domain Integration (Main Agent Responsibility)
For components spanning multiple domains:

```
// Main agent coordinates integration
1. Get LDAP client interface from active-directory-ldap-expert
2. Get provider configuration patterns from terraform-provider-expert  
3. Main agent implements provider.Configure() method that:
   - Parses Terraform configuration using provider patterns
   - Initializes LDAP client using LDAP patterns
   - Handles integration between the two domains
```

### Anti-Patterns to Avoid

❌ **Vague consultation requests**:
```
"Consult active-directory-ldap-expert for Phase 1.1"
→ Too vague, will trigger implementation instead of consultation
```

❌ **Cross-domain implementation**:
```
"Have terraform-provider-expert implement LDAP connection pooling"
→ Wrong expert domain, will produce suboptimal or incorrect code
```

❌ **Simultaneous work on same files**:
```
"Both experts work on provider.go"
→ Will cause conflicts and duplicate work
```

### Correct Usage Examples

✅ **Consultation for specifications**:
```
"Get technical specifications from active-directory-ldap-expert for member 
normalization. I need to understand how to convert GUID/SID/UPN/SAM identifiers 
to DNs to prevent configuration drift in group membership resources."
```

✅ **Targeted delegation**:
```
"Delegate implementation of group membership normalization logic to 
active-directory-ldap-expert. Create internal/ldap/normalizer.go with 
functions to convert any identifier type to DN."
```

✅ **Integration coordination**:
```
"Main agent will implement the provider Configure() method by:
1. Using Terraform configuration patterns from terraform-provider-expert
2. Using LDAP client initialization from active-directory-ldap-expert  
3. Coordinating the integration between provider config and LDAP client"
```

## Development Notes

### Key Files to Reference

- **DESIGN.md** - Comprehensive architecture and design decisions
- **PROGRESS.md** - Implementation progress tracking
- **TESTING.md** - Detailed testing strategy and patterns
- **.golangci.yml** - Linting configuration
- **go.mod** - Dependency management with Go 1.25.0

### Important Patterns

1. **Logging Context**: Always pass context through for proper logging subsystem integration
2. **Error Wrapping**: Use `fmt.Errorf("description: %w", err)` for error chains
3. **GUID Handling**: Use `internal/ldap.ParseGUID()` and `FormatGUID()` for GUID conversions
4. **DN Validation**: Use custom validators from `internal/provider/validators/`
5. **Member Normalization**: Use `internal/ldap.NormalizeMember()` for identifier conversion

### Common Pitfalls

- **GUID Encoding**: GUIDs in LDAP are binary, must be converted for Terraform state
- **DN Case Sensitivity**: LDAP DNs are case-insensitive but Terraform is case-sensitive
- **Group Type**: AD stores groupType as integer combining scope and category bits
- **Authentication**: Different username formats (DN/UPN/SAM) require different bind methods
- **Kerberos SPN**: IP-based connections need explicit SPN when using Kerberos

### Tools and Context

- Use **Context7 MCP** for Go, Terraform plugin framework, and LDAP library documentation
- Use **gopls MCP** for Go workspace analysis and symbol information
- Consult existing tests for implementation patterns before writing new code
- Follow existing code style - all code is gofmt'd and golangci-lint validated
