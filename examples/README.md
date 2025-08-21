# Terraform AD Provider Examples

This directory contains comprehensive examples for using the Terraform AD (Active Directory) provider.

## Provider Configuration Examples

### [`provider/provider.tf`](provider/provider.tf)
Complete provider configuration examples including:
- SRV-based domain discovery
- Direct LDAP URL connections
- Kerberos authentication
- Certificate-based authentication
- Production connection pooling settings
- Environment variable configuration

## Resource Examples

### [`resources/ad_group/`](resources/ad_group/)
Examples for creating and managing Active Directory groups:
- Basic security groups
- Distribution groups for email
- Different group scopes (Global, Universal, DomainLocal)
- Group containers and organization
- Import examples with multiple identifier formats

### [`resources/ad_group_membership/`](resources/ad_group_membership/)
Examples for managing group memberships:
- Mixed member identifier formats (DN, GUID, SID, UPN, SAM)
- Adding users and groups as members
- Nested group structures
- Import examples

### [`resources/ad_ou/`](resources/ad_ou/)
Examples for creating and managing Organizational Units:
- Basic OU creation
- Nested OU structures
- Protected OUs
- Using OUs as containers for other resources
- Import examples

## Data Source Examples

### [`data-sources/ad_group/`](data-sources/ad_group/)
Examples for looking up existing groups:
- Lookup by name, DN, GUID, SID, SAM
- Using group data in other resources
- Creating nested group structures

### [`data-sources/ad_groups/`](data-sources/ad_groups/)
Examples for searching multiple groups:
- Container-based searches
- Filtering by name patterns, type, scope
- Membership-based filtering
- Complex multi-criteria searches
- Generating reports and analytics

### [`data-sources/ad_ou/`](data-sources/ad_ou/)
Examples for looking up organizational units:
- Lookup by name, DN, GUID, path
- Using OU data for resource organization
- Creating nested structures

### [`data-sources/ad_user/`](data-sources/ad_user/)
Examples for looking up user information:
- Lookup by SAM, DN, UPN, GUID, SID
- Using user attributes for group creation
- Conditional resource creation based on user data

### [`data-sources/ad_users/`](data-sources/ad_users/)
Examples for searching multiple users:
- Department and title-based searches
- Enabled/disabled user filtering
- Complex multi-criteria searches
- Automatic group creation based on user attributes

## Complete Integration Example

### [`complete/main.tf`](complete/main.tf)
A comprehensive example showing:
- Complete organizational structure creation
- Multiple resource types working together
- Data source usage for dynamic configuration
- Production-ready patterns and best practices
- Conditional resource creation
- Comprehensive outputs for monitoring

## Getting Started

1. **Configure Provider**: Start with the provider examples to set up authentication
2. **Basic Resources**: Try the individual resource examples to understand each resource type
3. **Data Sources**: Explore data source examples to understand how to query existing AD objects
4. **Integration**: Review the complete example to see how everything works together

## Prerequisites

- Active Directory domain with appropriate permissions
- Service account with necessary AD permissions:
  - Create/modify groups and OUs
  - Read user information
  - Manage group memberships
- Terraform 1.0 or later
- Network connectivity to domain controllers

## Authentication Options

The provider supports multiple authentication methods:

1. **Username/Password** (most common)
2. **Kerberos/GSSAPI** (recommended for domain-joined systems)
3. **Certificate-based** (for service-to-service authentication)

See the provider configuration examples for detailed setup instructions.

## Security Best Practices

- Use service accounts with minimal required permissions
- Always use TLS in production (`use_tls = true`)
- Never skip TLS verification in production (`skip_tls_verify = false`)
- Use environment variables for sensitive values
- Implement proper connection limits and timeouts
- Consider certificate-based authentication for automated deployments

## Testing Examples

Each example includes:
- Complete, runnable Terraform configurations
- Import examples where applicable
- Output examples for validation
- Comments explaining key concepts

To test an example:

```bash
cd examples/resources/ad_group
terraform init
terraform plan
terraform apply
```

## Documentation Generation

The document generation tool looks for files in the following locations by default:

* **provider/provider.tf** - Provider configuration examples for the index page
* **data-sources/`data_source_name`/data-source.tf** - Examples for each data source
* **resources/`resource_name`/resource.tf** - Examples for each resource

All other *.tf files are ignored by the documentation tool but can be used for additional examples or testing.

## Troubleshooting

Common issues and solutions:

1. **Authentication failures**: Verify username format and permissions
2. **Connection issues**: Check domain controller accessibility and DNS
3. **Permission errors**: Ensure service account has necessary AD rights
4. **Container not found**: Verify OU exists before creating resources

See the provider documentation for detailed troubleshooting guides.
