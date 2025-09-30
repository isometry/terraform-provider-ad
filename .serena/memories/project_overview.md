# Project Overview

## Purpose
A modern Terraform provider for managing Active Directory resources via LDAP/LDAPS with native connectivity, automatic domain controller discovery, comprehensive Kerberos authentication support, and efficient connection management.

## Registry Information
- **Registry Address**: `registry.terraform.io/isometry/ad`
- **Provider Type Name**: `ad`
- **Go Version**: 1.25.0
- **Framework**: terraform-plugin-framework v1.15.1 (NOT SDK v2)

## Key Features
- Native LDAP connectivity with connection pooling
- SRV-based domain controller discovery
- Full Kerberos authentication (keytab, ccache, password)
- Resource identification via objectGUID
- Member identifier normalization (DN, GUID, SID, UPN, SAM)
- Cache warming for large environments

## Resources Implemented
- **Resources**: `ad_group`, `ad_ou`, `ad_group_membership`
- **Data Sources**: `ad_group`, `ad_groups`, `ad_ou`, `ad_user`, `ad_users`, `ad_whoami`
- **Provider Functions**: `provider::ad::build_hierarchy`, `provider::ad::normalize_roles`

## Architecture
- **Connection Management**: Connection pooling, health checks, retry logic, failover
- **Authentication**: Password auth (DN/UPN/SAM formats), Kerberos (keytab/ccache/password)
- **Identifiers**: objectGUID as Terraform ID, all identifiers normalized to DNs internally