/*
Package ldap provides Active Directory LDAP operations for the Terraform AD provider.

This package implements a comprehensive LDAP client layer specifically designed for
Active Directory operations, with focus on:

# Architecture Overview

The package is organized into several core components:

  - Client: Connection management with pooling and health checks
  - Managers: Domain-specific operations (OU, Group, User, Membership)
  - Handlers: Utility operations (GUID, SID conversion)
  - Normalizers: Identifier normalization and caching

# Connection Management

The Client interface provides connection pooling with automatic failover:

  - SRV-based domain controller discovery
  - Connection pooling with health checks
  - Automatic retry with exponential backoff
  - Support for password and Kerberos authentication

# Domain Object Management

Each AD object type has a dedicated manager:

  - OUManager: Organizational Unit operations
  - GroupManager: Security and Distribution group operations
  - UserReader: User query and search operations
  - GroupMembershipManager: Bulk membership operations

# Identifier Normalization

The package provides robust identifier handling:

  - Supports DN, GUID, SID, UPN, and SAM account name formats
  - Automatic format detection and conversion
  - Caching layer for performance optimization
  - Anti-drift prevention through normalization

For group membership, MemberNormalizer.ResolveBatchAgainst avoids per-member
lookups: GroupMembershipManager.GetCurrentMembers reads every current member's
DN, objectGUID and objectSid in one GUID-filtered subtree search under the
manager's base DN (LDAP_SERVER_EXTENDED_DN_OID; a group outside the base DN is
reported as not found), DN,
GUID and SID identifiers that unambiguously name a current member are resolved
from that list in memory, and only the remainder (UPN/SAM, new or stale
identifiers) goes through ResolveBatch, in a single call.

# Active Directory Constraints

The implementation respects Active Directory operational limits:

  - Batch sizes respect AD's member operation limits (ADMemberBatchSize)
  - Connection limits prevent resource exhaustion (MaxConnectionPoolLimit)
  - Cache sizes balance performance and memory usage (DefaultNormalizerCacheSize)
  - Security descriptor DACL parsing for OU protection detection

# Error Handling

The package provides structured error handling through LDAPError:

  - Categorized errors (connection, authentication, validation, etc.)
  - Retryable error classification
  - Detailed context preservation
  - Server message integration

# Thread Safety

All managers and handlers are thread-safe and can be used concurrently.
Connection pooling handles concurrent access automatically.

# Example Usage

	// Create client with connection pooling
	config := &ldap.ConnectionConfig{
		Domain:   "example.com",
		Username: "administrator",
		Password: "password",
	}
	client, err := ldap.NewClient(config)
	if err != nil {
		return err
	}
	defer client.Close()

	// Manage organizational units
	ouManager := ldap.NewOUManager(client, "DC=example,DC=com")
	ou, err := ouManager.GetOU(ctx, "guid-string")
	if err != nil {
		return err
	}

	// Manage group membership
	membershipManager := ldap.NewGroupMembershipManager(ctx, client, "DC=example,DC=com", nil)
	err = membershipManager.SetGroupMembers(groupGUID, memberDNs, nil)
	if err != nil {
		return err
	}

	// Resolve configured member identifiers against current membership
	current, err := membershipManager.GetCurrentMembers(groupGUID)
	if err != nil {
		return err
	}
	normalizer := ldap.NewMemberNormalizer(client, "DC=example,DC=com", cacheManager)
	resolved, failures := normalizer.ResolveBatchAgainst(identifiers, current)
*/
package ldap
