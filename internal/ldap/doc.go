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

# Active Directory Constraints

The implementation respects Active Directory operational limits:

  - Batch sizes respect AD's member operation limits (ADMemberBatchSize)
  - Connection limits prevent resource exhaustion (MaxConnectionPoolLimit)
  - Cache sizes balance performance and memory usage (DefaultNormalizerCacheSize)
  - Security descriptor analysis for protection detection (ProtectedOUDescriptorMinLength)

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
	err = membershipManager.SetGroupMembers(ctx, groupGUID, memberDNs)
	if err != nil {
		return err
	}
*/
package ldap
