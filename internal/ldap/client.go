package ldap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// client implements the Client interface.
type client struct {
	pool   ConnectionPool
	config *ConnectionConfig
}

// NewClient creates a new LDAP client with connection pooling.
func NewClient(config *ConnectionConfig) (Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	pool, err := NewConnectionPool(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	return &client{
		pool:   pool,
		config: config,
	}, nil
}

// Connect initializes the client (tests initial connection).
func (c *client) Connect(ctx context.Context) error {
	// Test that we can get a connection from the pool
	conn, err := c.pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer conn.Close()

	// Perform a basic connectivity test
	return c.ping(ctx, conn)
}

// Close closes the client and all its connections.
func (c *client) Close() error {
	return c.pool.Close()
}

// Bind authenticates with the LDAP server.
func (c *client) Bind(ctx context.Context, username, password string) error {
	conn, err := c.pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	// Perform bind operation with retry logic
	return c.withRetry(ctx, func() error {
		return conn.Conn().Bind(username, password)
	})
}

// BindWithConfig performs authentication using the client's configuration.
func (c *client) BindWithConfig(ctx context.Context) error {
	if !c.config.HasAuthentication() {
		return fmt.Errorf("no authentication configuration available")
	}

	conn, err := c.pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	// Perform authentication based on configured method
	return c.withRetry(ctx, func() error {
		return c.authenticate(conn.Conn())
	})
}

// authenticate performs authentication based on the configured method.
func (c *client) authenticate(conn *ldap.Conn) error {
	authMethod := c.config.GetAuthMethod()

	switch authMethod {
	case AuthMethodSimpleBind:
		return c.authenticateSimple(conn)
	case AuthMethodKerberos:
		return c.authenticateKerberos(conn)
	case AuthMethodExternal:
		return c.authenticateExternal(conn)
	default:
		return fmt.Errorf("unsupported authentication method: %s", authMethod.String())
	}
}

// authenticateSimple performs simple bind authentication.
func (c *client) authenticateSimple(conn *ldap.Conn) error {
	if c.config.Username == "" {
		return fmt.Errorf("username is required for simple bind authentication")
	}

	// Handle anonymous bind (empty password)
	password := c.config.Password
	if password == "" && c.config.Username != "" {
		// Allow anonymous bind attempt with username only
		return conn.Bind(c.config.Username, "")
	}

	return conn.Bind(c.config.Username, password)
}

// authenticateKerberos performs GSSAPI/Kerberos authentication.
func (c *client) authenticateKerberos(conn *ldap.Conn) error {
	// For now, return error indicating Kerberos is not yet implemented
	// This will be implemented in a future phase
	return fmt.Errorf("kerberos authentication not yet implemented")
}

// authenticateExternal performs external/certificate authentication.
func (c *client) authenticateExternal(conn *ldap.Conn) error {
	// External authentication typically relies on TLS client certificates
	// The authentication happens at the TLS layer, so we just need to
	// perform an empty bind to complete the LDAP authentication
	return conn.Bind("", "")
}

// Search performs an LDAP search.
func (c *client) Search(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	if req == nil {
		return nil, fmt.Errorf("search request cannot be nil")
	}

	conn, err := c.pool.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	// Convert our SearchRequest to go-ldap SearchRequest
	ldapReq := ldap.NewSearchRequest(
		req.BaseDN,
		int(req.Scope),
		int(req.DerefAliases),
		req.SizeLimit,
		int(req.TimeLimit.Seconds()),
		false, // TypesOnly
		req.Filter,
		req.Attributes,
		nil, // Controls
	)

	var result *ldap.SearchResult
	err = c.withRetry(ctx, func() error {
		var searchErr error
		result, searchErr = conn.Conn().Search(ldapReq)
		return searchErr
	})

	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Detect if there might be more results available
	// If we got exactly the size limit, there might be more results
	hasMore := req.SizeLimit > 0 && len(result.Entries) >= req.SizeLimit

	return &SearchResult{
		Entries: result.Entries,
		Total:   len(result.Entries),
		HasMore: hasMore,
	}, nil
}

// SearchWithPaging performs an LDAP search with automatic pagination.
func (c *client) SearchWithPaging(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	if req == nil {
		return nil, fmt.Errorf("search request cannot be nil")
	}

	conn, err := c.pool.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	var allEntries []*ldap.Entry
	pagingControl := ldap.NewControlPaging(1000) // Page size of 1000

	for {
		ldapReq := ldap.NewSearchRequest(
			req.BaseDN,
			int(req.Scope),
			int(req.DerefAliases),
			0, // No size limit when paging
			int(req.TimeLimit.Seconds()),
			false,
			req.Filter,
			req.Attributes,
			[]ldap.Control{pagingControl},
		)

		var result *ldap.SearchResult
		err = c.withRetry(ctx, func() error {
			var searchErr error
			result, searchErr = conn.Conn().Search(ldapReq)
			return searchErr
		})

		if err != nil {
			return nil, fmt.Errorf("paged search failed: %w", err)
		}

		allEntries = append(allEntries, result.Entries...)

		// Check for more pages
		pagingResult := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if pagingControl, ok := pagingResult.(*ldap.ControlPaging); ok {
			if len(pagingControl.Cookie) == 0 {
				break // No more pages
			}
			pagingControl.SetCookie(pagingControl.Cookie)
		} else {
			break // No paging control in response
		}
	}

	return &SearchResult{
		Entries: allEntries,
		Total:   len(allEntries),
		HasMore: false,
	}, nil
}

// Add creates a new LDAP entry.
func (c *client) Add(ctx context.Context, req *AddRequest) error {
	if req == nil {
		return fmt.Errorf("add request cannot be nil")
	}

	conn, err := c.pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	// Convert our AddRequest to go-ldap AddRequest
	ldapReq := ldap.NewAddRequest(req.DN, nil)
	for attr, values := range req.Attributes {
		ldapReq.Attribute(attr, values)
	}

	return c.withRetry(ctx, func() error {
		return conn.Conn().Add(ldapReq)
	})
}

// Modify modifies an existing LDAP entry.
func (c *client) Modify(ctx context.Context, req *ModifyRequest) error {
	if req == nil {
		return fmt.Errorf("modify request cannot be nil")
	}

	conn, err := c.pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	// Convert our ModifyRequest to go-ldap ModifyRequest
	ldapReq := ldap.NewModifyRequest(req.DN, nil)

	// Add attributes
	for attr, values := range req.AddAttributes {
		ldapReq.Add(attr, values)
	}

	// Replace attributes
	for attr, values := range req.ReplaceAttributes {
		ldapReq.Replace(attr, values)
	}

	// Delete attributes
	for _, attr := range req.DeleteAttributes {
		ldapReq.Delete(attr, []string{})
	}

	return c.withRetry(ctx, func() error {
		return conn.Conn().Modify(ldapReq)
	})
}

// ModifyDN moves or renames an LDAP entry.
func (c *client) ModifyDN(ctx context.Context, req *ModifyDNRequest) error {
	if req == nil {
		return fmt.Errorf("modify DN request cannot be nil")
	}

	if req.DN == "" {
		return fmt.Errorf("DN cannot be empty")
	}

	if req.NewRDN == "" {
		return fmt.Errorf("new RDN cannot be empty")
	}

	conn, err := c.pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	// Convert our ModifyDNRequest to go-ldap ModifyDNRequest
	ldapReq := ldap.NewModifyDNRequest(req.DN, req.NewRDN, req.DeleteOldRDN, req.NewSuperior)

	return c.withRetry(ctx, func() error {
		return conn.Conn().ModifyDN(ldapReq)
	})
}

// Delete removes an LDAP entry.
func (c *client) Delete(ctx context.Context, dn string) error {
	if dn == "" {
		return fmt.Errorf("DN cannot be empty")
	}

	conn, err := c.pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	ldapReq := ldap.NewDelRequest(dn, nil)

	return c.withRetry(ctx, func() error {
		return conn.Conn().Del(ldapReq)
	})
}

// Ping tests connectivity to the LDAP server.
func (c *client) Ping(ctx context.Context) error {
	conn, err := c.pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	return c.ping(ctx, conn)
}

// ping performs the actual ping test.
func (c *client) ping(_ context.Context, conn *PooledConnection) error {
	// Perform a simple search to test connectivity
	searchReq := ldap.NewSearchRequest(
		"", // Empty base DN for root DSE
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 5, false, // Size limit 1, time limit 5 seconds
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	_, err := conn.Conn().Search(searchReq)
	return err
}

// Stats returns pool statistics.
func (c *client) Stats() PoolStats {
	return c.pool.Stats()
}

// withRetry executes an operation with retry logic.
func (c *client) withRetry(ctx context.Context, operation func() error) error {
	var lastErr error
	backoff := c.config.InitialBackoff

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		err := operation()
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Check if error is retryable
		if !c.isRetryableError(err) {
			return err // Non-retryable error
		}

		// Don't wait after the last attempt
		if attempt == c.config.MaxRetries {
			break
		}

		// Wait before retrying
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			// Exponential backoff
			backoff = min(time.Duration(float64(backoff)*c.config.BackoffFactor), c.config.MaxBackoff)
		}
	}

	return NewConnectionError("operation failed after retries", false, lastErr)
}

// isRetryableError determines if an error should be retried.
func (c *client) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it implements RetryableError interface
	if retryable, ok := err.(RetryableError); ok {
		return retryable.IsRetryable()
	}

	// Check for specific LDAP error codes that are retryable
	if ldap.IsErrorWithCode(err, ldap.LDAPResultBusy) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultServerDown) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultOperationsError) {
		return true
	}

	// Check for network-related errors and authentication errors
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "network") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "successful bind must be completed") ||
		strings.Contains(errStr, "bind must be completed") {
		return true
	}

	return false
}

// Helper functions for common operations

// GetBaseDN retrieves the base DN from the root DSE.
func (c *client) GetBaseDN(ctx context.Context) (string, error) {
	searchReq := &SearchRequest{
		BaseDN:     "",
		Scope:      ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"defaultNamingContext"},
		SizeLimit:  1,
		TimeLimit:  5 * time.Second,
	}

	result, err := c.Search(ctx, searchReq)
	if err != nil {
		return "", fmt.Errorf("failed to get base DN: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no root DSE found")
	}

	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		return "", fmt.Errorf("no defaultNamingContext found in root DSE")
	}

	return baseDN, nil
}

// GetServerInfo retrieves server information.
func (c *client) GetServerInfo(ctx context.Context) (map[string]string, error) {
	searchReq := &SearchRequest{
		BaseDN: "",
		Scope:  ScopeBaseObject,
		Filter: "(objectClass=*)",
		Attributes: []string{
			"defaultNamingContext",
			"schemaNamingContext",
			"configurationNamingContext",
			"rootDomainNamingContext",
			"supportedLDAPVersion",
			"supportedSASLMechanisms",
			"dnsHostName",
		},
		SizeLimit: 1,
		TimeLimit: 10 * time.Second,
	}

	result, err := c.Search(ctx, searchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("no root DSE found")
	}

	info := make(map[string]string)
	entry := result.Entries[0]

	for _, attr := range searchReq.Attributes {
		value := entry.GetAttributeValue(attr)
		if value != "" {
			info[attr] = value
		}
	}

	return info, nil
}
