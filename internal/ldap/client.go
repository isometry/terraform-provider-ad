package ldap

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// client implements the Client interface.
type client struct {
	pool       ConnectionPool
	config     *ConnectionConfig
	logContext context.Context // Context with configured subsystems for logging
}

// NewClient creates a new LDAP client with connection pooling.
func NewClient(config *ConnectionConfig) (Client, error) {
	return NewClientWithContext(context.Background(), config)
}

// NewClientWithContext creates a new LDAP client with connection pooling and logging context.
func NewClientWithContext(ctx context.Context, config *ConnectionConfig) (Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Log client creation attempt
	tflog.SubsystemDebug(ctx, "ldap", "Creating new LDAP client", map[string]any{
		"domain":          config.Domain,
		"ldap_urls_count": len(config.LDAPURLs),
		"auth_method":     config.GetAuthMethod().String(),
		"use_tls":         config.UseTLS,
		"max_connections": config.MaxConnections,
	})

	start := time.Now()
	pool, err := NewConnectionPool(config)
	if err != nil {
		tflog.SubsystemError(ctx, "ldap", "Failed to create connection pool", map[string]any{
			"error":       err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	tflog.SubsystemInfo(ctx, "ldap", "LDAP client created successfully", map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
		"pool_size":   config.MaxConnections,
		"auth_method": config.GetAuthMethod().String(),
	})

	return &client{
		pool:       pool,
		config:     config,
		logContext: ctx, // Store the context with configured subsystems
	}, nil
}

// getLoggingContext merges the stored logging context with the operation context.
// This ensures that subsystem loggers are always available while respecting operation context.
func (c *client) getLoggingContext(ctx context.Context) context.Context {
	// Always use the stored context which has subsystems configured
	// This fixes the uninitialized subsystem logger warnings by ensuring
	// all tflog.SubsystemXXX calls use a context with proper subsystem configuration
	//
	// Note: This uses the provider's context which has a longer lifetime but ensures
	// subsystem loggers work correctly. For most LDAP operations this is acceptable
	// since they are relatively quick operations.
	//
	// The ctx parameter is intentionally unused in this implementation as we always
	// return the stored context with subsystem configuration.
	_ = ctx // Mark as intentionally unused
	return c.logContext
}

// Connect initializes the client (tests initial connection).
func (c *client) Connect(ctx context.Context) error {
	return LogOperation(ctx, "ldap", "connection_test", map[string]any{
		"domain": c.config.Domain,
	}, func() error {
		// Test that we can get a connection from the pool
		tflog.SubsystemDebug(ctx, "ldap", "Testing connection pool availability")

		conn, err := c.pool.Get(ctx)
		if err != nil {
			tflog.SubsystemError(ctx, "ldap", "Failed to get connection from pool", map[string]any{
				"error": err.Error(),
			})
			return fmt.Errorf("connection test failed: %w", err)
		}
		defer conn.Close()

		tflog.SubsystemDebug(ctx, "ldap", "Connection acquired, performing ping test")

		// Perform a basic connectivity test
		if err := c.ping(ctx, conn); err != nil {
			tflog.SubsystemError(ctx, "ldap", "Ping test failed", map[string]any{
				"error": err.Error(),
			})
			return err
		}

		tflog.SubsystemInfo(ctx, "ldap", "Connection test successful")
		return nil
	})
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
		tflog.SubsystemError(ctx, "ldap", "No authentication configuration available")
		return fmt.Errorf("no authentication configuration available")
	}

	authMethod := c.config.GetAuthMethod()
	return LogOperation(ctx, "ldap", "authentication", map[string]any{
		"auth_method": authMethod.String(),
		"username":    c.config.Username,
	}, func() error {
		conn, err := c.pool.Get(ctx)
		if err != nil {
			tflog.SubsystemError(ctx, "ldap", "Failed to get connection for authentication", map[string]any{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to get connection: %w", err)
		}
		defer conn.Close()

		tflog.SubsystemDebug(ctx, "ldap", "Starting authentication", map[string]any{
			"auth_method": authMethod.String(),
		})

		// Perform authentication based on configured method
		return c.withRetry(ctx, func() error {
			return c.authenticate(ctx, conn.Conn())
		})
	})
}

// authenticate performs authentication based on the configured method.
func (c *client) authenticate(ctx context.Context, conn *ldap.Conn) error {
	authMethod := c.config.GetAuthMethod()

	tflog.SubsystemDebug(ctx, "ldap", "Performing authentication", map[string]any{
		"auth_method": authMethod.String(),
	})

	start := time.Now()
	var err error

	switch authMethod {
	case AuthMethodSimpleBind:
		err = c.authenticateSimple(ctx, conn)
	case AuthMethodKerberos:
		err = c.authenticateKerberos(ctx, conn)
	case AuthMethodExternal:
		err = c.authenticateExternal(ctx, conn)
	default:
		err = fmt.Errorf("unsupported authentication method: %s", authMethod.String())
	}

	if err != nil {
		tflog.SubsystemError(ctx, "ldap", "Authentication failed", map[string]any{
			"auth_method": authMethod.String(),
			"error":       err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		return err
	}

	tflog.SubsystemInfo(ctx, "ldap", "Authentication successful", map[string]any{
		"auth_method": authMethod.String(),
		"duration_ms": time.Since(start).Milliseconds(),
	})

	return nil
}

// authenticateSimple performs simple bind authentication.
func (c *client) authenticateSimple(ctx context.Context, conn *ldap.Conn) error {
	if c.config.Username == "" {
		tflog.SubsystemError(ctx, "ldap", "Username is required for simple bind authentication")
		return fmt.Errorf("username is required for simple bind authentication")
	}

	// Handle anonymous bind (empty password)
	password := c.config.Password
	isAnonymousBind := password == "" && c.config.Username != ""

	fields := map[string]any{
		"username":       c.config.Username,
		"anonymous_bind": isAnonymousBind,
	}

	tflog.SubsystemDebug(ctx, "ldap", "Performing simple bind", fields)

	var err error
	if isAnonymousBind {
		// Allow anonymous bind attempt with username only
		tflog.SubsystemDebug(ctx, "ldap", "Attempting anonymous bind with username")
		err = conn.Bind(c.config.Username, "")
	} else {
		tflog.SubsystemDebug(ctx, "ldap", "Attempting authenticated bind")
		err = conn.Bind(c.config.Username, password)
	}

	if err != nil {
		LogLDAPError(ctx, "ldap", "simple_bind", err, fields)
		return err
	}

	tflog.SubsystemDebug(ctx, "ldap", "Simple bind successful", fields)
	return nil
}

// authenticateKerberos performs GSSAPI/Kerberos authentication.
func (c *client) authenticateKerberos(ctx context.Context, conn *ldap.Conn) error {
	// For client connections, we need to extract server info from the config
	// Since client doesn't have direct access to ServerInfo like pool does,
	// we'll create it from the first available server or derive from connection

	var serverInfo *ServerInfo

	// Try to get server info from the config
	if len(c.config.LDAPURLs) > 0 {
		// Use the first LDAP URL to create ServerInfo
		parsedServer, err := ParseLDAPURL(c.config.LDAPURLs[0])
		if err != nil {
			return fmt.Errorf("failed to parse LDAP URL for Kerberos: %w", err)
		}
		serverInfo = parsedServer
	} else if c.config.Domain != "" {
		// For domain-based configs, we need to construct a hostname
		// This is a fallback - ideally we'd have access to the actual connected server
		serverInfo = &ServerInfo{
			Host:   c.config.Domain,
			Port:   636, // Default LDAPS port
			UseTLS: true,
		}
	} else {
		return fmt.Errorf("insufficient connection information for Kerberos authentication")
	}

	return performKerberosAuthWithContext(ctx, conn, c.config, serverInfo)
}

// authenticateExternal performs external/certificate authentication.
func (c *client) authenticateExternal(ctx context.Context, conn *ldap.Conn) error {
	// External authentication typically relies on TLS client certificates
	// The authentication happens at the TLS layer, so we just need to
	// perform an empty bind to complete the LDAP authentication

	// Use context for timeout handling during the bind operation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Proceed with the bind
	}

	return conn.Bind("", "")
}

// performSearch is a helper function that performs search operations with comprehensive logging.
func (c *client) performSearch(ctx context.Context, operation string, fields map[string]any, searchFunc func() (*SearchResult, error)) (*SearchResult, error) {
	start := time.Now()

	if fields == nil {
		fields = make(map[string]any)
	}
	fields["operation"] = operation

	tflog.SubsystemDebug(ctx, "ldap", "Starting search operation", fields)

	result, err := searchFunc()

	fields["duration_ms"] = time.Since(start).Milliseconds()

	if err != nil {
		fields["error"] = err.Error()
		tflog.SubsystemError(ctx, "ldap", "Search operation failed", fields)
		return nil, err
	}

	fields["entries_found"] = len(result.Entries)
	tflog.SubsystemDebug(ctx, "ldap", "Search operation completed successfully", fields)

	return result, nil
}

// Search performs an LDAP search.
func (c *client) Search(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	if req == nil {
		tflog.SubsystemError(ctx, "ldap", "Search request cannot be nil")
		return nil, fmt.Errorf("search request cannot be nil")
	}

	searchFields := map[string]any{
		"base_dn":    req.BaseDN,
		"scope":      req.Scope.String(),
		"filter":     req.Filter,
		"attributes": req.Attributes,
		"size_limit": req.SizeLimit,
		"time_limit": req.TimeLimit.String(),
	}

	return c.performSearch(ctx, "search", searchFields, func() (*SearchResult, error) {
		conn, err := c.pool.Get(ctx)
		if err != nil {
			tflog.SubsystemError(ctx, "ldap", "Failed to get connection for search", map[string]any{
				"error": err.Error(),
			})
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
			LogLDAPError(ctx, "ldap", "search", err, searchFields)
			return nil, fmt.Errorf("search failed: %w", err)
		}

		// Detect if there might be more results available
		// If we got exactly the size limit, there might be more results
		hasMore := req.SizeLimit > 0 && len(result.Entries) >= req.SizeLimit

		searchResult := &SearchResult{
			Entries: result.Entries,
			Total:   len(result.Entries),
			HasMore: hasMore,
		}

		tflog.SubsystemDebug(ctx, "ldap", "Search completed", map[string]any{
			"entries_found": len(result.Entries),
			"has_more":      hasMore,
		})

		return searchResult, nil
	})
}

// SearchWithPaging performs an LDAP search with automatic pagination.
func (c *client) SearchWithPaging(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	if req == nil {
		return nil, fmt.Errorf("search request cannot be nil")
	}

	// Use the logging context
	logCtx := c.getLoggingContext(ctx)

	start := time.Now()
	fields := map[string]any{
		"base_dn":    req.BaseDN,
		"filter":     req.Filter,
		"scope":      req.Scope.String(),
		"attributes": req.Attributes,
		"time_limit": req.TimeLimit.String(),
	}

	tflog.SubsystemDebug(logCtx, "ldap", "Starting paged search", fields)

	conn, err := c.pool.Get(ctx)
	if err != nil {
		LogLDAPError(logCtx, "ldap", "get_connection", err, fields)
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	tflog.SubsystemTrace(logCtx, "ldap", "Connection acquired for paged search", fields)

	var allEntries []*ldap.Entry
	pagingControl := ldap.NewControlPaging(1000) // Page size of 1000
	pageNum := 0

	tflog.SubsystemDebug(logCtx, "ldap", "Beginning paged search loop", map[string]any{
		"page_size": 1000,
		"base_dn":   req.BaseDN,
		"filter":    req.Filter,
	})

	lastProgressTime := start
	maxSearchDuration := 30 * time.Minute // Maximum total search time
	maxPagesPerSearch := 1000             // Maximum pages to prevent runaway searches

	for {
		// Check for timeout conditions before starting next page
		currentTime := time.Now()
		elapsedTotal := currentTime.Sub(start)

		// Check maximum search duration
		if elapsedTotal > maxSearchDuration {
			timeoutFields := map[string]any{
				"operation":       "paged_search_timeout",
				"base_dn":         req.BaseDN,
				"filter":          req.Filter,
				"elapsed_minutes": int(elapsedTotal.Minutes()),
				"max_minutes":     int(maxSearchDuration.Minutes()),
				"pages_completed": pageNum - 1,
				"entries_found":   len(allEntries),
			}
			tflog.SubsystemError(logCtx, "ldap", "Paged search exceeded maximum duration, terminating", timeoutFields)
			return &SearchResult{
				Entries: allEntries,
				Total:   len(allEntries),
				HasMore: true, // Indicate there may be more results
			}, nil
		}

		// Check maximum pages per search
		if pageNum > maxPagesPerSearch {
			pageTimeoutFields := map[string]any{
				"operation":       "paged_search_page_limit",
				"base_dn":         req.BaseDN,
				"filter":          req.Filter,
				"pages_completed": pageNum - 1,
				"max_pages":       maxPagesPerSearch,
				"entries_found":   len(allEntries),
			}
			tflog.SubsystemError(logCtx, "ldap", "Paged search exceeded maximum page limit, terminating", pageTimeoutFields)
			return &SearchResult{
				Entries: allEntries,
				Total:   len(allEntries),
				HasMore: true, // Indicate there may be more results
			}, nil
		}

		// Check if context was cancelled
		select {
		case <-ctx.Done():
			cancelFields := map[string]any{
				"operation":       "paged_search_cancelled",
				"base_dn":         req.BaseDN,
				"filter":          req.Filter,
				"pages_completed": pageNum - 1,
				"entries_found":   len(allEntries),
				"context_error":   ctx.Err().Error(),
			}
			tflog.SubsystemWarn(logCtx, "ldap", "Paged search cancelled by context", cancelFields)
			return &SearchResult{
				Entries: allEntries,
				Total:   len(allEntries),
				HasMore: true, // Indicate there may be more results
			}, ctx.Err()
		default:
			// Continue processing
		}

		pageNum++
		pageStart := time.Now()

		pageFields := map[string]any{
			"page_number":          pageNum,
			"total_entries_so_far": len(allEntries),
			"base_dn":              req.BaseDN,
			"filter":               req.Filter,
		}

		tflog.SubsystemTrace(logCtx, "ldap", "Starting search page", pageFields)

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

		pageDuration := time.Since(pageStart)
		pageFields["duration_ms"] = pageDuration.Milliseconds()

		if err != nil {
			pageFields["error"] = err.Error()
			LogLDAPError(logCtx, "ldap", "paged_search", err, pageFields)
			return nil, fmt.Errorf("paged search failed: %w", err)
		}

		entriesInPage := len(result.Entries)
		allEntries = append(allEntries, result.Entries...)

		pageFields["entries_in_page"] = entriesInPage
		pageFields["total_entries"] = len(allEntries)

		tflog.SubsystemDebug(logCtx, "ldap", "Completed search page", pageFields)

		// Progress indicator: log every 10 pages or every 10 seconds
		// Note: currentTime and elapsedTotal are already calculated above
		showProgress := (pageNum%10 == 0) || (currentTime.Sub(lastProgressTime) >= 10*time.Second)

		if showProgress {
			progressFields := map[string]any{
				"operation":            "paged_search_progress",
				"base_dn":              req.BaseDN,
				"filter":               req.Filter,
				"pages_completed":      pageNum,
				"total_entries":        len(allEntries),
				"elapsed_seconds":      int(elapsedTotal.Seconds()),
				"average_page_time_ms": elapsedTotal.Milliseconds() / int64(pageNum),
				"entries_per_second":   float64(len(allEntries)) / elapsedTotal.Seconds(),
			}
			tflog.SubsystemInfo(logCtx, "ldap", "Paged search in progress", progressFields)
			lastProgressTime = currentTime
		}

		// Check for more pages
		pagingResult := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if responseControl, ok := pagingResult.(*ldap.ControlPaging); ok {
			if len(responseControl.Cookie) == 0 {
				tflog.SubsystemTrace(logCtx, "ldap", "No more pages, search complete", map[string]any{
					"final_page":    pageNum,
					"total_entries": len(allEntries),
				})
				break // No more pages
			}
			pagingControl.SetCookie(responseControl.Cookie)
			tflog.SubsystemTrace(logCtx, "ldap", "More pages available, continuing", map[string]any{
				"completed_pages": pageNum,
				"cookie_length":   len(responseControl.Cookie),
			})
		} else {
			tflog.SubsystemTrace(logCtx, "ldap", "No paging control in response, search complete", map[string]any{
				"final_page":    pageNum,
				"total_entries": len(allEntries),
			})
			break // No paging control in response
		}
	}

	totalDuration := time.Since(start)
	finalFields := map[string]any{
		"base_dn":            req.BaseDN,
		"filter":             req.Filter,
		"total_entries":      len(allEntries),
		"pages_processed":    pageNum,
		"duration_ms":        totalDuration.Milliseconds(),
		"entries_per_second": float64(len(allEntries)) / totalDuration.Seconds(),
	}

	tflog.SubsystemInfo(logCtx, "ldap", "Paged search completed", finalFields)

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
		if attempt > 0 {
			tflog.SubsystemDebug(ctx, "ldap", "Retrying operation", map[string]any{
				"attempt":    attempt,
				"max_retry":  c.config.MaxRetries,
				"backoff_ms": backoff.Milliseconds(),
				"last_error": lastErr.Error(),
			})
		}

		err := operation()
		if err == nil {
			if attempt > 0 {
				tflog.SubsystemInfo(ctx, "ldap", "Operation succeeded after retries", map[string]any{
					"successful_attempt": attempt + 1,
					"total_attempts":     attempt + 1,
				})
			}
			return nil // Success
		}

		lastErr = err

		// Check if error is retryable
		if !c.isRetryableError(err) {
			tflog.SubsystemDebug(ctx, "ldap", "Non-retryable error encountered", map[string]any{
				"error":   err.Error(),
				"attempt": attempt + 1,
			})
			return err // Non-retryable error
		}

		// Don't wait after the last attempt
		if attempt == c.config.MaxRetries {
			break
		}

		// Wait before retrying
		select {
		case <-ctx.Done():
			tflog.SubsystemWarn(ctx, "ldap", "Operation cancelled during retry", map[string]any{
				"context_error": ctx.Err().Error(),
				"attempt":       attempt + 1,
			})
			return ctx.Err()
		case <-time.After(backoff):
			// Exponential backoff
			backoff = min(time.Duration(float64(backoff)*c.config.BackoffFactor), c.config.MaxBackoff)
		}
	}

	tflog.SubsystemError(ctx, "ldap", "Operation failed after all retries exhausted", map[string]any{
		"total_attempts": c.config.MaxRetries + 1,
		"final_error":    lastErr.Error(),
	})

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

// WhoAmI performs the LDAP Who Am I? extended operation.
func (c *client) WhoAmI(ctx context.Context) (*WhoAmIResult, error) {
	conn, err := c.pool.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}
	defer conn.Close()

	var result *ldap.WhoAmIResult
	err = c.withRetry(ctx, func() error {
		var whoamiErr error
		result, whoamiErr = conn.Conn().WhoAmI(nil)
		return whoamiErr
	})

	if err != nil {
		return nil, fmt.Errorf("WhoAmI operation failed: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("WhoAmI operation returned nil result")
	}

	// Parse the authorization ID and extract meaningful information
	whoAmIResult := &WhoAmIResult{
		AuthzID: result.AuthzID,
	}

	c.parseAuthzID(whoAmIResult)

	return whoAmIResult, nil
}

// parseAuthzID parses the authorization ID and extracts structured information.
func (c *client) parseAuthzID(result *WhoAmIResult) {
	authzID := result.AuthzID

	if authzID == "" {
		result.Format = "empty"
		return
	}

	// Remove the "u:" prefix if present (common in Active Directory responses)
	cleanAuthzID := strings.TrimPrefix(authzID, "u:")

	// Try to identify the format and extract relevant information

	// Check for DN format (contains CN= or DC= components)
	if c.isDNFormat(cleanAuthzID) {
		result.Format = "dn"
		result.DN = cleanAuthzID
		return
	}

	// Check for UPN format (contains @ symbol)
	if strings.Contains(cleanAuthzID, "@") && !strings.Contains(cleanAuthzID, "\\") {
		result.Format = "upn"
		result.UserPrincipalName = cleanAuthzID
		return
	}

	// Check for SAM format (contains domain backslash)
	if strings.Contains(cleanAuthzID, "\\") && !strings.HasPrefix(cleanAuthzID, "S-") {
		result.Format = "sam"
		result.SAMAccountName = cleanAuthzID
		return
	}

	// Check for SID format (starts with S- and has the right pattern)
	if c.isSIDFormat(cleanAuthzID) {
		result.Format = "sid"
		result.SID = cleanAuthzID
		return
	}

	// Unknown format
	result.Format = "unknown"
}

// isDNFormat checks if the string looks like a Distinguished Name.
func (c *client) isDNFormat(s string) bool {
	// A DN should have at least one component like CN=, OU=, DC=, etc.
	dnPattern := regexp.MustCompile(`^[A-Za-z]+=.*`)
	return dnPattern.MatchString(s) && (strings.Contains(s, "CN=") || strings.Contains(s, "OU=") || strings.Contains(s, "DC="))
}

// isSIDFormat checks if the string looks like a Security Identifier.
func (c *client) isSIDFormat(s string) bool {
	// SID format: S-R-I-S-S-... where R is revision, I is identifier authority, S are subauthorities
	sidPattern := regexp.MustCompile(`^S-\d+-\d+-\d+(-\d+)*$`)
	return sidPattern.MatchString(s)
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
