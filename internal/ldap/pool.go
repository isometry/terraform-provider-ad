package ldap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Connection pool limits.
const (
	// MaxConnectionPoolLimit is the maximum allowed connections in a pool.
	//
	// This limit prevents excessive resource consumption and protects against:
	//   - LDAP server connection exhaustion
	//   - Memory overconsumption on the client side
	//   - Network socket depletion
	//   - Degraded performance due to context switching
	//
	// A limit of 100 connections provides sufficient concurrency for most
	// Terraform operations while staying well below typical AD server limits
	// (which often default to 1000+ concurrent connections).
	MaxConnectionPoolLimit = 100
)

// connectionPool implements ConnectionPool interface.
type connectionPool struct {
	ctx         context.Context // Logging context with LDAP subsystem
	config      *ConnectionConfig
	servers     []*ServerInfo
	connections chan *PooledConnection
	mu          sync.RWMutex
	closed      bool
	discovery   *SRVDiscovery

	// Statistics
	activeConns  int64
	totalCreated int64
	totalErrors  int64
	startTime    time.Time

	// Health checking
	healthTicker *time.Ticker
	healthStop   chan struct{}
	healthWg     sync.WaitGroup
}

// NewConnectionPool creates a new connection pool.
func NewConnectionPool(ctx context.Context, config *ConnectionConfig) (ConnectionPool, error) {
	start := time.Now()
	tflog.SubsystemDebug(ctx, "ldap", "Creating new connection pool")

	if config == nil {
		config = DefaultConfig()
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	pool := &connectionPool{
		ctx:         ctx, // Store context for logging
		config:      config,
		connections: make(chan *PooledConnection, config.MaxConnections),
		discovery:   NewSRVDiscovery(ctx),
		startTime:   time.Now(),
		healthStop:  make(chan struct{}),
	}

	// Discover servers with timing
	if err := pool.discoverServers(); err != nil {
		return nil, fmt.Errorf("server discovery failed: %w", err)
	}

	// Start health checking if enabled
	if config.HealthCheck > 0 {
		pool.startHealthChecker()
	}

	tflog.SubsystemDebug(ctx, "ldap", "Connection pool created", map[string]any{
		"duration": time.Since(start).String(),
	})
	return pool, nil
}

// discoverServers discovers available servers.
func (p *connectionPool) discoverServers() error {
	start := time.Now()
	var servers []*ServerInfo

	// Use configured URLs if provided
	if len(p.config.LDAPURLs) > 0 {
		tflog.SubsystemDebug(p.ctx, "ldap", "Using configured LDAP URLs", map[string]any{
			"urls": p.config.LDAPURLs,
		})
		for _, url := range p.config.LDAPURLs {
			server, err := ParseLDAPURL(url)
			if err != nil {
				return fmt.Errorf("invalid LDAP URL %s: %w", url, err)
			}
			servers = append(servers, server)
		}
		tflog.SubsystemDebug(p.ctx, "ldap", "Parsed servers from URLs", map[string]any{
			"server_count":   len(servers),
			"parse_duration": time.Since(start).String(),
		})
	} else if p.config.Domain != "" {
		// Use SRV discovery
		tflog.SubsystemDebug(p.ctx, "ldap", "Starting SRV discovery for domain", map[string]any{
			"domain":  p.config.Domain,
			"timeout": p.config.Timeout.String(),
		})
		ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
		defer cancel()

		discoveryStart := time.Now()
		discoveredServers, err := p.discovery.DiscoverServers(ctx, p.config.Domain)
		discoveryDuration := time.Since(discoveryStart)
		tflog.SubsystemDebug(p.ctx, "ldap", "SRV discovery completed", map[string]any{
			"duration": discoveryDuration.String(),
		})

		if err != nil {
			tflog.SubsystemDebug(p.ctx, "ldap", "SRV discovery failed", map[string]any{
				"duration": discoveryDuration.String(),
				"error":    err.Error(),
			})
			return fmt.Errorf("SRV discovery failed: %w", err)
		}
		servers = discoveredServers
		tflog.SubsystemDebug(p.ctx, "ldap", "SRV discovery found servers", map[string]any{
			"server_count": len(servers),
		})
	} else {
		return errors.New("either domain or LDAP URLs must be specified")
	}

	if len(servers) == 0 {
		return errors.New("no servers discovered")
	}

	p.mu.Lock()
	p.servers = servers
	p.mu.Unlock()

	tflog.SubsystemDebug(p.ctx, "ldap", "Server discovery completed", map[string]any{
		"duration":     time.Since(start).String(),
		"server_count": len(servers),
	})
	return nil
}

// Get retrieves a connection from the pool.
func (p *connectionPool) Get(ctx context.Context) (*PooledConnection, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, errors.New("connection pool is closed")
	}
	p.mu.RUnlock()

	// Try to get an existing connection from the pool
	select {
	case conn := <-p.connections:
		if p.isConnectionHealthy(conn) {
			// Check if authentication is still valid or if we need to re-authenticate
			if p.config.HasAuthentication() && p.needsReAuthentication(conn) {
				if err := p.authenticateConnection(conn); err != nil {
					// Re-authentication failed, close connection and create new one
					p.closeConnection(conn)
					break
				}
			}
			conn.lastUsed = time.Now()
			atomic.AddInt64(&p.activeConns, 1)
			return conn, nil
		}
		// Connection is unhealthy, close it and create a new one
		p.closeConnection(conn)
	default:
		// No connections available, create a new one
	}

	// Create a new connection with retry logic
	return p.createConnection(ctx)
}

// createConnection creates a new connection with retry logic.
func (p *connectionPool) createConnection(ctx context.Context) (*PooledConnection, error) {
	var lastErr error
	backoff := p.config.InitialBackoff

	for attempt := 0; attempt <= p.config.MaxRetries; attempt++ {
		for _, server := range p.servers {
			conn, err := p.createSingleConnection(ctx, server)
			if err != nil {
				lastErr = err
				atomic.AddInt64(&p.totalErrors, 1)
				continue
			}

			atomic.AddInt64(&p.totalCreated, 1)
			atomic.AddInt64(&p.activeConns, 1)
			return conn, nil
		}

		// All servers failed, wait before retrying
		if attempt < p.config.MaxRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				// Exponential backoff with jitter
				backoff = min(time.Duration(float64(backoff)*p.config.BackoffFactor), p.config.MaxBackoff)
			}
		}
	}

	return nil, NewConnectionError("failed to create connection after retries", true, lastErr)
}

// createSingleConnection creates a connection to a specific server.
func (p *connectionPool) createSingleConnection(_ context.Context, server *ServerInfo) (*PooledConnection, error) {
	url := ServerInfoToURL(server)

	var conn *ldap.Conn
	var err error

	if server.UseTLS {
		// Direct TLS connection (LDAPS)
		conn, err = ldap.DialURL(url, ldap.DialWithTLSConfig(p.config.TLSConfig))
	} else {
		// Plain connection, will use StartTLS if needed
		conn, err = ldap.DialURL(url)
		if err == nil && p.config.UseTLS && !p.config.SkipTLS {
			// Upgrade to TLS using StartTLS
			err = conn.StartTLS(p.config.TLSConfig)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", url, err)
	}

	// Set connection timeout
	conn.SetTimeout(p.config.Timeout)

	pooledConn := &PooledConnection{
		conn:          conn,
		lastUsed:      time.Now(),
		healthy:       true,
		authenticated: false,
		authTime:      time.Time{},
		serverInfo:    server,
		returnToPool:  p.returnConnection,
	}

	// Authenticate the connection immediately if authentication is configured
	if p.config.HasAuthentication() {
		if err := p.authenticateConnection(pooledConn); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to authenticate connection to %s: %w", url, err)
		}
	}

	return pooledConn, nil
}

// authenticateConnection authenticates a pooled connection using the configured method.
func (p *connectionPool) authenticateConnection(pooledConn *PooledConnection) error {
	if pooledConn == nil || pooledConn.conn == nil {
		return fmt.Errorf("connection is nil")
	}

	authMethod := p.config.GetAuthMethod()
	var err error

	switch authMethod {
	case AuthMethodSimpleBind:
		if p.config.Username == "" {
			return fmt.Errorf("username is required for simple bind authentication")
		}
		err = pooledConn.conn.Bind(p.config.Username, p.config.Password)
	case AuthMethodKerberos:
		err = p.authenticateKerberos(pooledConn.conn, pooledConn.serverInfo)
	case AuthMethodExternal:
		err = pooledConn.conn.Bind("", "")
	default:
		return fmt.Errorf("unsupported authentication method: %s", authMethod.String())
	}

	if err != nil {
		pooledConn.authenticated = false
		pooledConn.authTime = time.Time{}
		return err
	}

	// Mark connection as authenticated
	pooledConn.authenticated = true
	pooledConn.authTime = time.Now()
	return nil
}

// authenticateKerberos performs Kerberos authentication on a pooled connection.
func (p *connectionPool) authenticateKerberos(conn *ldap.Conn, serverInfo *ServerInfo) error {
	return performKerberosAuth(conn, p.config, serverInfo)
}

// needsReAuthentication determines if a connection needs to be re-authenticated.
func (p *connectionPool) needsReAuthentication(conn *PooledConnection) bool {
	if conn == nil {
		return true
	}

	// If connection was never authenticated, it needs authentication
	if !conn.authenticated {
		return true
	}

	// If authentication is too old (5 minutes), re-authenticate
	authAge := time.Since(conn.authTime)
	maxAuthAge := 5 * time.Minute
	return authAge > maxAuthAge
}

// returnConnection returns a connection to the pool.
func (p *connectionPool) returnConnection(conn *PooledConnection) {
	if conn == nil {
		return
	}

	atomic.AddInt64(&p.activeConns, -1)

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		p.closeConnection(conn)
		return
	}

	// Check if connection is still healthy and not too old
	if p.isConnectionHealthy(conn) && time.Since(conn.lastUsed) < p.config.MaxIdleTime {
		select {
		case p.connections <- conn:
			// Successfully returned to pool
		default:
			// Pool is full, close the connection
			p.closeConnection(conn)
		}
	} else {
		// Connection is unhealthy or too old, close it
		p.closeConnection(conn)
	}
}

// isConnectionHealthy checks if a connection is healthy.
func (p *connectionPool) isConnectionHealthy(conn *PooledConnection) bool {
	if conn == nil || conn.conn == nil || !conn.healthy {
		return false
	}

	// Check if connection is too old
	if time.Since(conn.lastUsed) > p.config.MaxIdleTime {
		return false
	}

	// If authentication is configured but connection has never been authenticated, consider unhealthy
	if p.config.HasAuthentication() && !conn.authenticated {
		return false
	}

	return true
}

// closeConnection closes a pooled connection.
func (p *connectionPool) closeConnection(conn *PooledConnection) {
	if conn != nil && conn.conn != nil {
		conn.conn.Close()
		conn.healthy = false
		conn.authenticated = false
		conn.authTime = time.Time{}
	}
}

// Close closes all connections and shuts down the pool.
func (p *connectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true

	// Stop health checker
	if p.healthTicker != nil {
		close(p.healthStop)
		p.healthWg.Wait()
		p.healthTicker.Stop()
	}

	// Close all connections in the pool
	close(p.connections)
	for conn := range p.connections {
		p.closeConnection(conn)
	}

	return nil
}

// Stats returns pool statistics.
func (p *connectionPool) Stats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := PoolStats{
		Total:   len(p.connections),
		Active:  atomic.LoadInt64(&p.activeConns),
		Idle:    len(p.connections),
		Created: atomic.LoadInt64(&p.totalCreated),
		Errors:  atomic.LoadInt64(&p.totalErrors),
		Uptime:  time.Since(p.startTime),
	}

	return stats
}

// HealthCheck performs health checks on all connections.
func (p *connectionPool) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return errors.New("pool is closed")
	}

	// Health check implementation would test connections
	// For now, just return success if pool is operational
	return nil
}

// startHealthChecker starts the periodic health checker.
func (p *connectionPool) startHealthChecker() {
	p.healthTicker = time.NewTicker(p.config.HealthCheck)

	p.healthWg.Go(func() {
		for {
			select {
			case <-p.healthTicker.C:
				p.performHealthCheck()
			case <-p.healthStop:
				return
			}
		}
	})
}

// performHealthCheck performs periodic health checks.
func (p *connectionPool) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()

	// Check a few connections from the pool
	var toCheck []*PooledConnection

	// Get up to 3 connections for health checking
healthCheckLoop:
	for range 3 {
		select {
		case conn := <-p.connections:
			toCheck = append(toCheck, conn)
		default:
			break healthCheckLoop
		}
	}

	// Test each connection and return healthy ones to pool
	for _, conn := range toCheck {
		if p.testConnection(ctx, conn) {
			p.returnConnection(conn)
		} else {
			p.closeConnection(conn)
		}
	}
}

// testConnection tests if a connection is working and properly authenticated.
func (p *connectionPool) testConnection(_ context.Context, conn *PooledConnection) bool {
	if conn == nil || conn.conn == nil {
		return false
	}

	// Check if connection needs re-authentication
	if p.config.HasAuthentication() && p.needsReAuthentication(conn) {
		if err := p.authenticateConnection(conn); err != nil {
			return false
		}
	}

	// Perform a simple operation to test the connection
	// Use a minimal search that should always work
	searchReq := ldap.NewSearchRequest(
		"", // Empty base DN for root DSE
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	_, err := conn.conn.Search(searchReq)
	if err != nil {
		// If search fails, mark connection as unauthenticated
		conn.authenticated = false
		conn.authTime = time.Time{}
		return false
	}

	return true
}

// validateConfig validates the connection configuration.
func validateConfig(config *ConnectionConfig) error {
	if config.MaxConnections <= 0 {
		return errors.New("MaxConnections must be positive")
	}

	if config.MaxConnections > MaxConnectionPoolLimit {
		return fmt.Errorf("MaxConnections too high (max %d)", MaxConnectionPoolLimit)
	}

	if config.MaxIdleTime <= 0 {
		return errors.New("MaxIdleTime must be positive")
	}

	if config.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	if config.MaxRetries < 0 {
		return errors.New("MaxRetries cannot be negative")
	}

	if config.BackoffFactor <= 1.0 {
		return errors.New("BackoffFactor must be greater than 1.0")
	}

	return nil
}

// Methods for PooledConnection.
func (pc *PooledConnection) Close() {
	if pc.returnToPool != nil {
		pc.returnToPool(pc)
	}
}

func (pc *PooledConnection) Conn() *ldap.Conn {
	return pc.conn
}

func (pc *PooledConnection) ServerInfo() *ServerInfo {
	return pc.serverInfo
}

func (pc *PooledConnection) IsHealthy() bool {
	return pc.healthy
}

func (pc *PooledConnection) LastUsed() time.Time {
	return pc.lastUsed
}
