package ldap

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ConnectionConfig holds configuration for LDAP connections.
type ConnectionConfig struct {
	// Connection settings
	Domain   string        // Domain for SRV discovery
	LDAPURLs []string      // Direct LDAP URLs (overrides domain)
	BaseDN   string        // Base DN for searches
	Timeout  time.Duration // Connection timeout

	// Authentication settings
	Username       string // Username for authentication (DN, UPN, or SAM format)
	Password       string // Password for simple bind authentication
	KerberosRealm  string // Kerberos realm for GSSAPI authentication
	KerberosKeytab string // Path to Kerberos keytab file
	KerberosConfig string // Path to Kerberos config file (krb5.conf)

	// TLS settings
	TLSConfig         *tls.Config // Custom TLS configuration
	UseTLS            bool        // Force TLS usage
	SkipTLS           bool        // Skip TLS entirely (not recommended)
	TLSCACertFile     string      // Path to CA certificate file
	TLSCACert         string      // CA certificate content
	TLSClientCertFile string      // Path to client certificate file
	TLSClientKeyFile  string      // Path to client private key file

	// Pool settings
	MaxConnections int           // Maximum connections in pool
	MaxIdleTime    time.Duration // Maximum idle time before connection cleanup
	HealthCheck    time.Duration // Health check interval

	// Retry settings
	MaxRetries     int           // Maximum retry attempts
	InitialBackoff time.Duration // Initial backoff duration
	MaxBackoff     time.Duration // Maximum backoff duration
	BackoffFactor  float64       // Backoff multiplication factor
}

// DefaultConfig returns a secure default configuration.
func DefaultConfig() *ConnectionConfig {
	return &ConnectionConfig{
		Timeout:        30 * time.Second,
		UseTLS:         true,
		MaxConnections: 10,
		MaxIdleTime:    5 * time.Minute,
		HealthCheck:    30 * time.Second,
		MaxRetries:     3,
		InitialBackoff: 500 * time.Millisecond,
		MaxBackoff:     30 * time.Second,
		BackoffFactor:  2.0,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Certificate validation enabled by default
			InsecureSkipVerify: false,
		},
	}
}

// PooledConnection represents a connection in the pool.
type PooledConnection struct {
	conn         *ldap.Conn
	lastUsed     time.Time
	healthy      bool
	serverInfo   *ServerInfo
	returnToPool func(*PooledConnection)
}

// ServerInfo contains information about an LDAP server.
type ServerInfo struct {
	Host     string
	Port     int
	UseTLS   bool
	Priority int
	Weight   int
	Source   string // "srv", "config", "fallback"
}

// ConnectionPool manages a pool of LDAP connections.
type ConnectionPool interface {
	// Get retrieves a connection from the pool
	Get(ctx context.Context) (*PooledConnection, error)

	// Close closes all connections and shuts down the pool
	Close() error

	// Stats returns pool statistics
	Stats() PoolStats

	// HealthCheck performs health checks on all connections
	HealthCheck(ctx context.Context) error
}

// PoolStats provides statistics about the connection pool.
type PoolStats struct {
	Total     int           // Total connections
	Active    int64         // Active (in-use) connections
	Idle      int           // Idle connections
	Unhealthy int           // Unhealthy connections
	Created   int64         // Total connections created
	Errors    int64         // Total connection errors
	Uptime    time.Duration // Pool uptime
}

// Client provides high-level LDAP operations.
type Client interface {
	// Connection management
	Connect(ctx context.Context) error
	Close() error

	// Authentication
	Bind(ctx context.Context, username, password string) error
	BindWithConfig(ctx context.Context) error // Uses authentication from ConnectionConfig

	// Basic operations
	Search(ctx context.Context, req *SearchRequest) (*SearchResult, error)
	Add(ctx context.Context, req *AddRequest) error
	Modify(ctx context.Context, req *ModifyRequest) error
	Delete(ctx context.Context, dn string) error

	// Health and statistics
	Ping(ctx context.Context) error
	Stats() PoolStats
}

// SearchRequest encapsulates LDAP search parameters.
type SearchRequest struct {
	BaseDN       string
	Scope        SearchScope
	Filter       string
	Attributes   []string
	SizeLimit    int
	TimeLimit    time.Duration
	DerefAliases DerefAliases
}

// SearchResult contains search results and metadata.
type SearchResult struct {
	Entries []*ldap.Entry
	Total   int
	HasMore bool
}

// AddRequest encapsulates LDAP add parameters.
type AddRequest struct {
	DN         string
	Attributes map[string][]string
}

// ModifyRequest encapsulates LDAP modify parameters.
type ModifyRequest struct {
	DN                string
	AddAttributes     map[string][]string
	ReplaceAttributes map[string][]string
	DeleteAttributes  []string
}

// SearchScope defines LDAP search scope.
type SearchScope int

const (
	ScopeBaseObject SearchScope = iota
	ScopeSingleLevel
	ScopeWholeSubtree
)

// DerefAliases defines alias dereferencing behavior.
type DerefAliases int

const (
	NeverDerefAliases DerefAliases = iota
	DerefInSearching
	DerefFindingBaseObj
	DerefAlways
)

// AuthMethod defines authentication method types.
type AuthMethod int

const (
	AuthMethodSimpleBind AuthMethod = iota // Username/password authentication
	AuthMethodKerberos                     // GSSAPI/Kerberos authentication
	AuthMethodExternal                     // External/certificate authentication
)

// String returns string representation of authentication method.
func (a AuthMethod) String() string {
	switch a {
	case AuthMethodSimpleBind:
		return "simple"
	case AuthMethodKerberos:
		return "kerberos"
	case AuthMethodExternal:
		return "external"
	default:
		return "unknown"
	}
}

// GetAuthMethod determines the authentication method from the configuration.
func (c *ConnectionConfig) GetAuthMethod() AuthMethod {
	// Kerberos authentication takes precedence
	if c.KerberosRealm != "" && (c.KerberosKeytab != "" || c.Username != "") {
		return AuthMethodKerberos
	}

	// Simple bind authentication
	if c.Username != "" && c.Password != "" {
		return AuthMethodSimpleBind
	}

	// External authentication (certificates)
	if c.TLSClientCertFile != "" && c.TLSClientKeyFile != "" {
		return AuthMethodExternal
	}

	// Default to simple bind if we have a username
	if c.Username != "" {
		return AuthMethodSimpleBind
	}

	return AuthMethodSimpleBind
}

// HasAuthentication checks if any authentication method is configured.
func (c *ConnectionConfig) HasAuthentication() bool {
	hasPassword := c.Username != "" && c.Password != ""
	hasKerberos := c.KerberosRealm != "" && (c.KerberosKeytab != "" || c.Username != "")
	hasExternal := c.TLSClientCertFile != "" && c.TLSClientKeyFile != ""

	return hasPassword || hasKerberos || hasExternal
}

// RetryableError indicates an error that can be retried.
type RetryableError interface {
	error
	IsRetryable() bool
}

// ConnectionError represents connection-related errors.
type ConnectionError struct {
	message   string
	retryable bool
	cause     error
}

func (e *ConnectionError) Error() string {
	if e.cause != nil {
		return e.message + ": " + e.cause.Error()
	}
	return e.message
}

func (e *ConnectionError) IsRetryable() bool {
	return e.retryable
}

func (e *ConnectionError) Unwrap() error {
	return e.cause
}

// NewConnectionError creates a new connection error.
func NewConnectionError(message string, retryable bool, cause error) *ConnectionError {
	return &ConnectionError{
		message:   message,
		retryable: retryable,
		cause:     cause,
	}
}
