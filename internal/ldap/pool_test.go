package ldap

import (
	"context"
	"crypto/tls"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig() returned nil")
		return
	}

	// Verify security defaults
	if !config.UseTLS {
		t.Error("Default config should use TLS")
	}

	if config.SkipTLS {
		t.Error("Default config should not skip TLS")
	}

	if config.TLSConfig == nil {
		t.Error("Default config should have TLS config")
	}

	if config.TLSConfig.InsecureSkipVerify {
		t.Error("Default config should validate certificates")
	}

	// Verify reasonable defaults
	if config.MaxConnections != 10 {
		t.Errorf("MaxConnections = %d, want 10", config.MaxConnections)
	}

	if config.MaxIdleTime != 5*time.Minute {
		t.Errorf("MaxIdleTime = %v, want 5m", config.MaxIdleTime)
	}

	if config.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", config.Timeout)
	}

	if config.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", config.MaxRetries)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *ConnectionConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "zero max connections",
			config: &ConnectionConfig{
				MaxConnections: 0,
				MaxIdleTime:    5 * time.Minute,
				Timeout:        30 * time.Second,
				MaxRetries:     3,
				BackoffFactor:  2.0,
			},
			wantErr: true,
		},
		{
			name: "too many max connections",
			config: &ConnectionConfig{
				MaxConnections: 200,
				MaxIdleTime:    5 * time.Minute,
				Timeout:        30 * time.Second,
				MaxRetries:     3,
				BackoffFactor:  2.0,
			},
			wantErr: true,
		},
		{
			name: "zero max idle time",
			config: &ConnectionConfig{
				MaxConnections: 10,
				MaxIdleTime:    0,
				Timeout:        30 * time.Second,
				MaxRetries:     3,
				BackoffFactor:  2.0,
			},
			wantErr: true,
		},
		{
			name: "zero timeout",
			config: &ConnectionConfig{
				MaxConnections: 10,
				MaxIdleTime:    5 * time.Minute,
				Timeout:        0,
				MaxRetries:     3,
				BackoffFactor:  2.0,
			},
			wantErr: true,
		},
		{
			name: "negative max retries",
			config: &ConnectionConfig{
				MaxConnections: 10,
				MaxIdleTime:    5 * time.Minute,
				Timeout:        30 * time.Second,
				MaxRetries:     -1,
				BackoffFactor:  2.0,
			},
			wantErr: true,
		},
		{
			name: "invalid backoff factor",
			config: &ConnectionConfig{
				MaxConnections: 10,
				MaxIdleTime:    5 * time.Minute,
				Timeout:        30 * time.Second,
				MaxRetries:     3,
				BackoffFactor:  1.0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)

			if tt.wantErr && err == nil {
				t.Errorf("validateConfig() expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("validateConfig() unexpected error: %v", err)
			}
		})
	}
}

func TestConnectionPool_CreateWithInvalidConfig(t *testing.T) {
	// Test pool creation with no domain or URLs
	config := DefaultConfig()
	config.Domain = ""
	config.LDAPURLs = nil

	_, err := NewConnectionPool(t.Context(), config)
	if err == nil {
		t.Error("Expected error when creating pool without domain or URLs")
	}
}

func TestConnectionPool_CreateWithURLs(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636", "ldap://dc2.example.com:389"}
	config.Domain = "" // Should use URLs instead of domain

	pool, err := NewConnectionPool(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create pool with URLs: %v", err)
	}

	if pool == nil {
		t.Fatal("Pool creation returned nil")
	}

	// Clean up
	pool.Close()
}

func TestConnectionPool_CreateWithInvalidURL(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"invalid://dc1.example.com"}
	config.Domain = ""

	_, err := NewConnectionPool(t.Context(), config)
	if err == nil {
		t.Error("Expected error when creating pool with invalid URL")
	}
}

func TestConnectionPool_Stats(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	pool, err := NewConnectionPool(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	stats := pool.Stats()

	// Initially should have zero active connections
	if stats.Active != 0 {
		t.Errorf("Initial active connections = %d, want 0", stats.Active)
	}

	if stats.Created != 0 {
		t.Errorf("Initial created connections = %d, want 0", stats.Created)
	}

	if stats.Uptime <= 0 {
		t.Errorf("Uptime should be positive, got %v", stats.Uptime)
	}
}

func TestConnectionPool_CloseBeforeUse(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	pool, err := NewConnectionPool(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	// Close immediately
	err = pool.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Try to get connection from closed pool
	ctx := t.Context()
	_, err = pool.Get(ctx)
	if err == nil {
		t.Error("Expected error when getting connection from closed pool")
	}
}

func TestConnectionPool_DoubleClose(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	pool, err := NewConnectionPool(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	// Close twice
	err1 := pool.Close()
	err2 := pool.Close()

	if err1 != nil {
		t.Errorf("First close failed: %v", err1)
	}

	if err2 != nil {
		t.Errorf("Second close failed: %v", err2)
	}
}

func TestPooledConnection_Methods(t *testing.T) {
	serverInfo := &ServerInfo{
		Host:   "dc1.example.com",
		Port:   636,
		UseTLS: true,
		Source: "test",
	}

	conn := &PooledConnection{
		conn:       nil, // We can't create a real connection in unit tests
		lastUsed:   time.Now(),
		healthy:    true,
		serverInfo: serverInfo,
	}

	// Test methods
	if conn.ServerInfo() != serverInfo {
		t.Error("ServerInfo() returned wrong value")
	}

	if !conn.IsHealthy() {
		t.Error("IsHealthy() should return true")
	}

	if conn.LastUsed().IsZero() {
		t.Error("LastUsed() should not be zero")
	}

	// Test Close() doesn't panic with nil returnToPool
	conn.Close() // Should not panic
}

func TestConnectionError(t *testing.T) {
	err := NewConnectionError("test operation failed", true, nil)

	if err.Error() != "test operation failed" {
		t.Errorf("Error() = %s, want 'test operation failed'", err.Error())
	}

	if !err.IsRetryable() {
		t.Error("Error should be retryable")
	}

	// Test with cause
	cause := NewConnectionError("underlying error", false, nil)
	wrapped := NewConnectionError("wrapped error", true, cause)

	if wrapped.Unwrap() != cause {
		t.Error("Unwrap() should return the cause")
	}
}

// Benchmarks

func BenchmarkConnectionPool_Creation(b *testing.B) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	for b.Loop() {
		pool, err := NewConnectionPool(b.Context(), config)
		if err != nil {
			b.Fatalf("Failed to create pool: %v", err)
		}
		pool.Close()
	}
}

func BenchmarkValidateConfig(b *testing.B) {
	config := DefaultConfig()

	for b.Loop() {
		err := validateConfig(config)
		if err != nil {
			b.Fatalf("Config validation failed: %v", err)
		}
	}
}

func BenchmarkServerInfoToURL(b *testing.B) {
	server := &ServerInfo{
		Host:   "dc1.example.com",
		Port:   636,
		UseTLS: true,
	}

	for b.Loop() {
		url := ServerInfoToURL(server)
		_ = url
	}
}

func TestTLSConfigServerName(t *testing.T) {
	tests := []struct {
		name               string
		serverHost         string
		tlsConfig          *tls.Config
		wantServerName     string
		skipServerNameTest bool
	}{
		{
			name:           "TLS config with certificate validation",
			serverHost:     "dc1.example.com",
			tlsConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
			wantServerName: "dc1.example.com",
		},
		{
			name:           "TLS config with FQDN",
			serverHost:     "dc-ws19-dc2.nexthink.local",
			tlsConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
			wantServerName: "dc-ws19-dc2.nexthink.local",
		},
		{
			name:               "TLS config with InsecureSkipVerify should not set ServerName",
			serverHost:         "dc1.example.com",
			tlsConfig:          &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
			skipServerNameTest: true,
		},
		{
			name:               "nil TLS config should not cause panic",
			serverHost:         "dc1.example.com",
			tlsConfig:          nil,
			skipServerNameTest: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal config for testing
			config := &ConnectionConfig{
				LDAPURLs:       []string{"ldap://test.example.com:389"},
				TLSConfig:      tt.tlsConfig,
				MaxConnections: 1,
				MaxIdleTime:    5 * time.Minute,
				Timeout:        30 * time.Second,
				MaxRetries:     0, // No retries for this test
				BackoffFactor:  2.0,
			}

			// Create server info
			server := &ServerInfo{
				Host:   tt.serverHost,
				Port:   636,
				UseTLS: true,
			}

			// Test the TLS config preparation logic (same as in createSingleConnection)
			var tlsConfig *tls.Config
			if config.TLSConfig != nil {
				tlsConfig = config.TLSConfig.Clone()
				if !tlsConfig.InsecureSkipVerify {
					tlsConfig.ServerName = server.Host
				}
			}

			// Verify the results
			if tt.skipServerNameTest {
				// For nil config or InsecureSkipVerify, just ensure we don't panic
				if tt.tlsConfig != nil && tt.tlsConfig.InsecureSkipVerify {
					if tlsConfig.ServerName != "" {
						t.Errorf("ServerName should not be set when InsecureSkipVerify is true, got %s", tlsConfig.ServerName)
					}
				}
			} else {
				if tlsConfig == nil {
					t.Fatal("TLS config should not be nil")
					return
				}
				if tlsConfig.ServerName != tt.wantServerName {
					t.Errorf("ServerName = %s, want %s", tlsConfig.ServerName, tt.wantServerName)
				}
				// Verify it's a clone, not the same reference
				if tt.tlsConfig != nil && tlsConfig == tt.tlsConfig {
					t.Error("TLS config should be cloned, not the same reference")
				}
			}
		})
	}
}

func TestDefaultConfigHasTLSConfig(t *testing.T) {
	// This test ensures that the default config always has a TLS config
	// so that ServerName can be set properly
	config := DefaultConfig()

	if config.TLSConfig == nil {
		t.Fatal("Default config must have TLSConfig initialized")
	}

	if config.TLSConfig.InsecureSkipVerify {
		t.Error("Default config should not skip TLS verification")
	}

	// Verify the config can be cloned without panic
	cloned := config.TLSConfig.Clone()
	if cloned == nil {
		t.Error("TLS config should be cloneable")
	}
}

func TestBuildCertPool_SystemOnly(t *testing.T) {
	// Test that buildCertPool returns system cert pool when no custom CA is specified
	pool, err := buildCertPool("", "")
	if err != nil {
		t.Fatalf("buildCertPool() failed: %v", err)
	}

	if pool == nil {
		t.Fatal("buildCertPool() returned nil pool")
	}

	// We can't easily verify the contents of the system cert pool,
	// but we can verify it's not empty on most systems
	// (this test might be platform-dependent)
}

func TestBuildCertPool_WithContent(t *testing.T) {
	// Valid test CA certificate (self-signed, for testing only)
	testCACert := `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUF3pBeK7vWjkiOn5vkdviUpPSZDIwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNTEwMjQxNzM3NDNaFw0yNjEwMjQx
NzM3NDNaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDcyerW4aUDqSKC9QPHuL1wZadQqNOP97LwivFl0rnJ1TTUw8Xn
qX+V16tViOSuPq+tp4vxLDE4Sv0dJbXm35+7mb9xkmJFvIQaP8wQweza/k/GnkuM
pCM9voUpxC2wDnNSenw46L0eTdFPyXDTDRQR8vbS85OektHdsSgMwxubugS0CihD
WlIKYZnvpLPrvjBoplfS5Ff3gdse2d5K9qzl4Vs+KDyfxJegML9ATmPnXWLkyl13
3WjV/rjlQrxqtIJH+APUVyGBCNe+LtymOHeIy+FMX3JpKV1CLGyVoQ1sowzgm17D
wgErA2L6/quQpkNKNuoZSuDbFdJBiHyGWNsRAgMBAAGjUzBRMB0GA1UdDgQWBBRg
vCPlMaoj4A/WZxqd7kvtbfQpZTAfBgNVHSMEGDAWgBRgvCPlMaoj4A/WZxqd7kvt
bfQpZTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBFbrOXuzvE
pdNN/f64PpkJakfrWGXAR4xhZul+2lXgJQd0iq7mEOkWpPlOq8/UeDTlLfOSPcDw
FrQuODeDQeUmeglZvvmJIinOzFYf4wsxaJNqdQoF3bwY6UmUWlABDoRvVkWHFMwA
VpAD/4I2VNcE+Mqe03Lx0UO+xkZ74KzHrEwKpYcPP4J3K78S16NAlz3MaH4eLRWK
yVZWTBLVmuIFB5ITwdrdL92vdP6IQoXYOSrFDyhXkSoB+UxgaZwDji2wnYw3KZrm
aomYL4gPZz6Cnw2euSkQEY64gm/e1ueJDarBkzWUFUhmTMTJ/XRJpnhdu5FTqwKj
eNsm2nzlwhTR
-----END CERTIFICATE-----`

	pool, err := buildCertPool("", testCACert)
	if err != nil {
		t.Fatalf("buildCertPool() with content failed: %v", err)
	}

	if pool == nil {
		t.Fatal("buildCertPool() returned nil pool")
	}
}

func TestBuildCertPool_WithFile(t *testing.T) {
	// Create a temporary CA cert file
	testCACert := `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUF3pBeK7vWjkiOn5vkdviUpPSZDIwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNTEwMjQxNzM3NDNaFw0yNjEwMjQx
NzM3NDNaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDcyerW4aUDqSKC9QPHuL1wZadQqNOP97LwivFl0rnJ1TTUw8Xn
qX+V16tViOSuPq+tp4vxLDE4Sv0dJbXm35+7mb9xkmJFvIQaP8wQweza/k/GnkuM
pCM9voUpxC2wDnNSenw46L0eTdFPyXDTDRQR8vbS85OektHdsSgMwxubugS0CihD
WlIKYZnvpLPrvjBoplfS5Ff3gdse2d5K9qzl4Vs+KDyfxJegML9ATmPnXWLkyl13
3WjV/rjlQrxqtIJH+APUVyGBCNe+LtymOHeIy+FMX3JpKV1CLGyVoQ1sowzgm17D
wgErA2L6/quQpkNKNuoZSuDbFdJBiHyGWNsRAgMBAAGjUzBRMB0GA1UdDgQWBBRg
vCPlMaoj4A/WZxqd7kvtbfQpZTAfBgNVHSMEGDAWgBRgvCPlMaoj4A/WZxqd7kvt
bfQpZTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBFbrOXuzvE
pdNN/f64PpkJakfrWGXAR4xhZul+2lXgJQd0iq7mEOkWpPlOq8/UeDTlLfOSPcDw
FrQuODeDQeUmeglZvvmJIinOzFYf4wsxaJNqdQoF3bwY6UmUWlABDoRvVkWHFMwA
VpAD/4I2VNcE+Mqe03Lx0UO+xkZ74KzHrEwKpYcPP4J3K78S16NAlz3MaH4eLRWK
yVZWTBLVmuIFB5ITwdrdL92vdP6IQoXYOSrFDyhXkSoB+UxgaZwDji2wnYw3KZrm
aomYL4gPZz6Cnw2euSkQEY64gm/e1ueJDarBkzWUFUhmTMTJ/XRJpnhdu5FTqwKj
eNsm2nzlwhTR
-----END CERTIFICATE-----`

	tmpFile, err := os.CreateTemp(t.TempDir(), "test-ca-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.Write([]byte(testCACert)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	pool, err := buildCertPool(tmpFile.Name(), "")
	if err != nil {
		t.Fatalf("buildCertPool() with file failed: %v", err)
	}

	if pool == nil {
		t.Fatal("buildCertPool() returned nil pool")
	}
}

func TestBuildCertPool_InvalidPEM(t *testing.T) {
	invalidPEM := "this is not valid PEM content"

	_, err := buildCertPool("", invalidPEM)
	if err == nil {
		t.Error("buildCertPool() should fail with invalid PEM")
	}

	if err != nil && !strings.Contains(err.Error(), "invalid PEM format") {
		t.Errorf("Expected 'invalid PEM format' error, got: %v", err)
	}
}

func TestBuildCertPool_FileNotFound(t *testing.T) {
	_, err := buildCertPool("/nonexistent/path/to/ca.pem", "")
	if err == nil {
		t.Error("buildCertPool() should fail with nonexistent file")
	}

	if err != nil && !strings.Contains(err.Error(), "failed to read CA certificate file") {
		t.Errorf("Expected 'failed to read CA certificate file' error, got: %v", err)
	}
}

func TestNewConnectionPool_CertPoolSet(t *testing.T) {
	// Test that NewConnectionPool sets RootCAs in TLS config
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	pool, err := NewConnectionPool(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Verify that RootCAs was set
	if config.TLSConfig.RootCAs == nil {
		t.Error("TLSConfig.RootCAs should be set by NewConnectionPool")
	}
}

// TestConnectionPool_ReuseAfterReturn verifies that a healthy connection
// returned to the pool via PooledConnection.Close() is handed back out by
// the next call to Get(). Identity is checked via pointer equality to
// prove the same underlying PooledConnection was reused rather than a
// fresh one created.
func TestConnectionPool_ReuseAfterReturn(t *testing.T) {
	pool := newTestPool(t, 4)

	// Pre-populate the idle channel with a known connection so that Get()
	// has no reason to dial a real server.
	pc := newHealthyPooled(t, pool)
	pool.connections <- pc

	first, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("first Get() failed: %v", err)
	}
	if first != pc {
		t.Fatalf("expected the pre-populated connection, got %p (want %p)", first, pc)
	}

	// Return the connection.
	first.Close()

	// Next Get() should recycle the same connection.
	second, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("second Get() failed: %v", err)
	}
	if second != first {
		t.Fatalf("expected connection reuse: got %p, want %p", second, first)
	}

	// Return again so Close() doesn't leak it on pool shutdown.
	second.Close()
}

// TestConnectionPool_MaxConnections_IdleCapOnly documents the pool's
// actual behaviour when MaxConnections worth of connections have been
// handed out: the pool does NOT block or return ErrPoolExhausted. Instead,
// MaxConnections is the cap on the IDLE buffer size — Get() will always
// attempt to create a new connection when the idle channel is empty.
//
// This test captures that contract: if the production behaviour ever
// changes to (e.g.) bounded concurrency with blocking, this test should
// be updated to match the new documented semantics.
func TestConnectionPool_MaxConnections_IdleCapOnly(t *testing.T) {
	maxConns := 2
	pool := newTestPool(t, maxConns)

	// Fill the idle channel to capacity with pre-built connections and
	// hand them all out via Get(). The pool should serve all of them
	// without attempting to dial a real server.
	for range maxConns {
		pool.connections <- newHealthyPooled(t, pool)
	}

	acquired := make([]*PooledConnection, 0, maxConns)
	for i := range maxConns {
		conn, err := pool.Get(t.Context())
		if err != nil {
			t.Fatalf("Get #%d failed: %v", i, err)
		}
		acquired = append(acquired, conn)
	}

	// Sanity check: all distinct connections, none nil.
	seen := make(map[*PooledConnection]struct{}, len(acquired))
	for i, c := range acquired {
		if c == nil {
			t.Fatalf("connection #%d is nil", i)
		}
		if _, dup := seen[c]; dup {
			t.Fatalf("connection #%d (%p) was handed out twice", i, c)
		}
		seen[c] = struct{}{}
	}

	// With the idle channel drained and all MaxConnections worth of
	// connections outstanding, the next Get() falls into createConnection,
	// which tries to dial the bogus LDAPURL configured in newTestPool.
	// That dial MUST fail; the pool MUST NOT block indefinitely.
	//
	// We bound the wait with a short context to fail the test rather than
	// hang if the pool were ever changed to block on max-connections.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := pool.Get(ctx)
	if err == nil {
		t.Fatal("Get() past MaxConnections should not succeed against bogus LDAP URL, but returned no error")
	}
	// Error should be about connection creation, not about pool state.
	if strings.Contains(err.Error(), "pool is closed") {
		t.Fatalf("unexpected pool-state error: %v", err)
	}

	// Return everything we acquired so cleanup can close the backing sockets.
	for _, c := range acquired {
		c.Close()
	}
}

// TestConnectionPool_UnhealthyDiscardedOnGet verifies that a connection
// marked unhealthy before return is NOT served back to the next caller.
// Instead, Get() falls through to createConnection (which in this test
// will fail because the configured server is bogus — the important thing
// is that the tainted connection is discarded, not reused).
func TestConnectionPool_UnhealthyDiscardedOnGet(t *testing.T) {
	pool := newTestPool(t, 4)

	// Seed the idle channel with a connection that claims to be healthy,
	// then taint it by flipping the flag to simulate a failed health check.
	bad := newHealthyPooled(t, pool)
	bad.healthy = false
	pool.connections <- bad

	// Put a known-good connection in behind the bad one so we can detect
	// whether the pool skipped past the bad one or not.
	//
	// NOTE: the pool's Get() only inspects ONE connection per call (via
	// non-blocking receive on the channel). So after discarding `bad`, it
	// proceeds to createConnection rather than peeking at the next idle
	// entry. That's fine — what we're asserting is that Get() does NOT
	// return the tainted connection.
	good := newHealthyPooled(t, pool)
	pool.connections <- good

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	got, err := pool.Get(ctx)

	if got == bad {
		t.Fatal("pool returned an unhealthy connection; it should have been discarded")
	}

	// One of two outcomes is acceptable given the current Get() semantics:
	//   (a) err != nil, because the dial attempt (after discarding bad)
	//       failed against the bogus URL — got is nil
	//   (b) err == nil with got != bad — e.g. if Get() were ever changed
	//       to loop through idle entries before dialing
	// Either way: got MUST NOT be the tainted connection.
	if err == nil && got == nil {
		t.Fatal("unexpected: no error but nil connection")
	}
	if got != nil {
		// Clean up — return it so the pool manages its lifecycle.
		got.Close()
	}

	// Drain the good connection so it doesn't leak its socket.
	select {
	case c := <-pool.connections:
		if c != good {
			t.Errorf("expected to drain the good connection, got a different one")
		}
	default:
		// No-op; it may have been consumed in a future Get().
	}
}
