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

	_, err := NewConnectionPool(context.Background(), config)
	if err == nil {
		t.Error("Expected error when creating pool without domain or URLs")
	}
}

func TestConnectionPool_CreateWithURLs(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636", "ldap://dc2.example.com:389"}
	config.Domain = "" // Should use URLs instead of domain

	pool, err := NewConnectionPool(context.Background(), config)
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

	_, err := NewConnectionPool(context.Background(), config)
	if err == nil {
		t.Error("Expected error when creating pool with invalid URL")
	}
}

func TestConnectionPool_Stats(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	pool, err := NewConnectionPool(context.Background(), config)
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

	pool, err := NewConnectionPool(context.Background(), config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	// Close immediately
	err = pool.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Try to get connection from closed pool
	ctx := context.Background()
	_, err = pool.Get(ctx)
	if err == nil {
		t.Error("Expected error when getting connection from closed pool")
	}
}

func TestConnectionPool_DoubleClose(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	pool, err := NewConnectionPool(context.Background(), config)
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
		pool, err := NewConnectionPool(context.Background(), config)
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

	pool, err := NewConnectionPool(context.Background(), config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Verify that RootCAs was set
	if config.TLSConfig.RootCAs == nil {
		t.Error("TLSConfig.RootCAs should be set by NewConnectionPool")
	}
}
