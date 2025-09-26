package ldap

import (
	"context"
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
