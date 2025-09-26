package ldap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *ConnectionConfig
		wantErr bool
	}{
		{
			name: "default config with URLs",
			config: func() *ConnectionConfig {
				cfg := DefaultConfig()
				cfg.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
				return cfg
			}(),
			wantErr: false,
		},
		{
			name: "valid config with URLs",
			config: &ConnectionConfig{
				LDAPURLs:       []string{"ldaps://dc1.example.com:636"},
				MaxConnections: 5,
				MaxIdleTime:    2 * time.Minute,
				Timeout:        15 * time.Second,
				MaxRetries:     2,
				BackoffFactor:  1.5,
				UseTLS:         true,
			},
			wantErr: false,
		},
		{
			name: "invalid config - no domain or URLs",
			config: &ConnectionConfig{
				Domain:         "",
				LDAPURLs:       nil,
				MaxConnections: 5,
				MaxIdleTime:    2 * time.Minute,
				Timeout:        15 * time.Second,
				MaxRetries:     2,
				BackoffFactor:  2.0,
			},
			wantErr: true,
		},
		{
			name: "invalid config - bad max connections",
			config: &ConnectionConfig{
				LDAPURLs:       []string{"ldaps://dc1.example.com:636"},
				MaxConnections: 0,
				MaxIdleTime:    2 * time.Minute,
				Timeout:        15 * time.Second,
				MaxRetries:     2,
				BackoffFactor:  2.0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(t.Context(), tt.config)

			if tt.wantErr && err == nil {
				t.Errorf("NewClient() expected error but got none")
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("NewClient() unexpected error: %v", err)
				return
			}

			if !tt.wantErr && client != nil {

				// Clean up
				client.Close()
			}
		})
	}
}

func TestClient_Close(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	client, err := NewClient(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test close
	err = client.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Test double close (should not panic or error)
	err = client.Close()
	if err != nil {
		t.Errorf("Second Close() failed: %v", err)
	}
}

func TestClient_Stats(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	client, err := NewClient(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	stats := client.Stats()

	// Should return valid stats structure
	if stats.Uptime <= 0 {
		t.Errorf("Expected positive uptime, got %v", stats.Uptime)
	}

	// Initially should have no active connections
	if stats.Active != 0 {
		t.Errorf("Expected 0 active connections, got %d", stats.Active)
	}
}

func TestSearchRequest_Validation(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	client, err := NewClient(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	tests := []struct {
		name    string
		req     *SearchRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "valid request",
			req: &SearchRequest{
				BaseDN:     "dc=example,dc=com",
				Scope:      ScopeWholeSubtree,
				Filter:     "(objectClass=user)",
				Attributes: []string{"cn", "mail"},
				SizeLimit:  100,
				TimeLimit:  30 * time.Second,
			},
			wantErr: false, // Will fail on connection, but validation should pass
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			_, err := client.Search(ctx, tt.req)

			if tt.wantErr && err == nil {
				t.Errorf("Search() expected error but got none")
			}

			if !tt.wantErr && err == nil {
				t.Error("Search() expected connection error but got none (this might be ok if test environment has LDAP)")
			}

			// For valid requests that fail due to connection issues, verify it's a connection error
			if !tt.wantErr && err != nil {
				if !strings.Contains(strings.ToLower(err.Error()), "connection") &&
					!strings.Contains(strings.ToLower(err.Error()), "dial") &&
					!strings.Contains(strings.ToLower(err.Error()), "network") {
					t.Errorf("Expected connection-related error, got: %v", err)
				}
			}
		})
	}
}

func TestAddRequest_Validation(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	client, err := NewClient(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	tests := []struct {
		name    string
		req     *AddRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "valid request",
			req: &AddRequest{
				DN: "cn=test,dc=example,dc=com",
				Attributes: map[string][]string{
					"objectClass": {"user"},
					"cn":          {"test"},
				},
			},
			wantErr: false, // Will fail on connection, but validation should pass
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			err := client.Add(ctx, tt.req)

			if tt.wantErr && err == nil {
				t.Errorf("Add() expected error but got none")
			}

			// For valid requests, we expect connection errors in test environment
			if !tt.wantErr && err != nil {
				if !strings.Contains(strings.ToLower(err.Error()), "connection") &&
					!strings.Contains(strings.ToLower(err.Error()), "dial") &&
					!strings.Contains(strings.ToLower(err.Error()), "network") {
					t.Errorf("Expected connection-related error, got: %v", err)
				}
			}
		})
	}
}

func TestModifyRequest_Validation(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	client, err := NewClient(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	tests := []struct {
		name    string
		req     *ModifyRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "valid request",
			req: &ModifyRequest{
				DN: "cn=test,dc=example,dc=com",
				AddAttributes: map[string][]string{
					"description": {"test user"},
				},
				ReplaceAttributes: map[string][]string{
					"mail": {"test@example.com"},
				},
				DeleteAttributes: []string{"telephoneNumber"},
			},
			wantErr: false, // Will fail on connection, but validation should pass
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			err := client.Modify(ctx, tt.req)

			if tt.wantErr && err == nil {
				t.Errorf("Modify() expected error but got none")
			}

			// For valid requests, we expect connection errors in test environment
			if !tt.wantErr && err != nil {
				if !strings.Contains(strings.ToLower(err.Error()), "connection") &&
					!strings.Contains(strings.ToLower(err.Error()), "dial") &&
					!strings.Contains(strings.ToLower(err.Error()), "network") {
					t.Errorf("Expected connection-related error, got: %v", err)
				}
			}
		})
	}
}

func TestDelete_Validation(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	client, err := NewClient(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	tests := []struct {
		name    string
		dn      string
		wantErr bool
	}{
		{
			name:    "empty DN",
			dn:      "",
			wantErr: true,
		},
		{
			name:    "valid DN",
			dn:      "cn=test,dc=example,dc=com",
			wantErr: false, // Will fail on connection, but validation should pass
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			err := client.Delete(ctx, tt.dn)

			if tt.wantErr && err == nil {
				t.Errorf("Delete() expected error but got none")
			}

			// For valid requests, we expect connection errors in test environment
			if !tt.wantErr && err != nil {
				if !strings.Contains(strings.ToLower(err.Error()), "connection") &&
					!strings.Contains(strings.ToLower(err.Error()), "dial") &&
					!strings.Contains(strings.ToLower(err.Error()), "network") {
					t.Errorf("Expected connection-related error, got: %v", err)
				}
			}
		})
	}
}

func TestClient_IsRetryableError(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	clientInterface, err := NewClient(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer clientInterface.Close()

	// Get the client implementation to test private method
	c, ok := clientInterface.(*client)
	if !ok {
		t.Fatal("client is not of expected type")
	}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "retryable connection error",
			err:  NewConnectionError("connection failed", true, nil),
			want: true,
		},
		{
			name: "non-retryable connection error",
			err:  NewConnectionError("config error", false, nil),
			want: false,
		},
		{
			name: "busy LDAP error",
			err:  ldap.NewError(ldap.LDAPResultBusy, errors.New("server busy")),
			want: true,
		},
		{
			name: "invalid credentials LDAP error",
			err:  ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad password")),
			want: false,
		},
		{
			name: "connection timeout error",
			err:  errors.New("connection timeout"),
			want: true,
		},
		{
			name: "broken pipe error",
			err:  errors.New("broken pipe"),
			want: true,
		},
		{
			name: "validation error",
			err:  errors.New("invalid syntax"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.isRetryableError(tt.err)
			if got != tt.want {
				t.Errorf("isRetryableError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSearchScope_Constants(t *testing.T) {
	// Verify search scope constants map to correct LDAP values
	if int(ScopeBaseObject) != ldap.ScopeBaseObject {
		t.Errorf("ScopeBaseObject = %d, want %d", int(ScopeBaseObject), ldap.ScopeBaseObject)
	}

	if int(ScopeSingleLevel) != ldap.ScopeSingleLevel {
		t.Errorf("ScopeSingleLevel = %d, want %d", int(ScopeSingleLevel), ldap.ScopeSingleLevel)
	}

	if int(ScopeWholeSubtree) != ldap.ScopeWholeSubtree {
		t.Errorf("ScopeWholeSubtree = %d, want %d", int(ScopeWholeSubtree), ldap.ScopeWholeSubtree)
	}
}

func TestDerefAliases_Constants(t *testing.T) {
	// Verify deref aliases constants map to correct LDAP values
	if int(NeverDerefAliases) != ldap.NeverDerefAliases {
		t.Errorf("NeverDerefAliases = %d, want %d", int(NeverDerefAliases), ldap.NeverDerefAliases)
	}

	if int(DerefInSearching) != ldap.DerefInSearching {
		t.Errorf("DerefInSearching = %d, want %d", int(DerefInSearching), ldap.DerefInSearching)
	}

	if int(DerefFindingBaseObj) != ldap.DerefFindingBaseObj {
		t.Errorf("DerefFindingBaseObj = %d, want %d", int(DerefFindingBaseObj), ldap.DerefFindingBaseObj)
	}

	if int(DerefAlways) != ldap.DerefAlways {
		t.Errorf("DerefAlways = %d, want %d", int(DerefAlways), ldap.DerefAlways)
	}
}

// Benchmarks

func BenchmarkNewClient(b *testing.B) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	for b.Loop() {
		client, err := NewClient(b.Context(), config)
		if err != nil {
			b.Fatalf("Failed to create client: %v", err)
		}
		client.Close()
	}
}

func BenchmarkSearchRequest_Creation(b *testing.B) {

	for b.Loop() {
		req := &SearchRequest{
			BaseDN:       "dc=example,dc=com",
			Scope:        ScopeWholeSubtree,
			Filter:       "(objectClass=user)",
			Attributes:   []string{"cn", "mail", "objectGUID"},
			SizeLimit:    1000,
			TimeLimit:    30 * time.Second,
			DerefAliases: NeverDerefAliases,
		}
		_ = req
	}
}

func BenchmarkClient_IsRetryableError(b *testing.B) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""

	clientInterface, err := NewClient(b.Context(), config)
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	defer clientInterface.Close()

	c, ok := clientInterface.(*client)
	if !ok {
		b.Fatal("client is not of expected type")
	}
	testErr := errors.New("connection timeout")

	for b.Loop() {
		_ = c.isRetryableError(testErr)
	}
}

func TestClient_WithRetry_Logic(t *testing.T) {
	config := DefaultConfig()
	config.LDAPURLs = []string{"ldaps://dc1.example.com:636"}
	config.Domain = ""
	config.MaxRetries = 2
	config.InitialBackoff = 1 * time.Millisecond // Fast for testing

	clientInterface, err := NewClient(t.Context(), config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer clientInterface.Close()

	c, ok := clientInterface.(*client)
	if !ok {
		t.Fatal("client is not of expected type")
	}

	// Test with retryable error
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	attempts := 0
	err = c.withRetry(ctx, func() error {
		attempts++
		if attempts < 3 {
			return NewConnectionError("temporary failure", true, nil)
		}
		return nil // Success on third attempt
	})

	if err != nil {
		t.Errorf("withRetry() should have succeeded after retries, got: %v", err)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}

	// Test with non-retryable error
	attempts = 0
	err = c.withRetry(ctx, func() error {
		attempts++
		return NewConnectionError("permanent failure", false, nil)
	})

	if err == nil {
		t.Error("withRetry() should have failed with non-retryable error")
	}

	if attempts != 1 {
		t.Errorf("Expected 1 attempt for non-retryable error, got %d", attempts)
	}
}
