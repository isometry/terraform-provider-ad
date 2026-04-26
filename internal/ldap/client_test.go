package ldap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

// TestSearchRequest_Validation verifies that client.Search rejects nil
// requests and, for valid requests, builds a *ldap.SearchRequest with the
// expected fields and hands it to the underlying LDAP connection.
func TestSearchRequest_Validation(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		pool := &mockPool{}
		// No pool/ops expectations: the nil-check must short-circuit before
		// any connection is acquired.
		c := newTestClient(pool, nil)

		_, err := c.Search(t.Context(), nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "search request cannot be nil")
		pool.AssertExpectations(t)
	})

	t.Run("builds SearchRequest with expected fields", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{}
		swapConnOps(t, ops)

		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil).Once()

		req := &SearchRequest{
			BaseDN:       "ou=Users,dc=example,dc=com",
			Scope:        ScopeWholeSubtree,
			Filter:       "(objectClass=user)",
			Attributes:   []string{"cn", "mail", "objectGUID"},
			SizeLimit:    100,
			TimeLimit:    30 * time.Second,
			DerefAliases: NeverDerefAliases,
		}

		var captured *ldap.SearchRequest
		ops.On("Search", mock.AnythingOfType("*ldap.SearchRequest")).
			Run(captureArg(t, &captured)).
			Return(&ldap.SearchResult{}, nil).Once()

		c := newTestClient(pool, nil)
		result, err := c.Search(t.Context(), req)

		require.NoError(t, err)
		require.NotNil(t, result)

		require.NotNil(t, captured, "ops.Search should have received a request")
		assert.Equal(t, "ou=Users,dc=example,dc=com", captured.BaseDN)
		assert.Equal(t, int(ScopeWholeSubtree), captured.Scope)
		assert.Equal(t, int(NeverDerefAliases), captured.DerefAliases)
		assert.Equal(t, 100, captured.SizeLimit)
		assert.Equal(t, 30, captured.TimeLimit)
		assert.Equal(t, "(objectClass=user)", captured.Filter)
		assert.Equal(t, []string{"cn", "mail", "objectGUID"}, captured.Attributes)
		assert.False(t, captured.TypesOnly)

		pool.AssertExpectations(t)
		ops.AssertExpectations(t)
	})

	t.Run("HasMore when result equals size limit", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{}
		swapConnOps(t, ops)

		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil).Once()
		ops.On("Search", mock.AnythingOfType("*ldap.SearchRequest")).
			Return(&ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=a,dc=example,dc=com"},
					{DN: "cn=b,dc=example,dc=com"},
				},
			}, nil).Once()

		c := newTestClient(pool, nil)
		got, err := c.Search(t.Context(), &SearchRequest{
			BaseDN:    "dc=example,dc=com",
			Scope:     ScopeSingleLevel,
			Filter:    "(objectClass=*)",
			SizeLimit: 2,
		})

		require.NoError(t, err)
		assert.Equal(t, 2, got.Total)
		assert.True(t, got.HasMore, "HasMore should be true when entries == size limit")
		pool.AssertExpectations(t)
		ops.AssertExpectations(t)
	})

	t.Run("propagates underlying search error", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{}
		swapConnOps(t, ops)

		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil).Once()
		ops.On("Search", mock.AnythingOfType("*ldap.SearchRequest")).
			Return((*ldap.SearchResult)(nil),
				ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("not found"))).
			Once()

		config := DefaultConfig()
		config.MaxRetries = 0
		c := newTestClient(pool, config)
		_, err := c.Search(t.Context(), &SearchRequest{
			BaseDN: "dc=example,dc=com",
			Scope:  ScopeBaseObject,
			Filter: "(objectClass=*)",
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "search failed")
		pool.AssertExpectations(t)
		ops.AssertExpectations(t)
	})

	t.Run("pool acquisition failure surfaces error", func(t *testing.T) {
		pool := &mockPool{}
		pool.On("Get", mock.Anything).Return((*PooledConnection)(nil), errPoolDeliberate).Once()

		c := newTestClient(pool, nil)
		_, err := c.Search(t.Context(), &SearchRequest{
			BaseDN: "dc=example,dc=com",
			Scope:  ScopeBaseObject,
			Filter: "(objectClass=*)",
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get connection")
		pool.AssertExpectations(t)
	})
}

// TestAddRequest_Validation verifies that client.Add rejects nil requests
// and that it converts a *AddRequest into a *ldap.AddRequest carrying the
// expected DN and attribute set.
func TestAddRequest_Validation(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		pool := &mockPool{}
		c := newTestClient(pool, nil)

		err := c.Add(t.Context(), nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "add request cannot be nil")
		pool.AssertExpectations(t)
	})

	t.Run("builds AddRequest with DN and attributes", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{}
		swapConnOps(t, ops)

		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil).Once()

		var captured *ldap.AddRequest
		ops.On("Add", mock.AnythingOfType("*ldap.AddRequest")).
			Run(captureArg(t, &captured)).
			Return(nil).Once()

		req := &AddRequest{
			DN: "cn=test,dc=example,dc=com",
			Attributes: map[string][]string{
				"objectClass":    {"top", "person", "user"},
				"cn":             {"test"},
				"sAMAccountName": {"test"},
			},
		}

		c := newTestClient(pool, nil)
		require.NoError(t, c.Add(t.Context(), req))

		require.NotNil(t, captured, "ops.Add should have received a request")
		assert.Equal(t, "cn=test,dc=example,dc=com", captured.DN)

		// Assert on the attribute set: map→slice conversion makes order
		// non-deterministic so we index by type.
		byType := make(map[string][]string, len(captured.Attributes))
		for _, a := range captured.Attributes {
			byType[a.Type] = a.Vals
		}
		assert.Equal(t, []string{"top", "person", "user"}, byType["objectClass"])
		assert.Equal(t, []string{"test"}, byType["cn"])
		assert.Equal(t, []string{"test"}, byType["sAMAccountName"])
		assert.Len(t, byType, 3, "no unexpected attributes should be present")

		pool.AssertExpectations(t)
		ops.AssertExpectations(t)
	})

	t.Run("pool acquisition failure surfaces error", func(t *testing.T) {
		pool := &mockPool{}
		pool.On("Get", mock.Anything).Return((*PooledConnection)(nil), errPoolDeliberate).Once()

		c := newTestClient(pool, nil)
		err := c.Add(t.Context(), &AddRequest{DN: "cn=a,dc=example,dc=com"})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get connection")
		pool.AssertExpectations(t)
	})
}

// TestModifyRequest_Validation verifies that client.Modify rejects nil
// requests and that Add/Replace/Delete attribute sets translate into the
// expected set of ldap.Change operations in the outgoing request.
func TestModifyRequest_Validation(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		pool := &mockPool{}
		c := newTestClient(pool, nil)

		err := c.Modify(t.Context(), nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "modify request cannot be nil")
		pool.AssertExpectations(t)
	})

	t.Run("builds ModifyRequest with expected changes", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{}
		swapConnOps(t, ops)

		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil).Once()

		var captured *ldap.ModifyRequest
		ops.On("Modify", mock.AnythingOfType("*ldap.ModifyRequest")).
			Run(captureArg(t, &captured)).
			Return(nil).Once()

		req := &ModifyRequest{
			DN: "cn=test,dc=example,dc=com",
			AddAttributes: map[string][]string{
				"description": {"test user"},
			},
			ReplaceAttributes: map[string][]string{
				"mail": {"test@example.com"},
			},
			DeleteAttributes: []string{"telephoneNumber"},
		}

		c := newTestClient(pool, nil)
		require.NoError(t, c.Modify(t.Context(), req))

		require.NotNil(t, captured)
		assert.Equal(t, "cn=test,dc=example,dc=com", captured.DN)
		require.Len(t, captured.Changes, 3, "one change per Add/Replace/Delete entry")

		type op struct {
			Op   uint
			Type string
			Vals []string
		}
		gotOps := make([]op, len(captured.Changes))
		for i, ch := range captured.Changes {
			gotOps[i] = op{
				Op:   ch.Operation,
				Type: ch.Modification.Type,
				Vals: ch.Modification.Vals,
			}
		}

		assert.Contains(t, gotOps, op{
			Op: ldap.AddAttribute, Type: "description", Vals: []string{"test user"},
		})
		assert.Contains(t, gotOps, op{
			Op: ldap.ReplaceAttribute, Type: "mail", Vals: []string{"test@example.com"},
		})
		assert.Contains(t, gotOps, op{
			Op: ldap.DeleteAttribute, Type: "telephoneNumber", Vals: []string{},
		})

		pool.AssertExpectations(t)
		ops.AssertExpectations(t)
	})

	t.Run("propagates controls", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{}
		swapConnOps(t, ops)

		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil).Once()

		// Use a no-argument control - ManageDsaIT is a simple, well-known OID
		// with no value that's easy to match by type.
		sdFlagsOID := "1.2.840.113556.1.4.801"
		wantControl := &ldap.ControlString{
			ControlType:  sdFlagsOID,
			Criticality:  true,
			ControlValue: "",
		}

		var captured *ldap.ModifyRequest
		ops.On("Modify", mock.AnythingOfType("*ldap.ModifyRequest")).
			Run(captureArg(t, &captured)).
			Return(nil).Once()

		req := &ModifyRequest{
			DN:                "cn=test,dc=example,dc=com",
			ReplaceAttributes: map[string][]string{"description": {"x"}},
			Controls:          []ldap.Control{wantControl},
		}

		c := newTestClient(pool, nil)
		require.NoError(t, c.Modify(t.Context(), req))
		require.NotNil(t, captured)
		require.Len(t, captured.Controls, 1)
		assert.Equal(t, sdFlagsOID, captured.Controls[0].GetControlType())

		pool.AssertExpectations(t)
		ops.AssertExpectations(t)
	})

	t.Run("pool acquisition failure surfaces error", func(t *testing.T) {
		pool := &mockPool{}
		pool.On("Get", mock.Anything).Return((*PooledConnection)(nil), errPoolDeliberate).Once()

		c := newTestClient(pool, nil)
		err := c.Modify(t.Context(), &ModifyRequest{DN: "cn=a,dc=example,dc=com"})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get connection")
		pool.AssertExpectations(t)
	})
}

// TestDelete_Validation verifies that client.Delete rejects empty DNs and
// that for a non-empty DN the outgoing *ldap.DelRequest carries the
// expected DN.
func TestDelete_Validation(t *testing.T) {
	t.Run("empty DN", func(t *testing.T) {
		pool := &mockPool{}
		c := newTestClient(pool, nil)

		err := c.Delete(t.Context(), "")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "DN cannot be empty")
		pool.AssertExpectations(t)
	})

	t.Run("builds DelRequest with expected DN", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{}
		swapConnOps(t, ops)

		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil).Once()

		var captured *ldap.DelRequest
		ops.On("Del", mock.AnythingOfType("*ldap.DelRequest")).
			Run(captureArg(t, &captured)).
			Return(nil).Once()

		c := newTestClient(pool, nil)
		require.NoError(t, c.Delete(t.Context(), "cn=test,dc=example,dc=com"))

		require.NotNil(t, captured)
		assert.Equal(t, "cn=test,dc=example,dc=com", captured.DN)

		pool.AssertExpectations(t)
		ops.AssertExpectations(t)
	})

	t.Run("pool acquisition failure surfaces error", func(t *testing.T) {
		pool := &mockPool{}
		pool.On("Get", mock.Anything).Return((*PooledConnection)(nil), errPoolDeliberate).Once()

		c := newTestClient(pool, nil)
		err := c.Delete(t.Context(), "cn=a,dc=example,dc=com")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get connection")
		pool.AssertExpectations(t)
	})
}

// TestModifyDN_Validation verifies that client.ModifyDN rejects nil/empty
// inputs and that a valid request produces an outgoing *ldap.ModifyDNRequest
// carrying the expected DN, new RDN, deleteOldRDN flag, and new superior.
func TestModifyDN_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     *ModifyDNRequest
		errText string
	}{
		{
			name:    "nil request",
			req:     nil,
			errText: "modify DN request cannot be nil",
		},
		{
			name:    "empty DN",
			req:     &ModifyDNRequest{DN: "", NewRDN: "cn=new"},
			errText: "DN cannot be empty",
		},
		{
			name:    "empty NewRDN",
			req:     &ModifyDNRequest{DN: "cn=old,dc=example,dc=com", NewRDN: ""},
			errText: "new RDN cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := &mockPool{}
			c := newTestClient(pool, nil)

			err := c.ModifyDN(t.Context(), tt.req)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errText)
			pool.AssertExpectations(t)
		})
	}

	t.Run("builds ModifyDNRequest with expected fields", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{}
		swapConnOps(t, ops)

		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil).Once()

		var captured *ldap.ModifyDNRequest
		ops.On("ModifyDN", mock.AnythingOfType("*ldap.ModifyDNRequest")).
			Run(captureArg(t, &captured)).
			Return(nil).Once()

		req := &ModifyDNRequest{
			DN:           "cn=old,ou=Users,dc=example,dc=com",
			NewRDN:       "cn=new",
			DeleteOldRDN: true,
			NewSuperior:  "ou=Admins,dc=example,dc=com",
		}

		c := newTestClient(pool, nil)
		require.NoError(t, c.ModifyDN(t.Context(), req))

		require.NotNil(t, captured)
		assert.Equal(t, "cn=old,ou=Users,dc=example,dc=com", captured.DN)
		assert.Equal(t, "cn=new", captured.NewRDN)
		assert.True(t, captured.DeleteOldRDN)
		assert.Equal(t, "ou=Admins,dc=example,dc=com", captured.NewSuperior)

		pool.AssertExpectations(t)
		ops.AssertExpectations(t)
	})
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
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
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
