package ldap

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/mock"
)

// mockPool is a testify-style mock that implements the ConnectionPool
// interface. It is used to inject a controllable PooledConnection into the
// client without needing a live LDAP server. The returned *PooledConnection
// typically has a nil *ldap.Conn; clients should route generic operations
// through connOps (see client.go) and thus never touch the nil field.
type mockPool struct {
	mock.Mock
}

func (m *mockPool) Get(ctx context.Context) (*PooledConnection, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		if pc, ok := v.(*PooledConnection); ok {
			return pc, args.Error(1)
		}
	}
	return nil, args.Error(1)
}

func (m *mockPool) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockPool) Stats() PoolStats {
	args := m.Called()
	if v := args.Get(0); v != nil {
		if s, ok := v.(PoolStats); ok {
			return s
		}
	}
	return PoolStats{}
}

func (m *mockPool) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// mockLDAPOps is a testify-style mock that implements the ldapOps
// interface declared in client.go. It allows assertions on the exact
// *ldap.SearchRequest, *ldap.AddRequest, etc. that the client builds and
// would otherwise send to the remote directory server.
type mockLDAPOps struct {
	mock.Mock
}

func (m *mockLDAPOps) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	args := m.Called(req)
	if v := args.Get(0); v != nil {
		if r, ok := v.(*ldap.SearchResult); ok {
			return r, args.Error(1)
		}
	}
	return nil, args.Error(1)
}

func (m *mockLDAPOps) Add(req *ldap.AddRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

func (m *mockLDAPOps) Modify(req *ldap.ModifyRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

func (m *mockLDAPOps) ModifyDN(req *ldap.ModifyDNRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

func (m *mockLDAPOps) Del(req *ldap.DelRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

func (m *mockLDAPOps) WhoAmI(controls []ldap.Control) (*ldap.WhoAmIResult, error) {
	args := m.Called(controls)
	if v := args.Get(0); v != nil {
		if r, ok := v.(*ldap.WhoAmIResult); ok {
			return r, args.Error(1)
		}
	}
	return nil, args.Error(1)
}

// swapConnOps temporarily replaces the package-level connOps function
// with one that returns the provided ldapOps for any PooledConnection.
// It returns a cleanup function that restores the original. Tests should
// call this with t.Cleanup to keep state isolated between parallel tests.
//
// Note: connOps is a package-level variable, so concurrent tests that mutate
// it must not run in parallel with each other. None of the tests that use
// this helper call t.Parallel().
func swapConnOps(tb testing.TB, ops ldapOps) {
	tb.Helper()
	original := connOps
	connOps = func(_ *PooledConnection) ldapOps { return ops }
	tb.Cleanup(func() { connOps = original })
}

// newTestClient constructs a *client backed by the given ConnectionPool.
// It bypasses NewClient (which validates config and performs discovery)
// so unit tests can exercise the client's CRUD methods without requiring
// a live LDAP server.
func newTestClient(pool ConnectionPool, config *ConnectionConfig) *client {
	if config == nil {
		config = DefaultConfig()
		config.MaxRetries = 0
	}
	return &client{
		ctx:    context.Background(),
		pool:   pool,
		config: config,
	}
}

// errPoolDeliberate is used by tests that want pool.Get to return an error.
var errPoolDeliberate = errors.New("deliberate pool failure for test")

// captureArg returns a mock.Run callback that stores the first argument
// of the call into *dst. It fails the test (via tb) if the argument's
// concrete type doesn't match. Using this avoids sprinkling unchecked
// type assertions across tests, which the `forcetypeassert` linter flags.
func captureArg[T any](tb testing.TB, dst *T) func(mock.Arguments) {
	tb.Helper()
	return func(args mock.Arguments) {
		tb.Helper()
		v, ok := args.Get(0).(T)
		if !ok {
			tb.Fatalf("captureArg: argument has type %T, want %T", args.Get(0), *dst)
		}
		*dst = v
	}
}
