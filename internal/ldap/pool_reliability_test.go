package ldap

import (
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newPipeLDAPConn returns a started *ldap.Conn over an in-memory pipe (no
// listener needed) and the peer end.
func newPipeLDAPConn(tb testing.TB) (*ldap.Conn, net.Conn) {
	tb.Helper()
	c, peer := net.Pipe()
	conn := ldap.NewConn(c, false)
	conn.Start()
	tb.Cleanup(func() { _ = peer.Close(); conn.Close() })
	return conn, peer
}

// replyOnce reads the client's request and answers with the canned bytes
// (message ID 1, the first request on a new connection).
func replyOnce(peer net.Conn, resp []byte) {
	go func() {
		buf := make([]byte, 4096)
		if _, err := peer.Read(buf); err == nil {
			_, _ = peer.Write(resp)
		}
	}()
}

var (
	// ExtendedResponse, resultCode protocolError(2).
	extErrResp = []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x02, 0x04, 0x00, 0x04, 0x00}
	// BindResponse, resultCode invalidCredentials(49).
	bindErrResp = []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00}
)

func swapDialURL(tb testing.TB, fn func(string, ...ldap.DialOpt) (*ldap.Conn, error)) {
	tb.Helper()
	orig := dialURL
	dialURL = fn
	tb.Cleanup(func() { dialURL = orig })
}

func TestIsConnectionHealthy_ClosingConnIsUnhealthy(t *testing.T) {
	pool := newTestPool(t, 2)
	conn, _ := newPipeLDAPConn(t)
	pc := &PooledConnection{conn: conn, lastUsed: time.Now(), healthy: true, authenticated: true}

	assert.True(t, pool.isConnectionHealthy(pc))
	conn.Close() // what the reader goroutine does when the socket dies
	assert.False(t, pool.isConnectionHealthy(pc))
}

func TestConnectionPool_ClosingConnDiscardedOnGet(t *testing.T) {
	pool := newTestPool(t, 2)
	dead, _ := newPipeLDAPConn(t)
	fresh, _ := newPipeLDAPConn(t)
	swapDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) { return fresh, nil })

	pc := &PooledConnection{conn: dead, lastUsed: time.Now(), healthy: true, authenticated: true,
		serverInfo: &ServerInfo{Host: "test.invalid", Port: 636, UseTLS: true}}
	dead.Close()
	pool.connections <- pc

	got, err := pool.Get(t.Context())
	require.NoError(t, err)
	assert.NotSame(t, pc, got)
	assert.Same(t, fresh, got.conn)
}

func TestCreateSingleConnection_ClosesOnStartTLSFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UseTLS = true
	p := &connectionPool{config: cfg}
	conn, peer := newPipeLDAPConn(t)
	swapDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) { return conn, nil })
	replyOnce(peer, extErrResp)

	_, err := p.createSingleConnection(t.Context(), &ServerInfo{Host: "dc.invalid", Port: 389})
	require.Error(t, err)
	assert.True(t, conn.IsClosing(), "connection must be closed when StartTLS fails")
}

func TestCreateSingleConnection_ClosesOnBindFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UseTLS = false
	cfg.Username, cfg.Password = "cn=x,dc=example,dc=com", "pw"
	p := &connectionPool{config: cfg}
	conn, peer := newPipeLDAPConn(t)
	swapDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) { return conn, nil })
	replyOnce(peer, bindErrResp)

	_, err := p.createSingleConnection(t.Context(), &ServerInfo{Host: "dc.invalid", Port: 389})
	require.Error(t, err)
	assert.True(t, conn.IsClosing(), "connection must be closed when bind fails")
}

func TestIsNetworkError(t *testing.T) {
	assert.True(t, isNetworkError(ldap.NewError(ldap.ErrorNetwork, assert.AnError)))
	assert.True(t, isNetworkError(&net.OpError{Op: "write", Err: errBrokenPipe{}}))
	assert.False(t, isNetworkError(ldap.NewError(ldap.LDAPResultEntryAlreadyExists, assert.AnError)))
	assert.False(t, isNetworkError(nil))
}

type errBrokenPipe struct{}

func (errBrokenPipe) Error() string { return "broken pipe" }

func TestWrite_NetworkErrorMarksConnectionUnhealthy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantHealthy bool
	}{
		{"network", ldap.NewError(ldap.ErrorNetwork, assert.AnError), false},
		{"server rejection", ldap.NewError(ldap.LDAPResultEntryAlreadyExists, assert.AnError), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := &PooledConnection{healthy: true}
			pool := &mockPool{}
			pool.On("Get", mock.Anything).Return(pc, nil)
			ops := &mockLDAPOps{}
			ops.On("Add", mock.Anything).Return(tc.err)
			swapConnOps(t, ops)

			err := newTestClient(pool, nil).Add(t.Context(), &AddRequest{DN: "cn=x,dc=example,dc=com",
				Attributes: map[string][]string{"objectClass": {"top"}}})
			require.Error(t, err)
			assert.Equal(t, tc.wantHealthy, pc.healthy)
		})
	}
}

func TestSearch_RetryUsesFreshConnectionAfterNetworkError(t *testing.T) {
	dead, fresh := &PooledConnection{healthy: true}, &PooledConnection{healthy: true}
	pool := &mockPool{}
	pool.On("Get", mock.Anything).Return(dead, nil).Once()
	pool.On("Get", mock.Anything).Return(fresh, nil).Once()

	ops := &mockLDAPOps{}
	ops.On("Search", mock.Anything).Return(nil, ldap.NewError(ldap.ErrorNetwork, assert.AnError)).Once()
	ops.On("Search", mock.Anything).Return(&ldap.SearchResult{}, nil).Once()
	var used []*PooledConnection
	orig := connOps
	connOps = func(pc *PooledConnection) ldapOps { used = append(used, pc); return ops }
	t.Cleanup(func() { connOps = orig })

	cfg := DefaultConfig()
	cfg.MaxRetries, cfg.InitialBackoff, cfg.MaxBackoff, cfg.BackoffFactor = 2, time.Millisecond, time.Millisecond, 2
	_, err := newTestClient(pool, cfg).Search(t.Context(), &SearchRequest{BaseDN: "dc=example,dc=com", Filter: "(objectClass=*)", Scope: ScopeBaseObject})
	require.NoError(t, err)

	assert.False(t, dead.healthy)
	assert.Equal(t, []*PooledConnection{dead, fresh}, used)
	pool.AssertNumberOfCalls(t, "Get", 2)
}
