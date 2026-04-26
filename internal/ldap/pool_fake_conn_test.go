package ldap

import (
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// newFakeLDAPConn returns a live, unstarted *ldap.Conn backed by a loopback
// TCP connection. The returned *ldap.Conn is not useful for real LDAP
// operations — no server is listening on the other side of the pipe — but
// it is safe for the connection pool to treat as a real connection:
//
//   - its internal net.Conn is non-nil
//   - PooledConnection.healthy checks will succeed (conn.conn != nil)
//   - pool.closeConnection -> conn.conn.Close() is a clean shutdown
//
// The paired peer socket is tracked via t.Cleanup so goroutines started by
// ldap.NewConn (via Start) exit promptly at test end.
func newFakeLDAPConn(tb testing.TB) *ldap.Conn {
	tb.Helper()

	// Start a loopback listener. We accept exactly one connection, hold the
	// peer end so the net.Conn remains alive, and close both ends via
	// t.Cleanup.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("failed to listen on loopback: %v", err)
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		l.Close()
		tb.Fatalf("failed to dial loopback listener: %v", err)
	}

	var peer net.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		client.Close()
		l.Close()
		tb.Fatalf("timed out waiting for loopback accept")
	}
	_ = l.Close() // listener no longer needed once paired

	conn := ldap.NewConn(client, false)
	conn.Start()

	tb.Cleanup(func() {
		// Closing peer first causes the ldap reader goroutine to see EOF
		// and exit cleanly; the pool is responsible for closing the ldap
		// side of things, but we defend against leaks if the test does not.
		if peer != nil {
			_ = peer.Close()
		}
	})

	return conn
}

// newTestPool constructs a connection pool with a non-real set of servers
// (suitable for tests that inject connections directly into the pool's
// idle channel rather than actually dialing).
func newTestPool(tb testing.TB, maxConns int) *connectionPool {
	tb.Helper()
	cfg := DefaultConfig()
	cfg.LDAPURLs = []string{"ldaps://test.invalid:636"}
	cfg.Domain = ""
	cfg.MaxConnections = maxConns
	cfg.HealthCheck = 0 // disable background health checker for deterministic tests
	cfg.MaxRetries = 0

	poolIface, err := NewConnectionPool(tb.Context(), cfg)
	if err != nil {
		tb.Fatalf("NewConnectionPool failed: %v", err)
	}
	tb.Cleanup(func() { _ = poolIface.Close() })

	pool, ok := poolIface.(*connectionPool)
	if !ok {
		tb.Fatalf("NewConnectionPool returned unexpected type %T", poolIface)
	}
	return pool
}

// newHealthyPooled constructs a *PooledConnection backed by a fake ldap
// connection and wired to return to the given pool. The connection is
// marked healthy, authenticated, and freshly used, so isConnectionHealthy
// accepts it.
func newHealthyPooled(tb testing.TB, pool *connectionPool) *PooledConnection {
	tb.Helper()
	pc := &PooledConnection{
		conn:          newFakeLDAPConn(tb),
		lastUsed:      time.Now(),
		healthy:       true,
		authenticated: true,
		authTime:      time.Now(),
		serverInfo:    &ServerInfo{Host: "test.invalid", Port: 636, UseTLS: true},
		returnToPool:  pool.returnConnection,
	}
	return pc
}
