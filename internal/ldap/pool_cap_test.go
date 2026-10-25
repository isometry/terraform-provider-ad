package ldap

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPipedPooled is newHealthyPooled over an in-memory pipe, so it needs no
// loopback listener. The returned peer end is the "server".
func newPipedPooled(tb testing.TB, pool *connectionPool) (*PooledConnection, net.Conn) {
	tb.Helper()
	conn, peer := newPipeLDAPConn(tb)
	return &PooledConnection{
		conn:          conn,
		lastUsed:      time.Now(),
		healthy:       true,
		authenticated: true,
		authTime:      time.Now(),
		serverInfo:    &ServerInfo{Host: "test.invalid", Port: 636, UseTLS: true},
		returnToPool:  pool.returnConnection,
	}, peer
}

// seedIdle parks n pipe-backed connections in the pool's idle channel.
func seedIdle(tb testing.TB, pool *connectionPool, n int) {
	tb.Helper()
	for range n {
		pc, _ := newPipedPooled(tb, pool)
		pool.connections <- pc
	}
}

type getResult struct {
	pc  *PooledConnection
	err error
}

func getAsync(ctx context.Context, pool *connectionPool) <-chan getResult {
	ch := make(chan getResult, 1)
	go func() {
		pc, err := pool.Get(ctx)
		ch <- getResult{pc, err}
	}()
	return ch
}

func assertBlocked(t *testing.T, ch <-chan getResult) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("Get should be blocked at the cap, returned %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
}

func waitResult(t *testing.T, ch <-chan getResult) getResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("Get did not return")
		return getResult{}
	}
}

func TestConnectionPool_MaxConnections_HardCap(t *testing.T) {
	pool := newTestPool(t, 2)
	seedIdle(t, pool, 2)

	a, err := pool.Get(t.Context())
	require.NoError(t, err)
	b, err := pool.Get(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 2, pool.Stats().Active)

	third := getAsync(t.Context(), pool)
	assertBlocked(t, third)

	a.Close() // idle again -> the waiter takes it
	r := waitResult(t, third)
	require.NoError(t, r.err)
	assert.Same(t, a, r.pc)
	assert.EqualValues(t, 2, pool.Stats().Active)

	b.Close()
	r.pc.Close()
	assert.EqualValues(t, 0, pool.Stats().Active)
}

func TestConnectionPool_Get_ContextCancelUnblocksWaiter(t *testing.T) {
	pool := newTestPool(t, 1)
	seedIdle(t, pool, 1)
	held, err := pool.Get(t.Context())
	require.NoError(t, err)
	defer held.Close()

	ctx, cancel := context.WithCancel(t.Context())
	ch := getAsync(ctx, pool)
	assertBlocked(t, ch)
	cancel()
	r := waitResult(t, ch)
	assert.ErrorIs(t, r.err, context.Canceled)
	assert.EqualValues(t, 1, pool.Stats().Active, "a cancelled waiter must not take or leak a slot")
}

func TestConnectionPool_Get_WaitBoundedByTimeout(t *testing.T) {
	pool := newTestPool(t, 1)
	pool.config.Timeout = 50 * time.Millisecond
	seedIdle(t, pool, 1)
	held, err := pool.Get(t.Context())
	require.NoError(t, err)
	defer held.Close()

	_, err = pool.Get(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "waiting for a free connection")
}

func TestConnectionPool_Close_WakesWaiters(t *testing.T) {
	pool := newTestPool(t, 1)
	seedIdle(t, pool, 1)
	held, err := pool.Get(t.Context())
	require.NoError(t, err)

	ch := getAsync(t.Context(), pool)
	assertBlocked(t, ch)
	require.NoError(t, pool.Close())
	r := waitResult(t, ch)
	assert.ErrorIs(t, r.err, errPoolClosed)

	held.Close() // returning after Close closes the conn instead of sending on the closed channel
}

func TestPooledConnection_DoubleCloseReleasesOnce(t *testing.T) {
	pool := newTestPool(t, 2)
	seedIdle(t, pool, 2)
	a, err := pool.Get(t.Context())
	require.NoError(t, err)
	b, err := pool.Get(t.Context())
	require.NoError(t, err)
	defer b.Close()

	a.Close()
	a.Close() // must not free b's slot

	c, err := pool.Get(t.Context())
	require.NoError(t, err)
	defer c.Close()
	assert.EqualValues(t, 2, pool.Stats().Active)
	assertBlocked(t, getAsync(t.Context(), pool))
}

func TestConnectionPool_FailedCreateReleasesSlot(t *testing.T) {
	pool := newTestPool(t, 1)
	swapDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) { return nil, assert.AnError })

	_, err := pool.Get(t.Context())
	require.Error(t, err)
	assert.EqualValues(t, 0, pool.Stats().Active)

	fresh, _ := newPipeLDAPConn(t)
	swapDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) { return fresh, nil })
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	pc, err := pool.Get(ctx)
	require.NoError(t, err, "slot must be free after a failed create")
	pc.Close()
}

// healthPeer answers every request on peer with a SearchResultDone(success)
// once gate is closed (nil gate: immediately).
func healthPeer(peer net.Conn, gate <-chan struct{}) {
	go func() {
		buf := make([]byte, 4096)
		for id := byte(1); ; id++ {
			if _, err := peer.Read(buf); err != nil {
				return
			}
			if gate != nil {
				<-gate
			}
			if _, err := peer.Write([]byte{0x30, 0x0c, 0x02, 0x01, id, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}); err != nil {
				return
			}
		}
	}()
}

func TestPerformHealthCheck_KeepsHealthyDropsDeadWithoutCounterDrift(t *testing.T) {
	pool := newTestPool(t, 3)
	good, goodPeer := newPipedPooled(t, pool)
	healthPeer(goodPeer, nil)
	bad, _ := newPipedPooled(t, pool)
	bad.conn.Close()
	pool.connections <- good
	pool.connections <- bad

	pool.performHealthCheck()

	assert.Equal(t, 1, pool.Stats().Idle)
	assert.EqualValues(t, 0, pool.Stats().Active, "health check must not touch the checked-out counter")
	assert.True(t, bad.conn.IsClosing())
	got, err := pool.Get(t.Context())
	require.NoError(t, err)
	assert.Same(t, good, got)
	got.Close()
}

func TestHealthChecker_RunsOnInterval(t *testing.T) {
	pool := newTestPool(t, 2)
	pool.config.HealthCheck = 10 * time.Millisecond
	bad, _ := newPipedPooled(t, pool)
	bad.conn.Close()
	pool.connections <- bad
	pool.startHealthChecker()

	require.Eventually(t, func() bool { return pool.Stats().Idle == 0 }, 2*time.Second, 5*time.Millisecond)
	assert.GreaterOrEqual(t, pool.Stats().Active, int64(0))
}

func TestConnectionPool_Close_DuringHealthCheckDoesNotDeadlock(t *testing.T) {
	pool := newTestPool(t, 2)
	pool.config.HealthCheck = 10 * time.Millisecond
	pc, peer := newPipedPooled(t, pool)
	gate := make(chan struct{})
	healthPeer(peer, gate) // the check blocks on the search reply until gate closes
	pool.connections <- pc
	pool.startHealthChecker()

	// The checker has the connection out of the idle channel and is mid-search.
	require.Eventually(t, func() bool { return pool.Stats().Idle == 0 }, 2*time.Second, 5*time.Millisecond)

	closed := make(chan error, 1)
	go func() { closed <- pool.Close() }()
	time.Sleep(50 * time.Millisecond) // let Close take its first lock and start waiting on the checker
	close(gate)

	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Close deadlocked with a health check in flight")
	}
	assert.True(t, pc.conn.IsClosing(), "connection returned after Close must be closed")
	assert.EqualValues(t, 0, pool.Stats().Active)
}
