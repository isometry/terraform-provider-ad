package ldap

import (
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Under a hard max_connections cap the dead connection must be released
// before the replacement is requested, or the last slot deadlocks.
func TestSearch_RetryReleasesDeadConnectionBeforeGet(t *testing.T) {
	released := false
	dead := &PooledConnection{healthy: true, returnToPool: func(*PooledConnection) { released = true }}
	fresh := &PooledConnection{healthy: true}
	pool := &mockPool{}
	pool.On("Get", mock.Anything).Return(dead, nil).Once()
	pool.On("Get", mock.Anything).Run(func(mock.Arguments) {
		assert.True(t, released, "dead connection must be closed before requesting a fresh one")
	}).Return(fresh, nil).Once()

	ops := &mockLDAPOps{}
	ops.On("Search", mock.Anything).Return(nil, ldap.NewError(ldap.ErrorNetwork, assert.AnError)).Once()
	ops.On("Search", mock.Anything).Return(&ldap.SearchResult{}, nil).Once()
	swapConnOps(t, ops)

	cfg := DefaultConfig()
	cfg.MaxRetries, cfg.InitialBackoff, cfg.MaxBackoff, cfg.BackoffFactor = 2, time.Millisecond, time.Millisecond, 2
	_, err := newTestClient(pool, cfg).Search(t.Context(), &SearchRequest{BaseDN: "dc=example,dc=com", Filter: "(objectClass=*)", Scope: ScopeBaseObject})
	require.NoError(t, err)
}
