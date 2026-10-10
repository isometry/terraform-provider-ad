package ldap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func writeSelfSignedPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tf-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

func clientCertConfig(certFile, keyFile string) *ConnectionConfig {
	cfg := DefaultConfig()
	cfg.LDAPURLs = []string{"ldaps://dc.example.invalid:636"}
	cfg.HealthCheck = 0
	cfg.TLSClientCertFile = certFile
	cfg.TLSClientKeyFile = keyFile
	return cfg
}

func TestNewConnectionPool_ClientCert_BadPathNamesFile(t *testing.T) {
	_, keyFile := writeSelfSignedPair(t)
	missing := filepath.Join(t.TempDir(), "missing.crt")

	_, err := NewConnectionPool(t.Context(), clientCertConfig(missing, keyFile))
	require.Error(t, err)
	assert.Contains(t, err.Error(), missing)
}

func TestNewConnectionPool_ClientCert_LoadedIntoTLSConfig(t *testing.T) {
	certFile, keyFile := writeSelfSignedPair(t)
	cfg := clientCertConfig(certFile, keyFile)

	p, err := NewConnectionPool(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	require.NotNil(t, cfg.TLSConfig)
	assert.Len(t, cfg.TLSConfig.Certificates, 1)
}

func TestAuthenticateExternal(t *testing.T) {
	t.Run("uses SASL EXTERNAL", func(t *testing.T) {
		b := &mockExternalBinder{}
		b.On("ExternalBind").Return(nil).Once()
		c := newTestClient(&mockPool{}, clientCertConfig("c", "k"))
		require.NoError(t, c.authenticateExternal(t.Context(), b))
		b.AssertExpectations(t)
	})

	t.Run("requires TLS", func(t *testing.T) {
		cfg := clientCertConfig("c", "k")
		cfg.LDAPURLs = []string{"ldap://dc.example.invalid:389"}
		cfg.UseTLS = false
		b := &mockExternalBinder{}
		c := newTestClient(&mockPool{}, cfg)
		err := c.authenticateExternal(t.Context(), b)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "needs TLS")
		b.AssertNotCalled(t, "ExternalBind")
	})
}

func TestSetPasswordByDN_RequiresEncryptedConnection(t *testing.T) {
	const dn = "cn=u,dc=example,dc=com"

	t.Run("plaintext refused before Modify", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{encrypted: false}
		swapConnOps(t, ops)
		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil)

		um := NewUserManager(t.Context(), newTestClient(pool, nil), "dc=example,dc=com", nil)
		err := um.setPasswordByDN(dn, "S3cret!pw")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to send a password over an unencrypted LDAP connection")
		ops.AssertNotCalled(t, "Modify", mock.Anything)
	})

	t.Run("TLS proceeds", func(t *testing.T) {
		pool := &mockPool{}
		ops := &mockLDAPOps{encrypted: true}
		swapConnOps(t, ops)
		pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil)
		ops.On("Modify", mock.Anything).Return(nil).Once()

		um := NewUserManager(t.Context(), newTestClient(pool, nil), "dc=example,dc=com", nil)
		require.NoError(t, um.setPasswordByDN(dn, "S3cret!pw"))
		ops.AssertExpectations(t)
	})
}
