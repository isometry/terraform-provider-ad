package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

func TestBuildLDAPConfig_AuthCombinations(t *testing.T) {
	for _, env := range []string{
		"AD_USERNAME", "AD_USER", "AD_PASSWORD", "AD_KERBEROS_REALM", "AD_KERBEROS_KEYTAB",
		"AD_KERBEROS_CCACHE", "AD_TLS_CLIENT_CERT_FILE", "AD_TLS_CLIENT_KEY_FILE",
	} {
		t.Setenv(env, "")
	}

	s := types.StringValue
	tests := []struct {
		name       string
		model      ActiveDirectoryProviderModel
		wantErr    bool
		wantMethod ldapclient.AuthMethod
	}{
		{"password", ActiveDirectoryProviderModel{Username: s("u"), Password: s("p")}, false, ldapclient.AuthMethodSimpleBind},
		{"kerberos keytab without username", ActiveDirectoryProviderModel{KerberosRealm: s("EXAMPLE.COM"), KerberosKeytab: s("/k.keytab")}, false, ldapclient.AuthMethodKerberos},
		{"kerberos ccache only", ActiveDirectoryProviderModel{KerberosRealm: s("EXAMPLE.COM"), KerberosCCache: s("/tmp/cc")}, false, ldapclient.AuthMethodKerberos},
		{"certificate only", ActiveDirectoryProviderModel{TLSClientCertFile: s("/c.pem"), TLSClientKeyFile: s("/k.pem")}, false, ldapclient.AuthMethodExternal},
		{"nothing", ActiveDirectoryProviderModel{}, true, 0},
		{"username without password", ActiveDirectoryProviderModel{Username: s("u")}, true, 0},
		{"realm alone", ActiveDirectoryProviderModel{KerberosRealm: s("EXAMPLE.COM")}, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ActiveDirectoryProvider{}
			var diags diag.Diagnostics
			cfg := p.buildLDAPConfig(&tt.model, &diags)
			if tt.wantErr {
				require.True(t, diags.HasError())
				assert.Equal(t, "Missing Authentication Configuration", diags[0].Summary())
				return
			}
			require.False(t, diags.HasError(), "%v", diags)
			assert.Equal(t, tt.wantMethod, cfg.GetAuthMethod())
		})
	}
}
