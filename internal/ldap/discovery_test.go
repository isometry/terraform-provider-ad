package ldap

import (
	"context"
	"testing"
	"time"
)

func TestSRVDiscovery_DiscoverServers(t *testing.T) {
	discovery := NewSRVDiscovery(context.Background())

	tests := []struct {
		name     string
		domain   string
		wantErr  bool
		minCount int
	}{
		{
			name:     "empty domain",
			domain:   "",
			wantErr:  true,
			minCount: 0,
		},
		{
			name:     "invalid domain",
			domain:   "nonexistent.invalid.domain.test",
			wantErr:  true, // Should error when SRV records not found
			minCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			servers, err := discovery.DiscoverServers(ctx, tt.domain)

			if tt.wantErr && err == nil {
				t.Errorf("DiscoverServers() expected error but got none")
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("DiscoverServers() unexpected error: %v", err)
				return
			}

			if len(servers) < tt.minCount {
				t.Errorf("DiscoverServers() got %d servers, want at least %d", len(servers), tt.minCount)
			}

			// Validate server info structure
			for i, server := range servers {
				if err := ValidateServerInfo(server); err != nil {
					t.Errorf("Server %d validation failed: %v", i, err)
				}
			}
		})
	}
}

func TestParseLDAPURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    *ServerInfo
		wantErr bool
	}{
		{
			name: "ldaps with port",
			url:  "ldaps://dc1.example.com:636",
			want: &ServerInfo{
				Host:     "dc1.example.com",
				Port:     636,
				UseTLS:   true,
				Priority: 0,
				Weight:   100,
				Source:   "config",
			},
			wantErr: false,
		},
		{
			name: "ldap with port",
			url:  "ldap://dc1.example.com:389",
			want: &ServerInfo{
				Host:     "dc1.example.com",
				Port:     389,
				UseTLS:   false,
				Priority: 0,
				Weight:   100,
				Source:   "config",
			},
			wantErr: false,
		},
		{
			name: "ldaps without port",
			url:  "ldaps://dc1.example.com",
			want: &ServerInfo{
				Host:     "dc1.example.com",
				Port:     636,
				UseTLS:   true,
				Priority: 0,
				Weight:   100,
				Source:   "config",
			},
			wantErr: false,
		},
		{
			name: "ldap without port",
			url:  "ldap://dc1.example.com",
			want: &ServerInfo{
				Host:     "dc1.example.com",
				Port:     389,
				UseTLS:   false,
				Priority: 0,
				Weight:   100,
				Source:   "config",
			},
			wantErr: false,
		},
		{
			name:    "empty URL",
			url:     "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid scheme",
			url:     "https://dc1.example.com",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid port",
			url:     "ldap://dc1.example.com:abc",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLDAPURL(tt.url)

			if tt.wantErr && err == nil {
				t.Errorf("ParseLDAPURL() expected error but got none")
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("ParseLDAPURL() unexpected error: %v", err)
				return
			}

			if !tt.wantErr && got != nil && tt.want != nil {
				if got.Host != tt.want.Host ||
					got.Port != tt.want.Port ||
					got.UseTLS != tt.want.UseTLS ||
					got.Source != tt.want.Source {
					t.Errorf("ParseLDAPURL() = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

func TestValidateServerInfo(t *testing.T) {
	tests := []struct {
		name    string
		server  *ServerInfo
		wantErr bool
	}{
		{
			name: "valid server",
			server: &ServerInfo{
				Host:     "dc1.example.com",
				Port:     636,
				UseTLS:   true,
				Priority: 0,
				Weight:   100,
				Source:   "config",
			},
			wantErr: false,
		},
		{
			name:    "nil server",
			server:  nil,
			wantErr: true,
		},
		{
			name: "empty host",
			server: &ServerInfo{
				Host:   "",
				Port:   636,
				UseTLS: true,
			},
			wantErr: true,
		},
		{
			name: "invalid port - zero",
			server: &ServerInfo{
				Host:   "dc1.example.com",
				Port:   0,
				UseTLS: true,
			},
			wantErr: true,
		},
		{
			name: "invalid port - too high",
			server: &ServerInfo{
				Host:   "dc1.example.com",
				Port:   70000,
				UseTLS: true,
			},
			wantErr: true,
		},
		{
			name: "negative priority",
			server: &ServerInfo{
				Host:     "dc1.example.com",
				Port:     636,
				Priority: -1,
				Weight:   100,
			},
			wantErr: true,
		},
		{
			name: "negative weight",
			server: &ServerInfo{
				Host:     "dc1.example.com",
				Port:     636,
				Priority: 0,
				Weight:   -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServerInfo(tt.server)

			if tt.wantErr && err == nil {
				t.Errorf("ValidateServerInfo() expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("ValidateServerInfo() unexpected error: %v", err)
			}
		})
	}
}

func TestServerInfoToURL(t *testing.T) {
	tests := []struct {
		name   string
		server *ServerInfo
		want   string
	}{
		{
			name: "ldaps server",
			server: &ServerInfo{
				Host:   "dc1.example.com",
				Port:   636,
				UseTLS: true,
			},
			want: "ldaps://dc1.example.com:636",
		},
		{
			name: "ldap server",
			server: &ServerInfo{
				Host:   "dc1.example.com",
				Port:   389,
				UseTLS: false,
			},
			want: "ldap://dc1.example.com:389",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ServerInfoToURL(tt.server)
			if got != tt.want {
				t.Errorf("ServerInfoToURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSortServersByPriority(t *testing.T) {
	discovery := NewSRVDiscovery(context.Background())

	servers := []*ServerInfo{
		{Host: "dc3", Priority: 2, Weight: 50},
		{Host: "dc1", Priority: 1, Weight: 100},
		{Host: "dc2", Priority: 1, Weight: 50},
		{Host: "dc4", Priority: 0, Weight: 100},
	}

	discovery.sortServersByPriority(servers)

	// Should be sorted by priority first, then by weight (descending)
	expected := []string{"dc4", "dc1", "dc2", "dc3"}

	for i, server := range servers {
		if server.Host != expected[i] {
			t.Errorf("Position %d: got %s, want %s", i, server.Host, expected[i])
		}
	}

	// Verify priority ordering
	if servers[0].Priority != 0 {
		t.Errorf("First server priority = %d, want 0", servers[0].Priority)
	}

	if servers[len(servers)-1].Priority != 2 {
		t.Errorf("Last server priority = %d, want 2", servers[len(servers)-1].Priority)
	}
}
