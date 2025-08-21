package provider

import (
	"testing"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// TestValidateMemberIdentifiers tests member identifier validation.
func TestValidateMemberIdentifiers(t *testing.T) {
	testCases := []struct {
		name      string
		members   []string
		expectErr bool
	}{
		{
			name:      "empty members",
			members:   []string{},
			expectErr: false,
		},
		{
			name:      "nil members",
			members:   nil,
			expectErr: false,
		},
		{
			name: "valid DN",
			members: []string{
				"CN=TestUser,CN=Users,DC=example,DC=com",
			},
			expectErr: false,
		},
		{
			name: "valid GUID",
			members: []string{
				"550e8400-e29b-41d4-a716-446655440000",
			},
			expectErr: false,
		},
		{
			name: "valid SID",
			members: []string{
				"S-1-5-21-123456789-123456789-123456789-1001",
			},
			expectErr: false,
		},
		{
			name: "valid UPN",
			members: []string{
				"user@example.com",
			},
			expectErr: false,
		},
		{
			name: "valid SAM with domain",
			members: []string{
				"EXAMPLE\\user",
			},
			expectErr: false,
		},
		{
			name: "mixed valid identifiers",
			members: []string{
				"CN=TestUser,CN=Users,DC=example,DC=com",
				"550e8400-e29b-41d4-a716-446655440000",
				"user@example.com",
				"EXAMPLE\\user",
			},
			expectErr: false,
		},
		{
			name: "invalid identifier",
			members: []string{
				"@invalid.com", // Invalid UPN format (missing username)
			},
			expectErr: true,
		},
		{
			name: "mixed valid and invalid",
			members: []string{
				"CN=TestUser,CN=Users,DC=example,DC=com",
				"domain\\", // Invalid SAM format (missing username)
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the validation directly using the normalizer since we're only
			// testing format validation, not actual LDAP resolution
			normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com")

			// Create a temporary manager-like validator
			var err error
			for _, member := range tc.members {
				if validationErr := normalizer.ValidateIdentifier(member); validationErr != nil {
					err = validationErr
					break
				}
			}

			if tc.expectErr && err == nil {
				t.Error("Expected error but got none")
			}

			if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestGetMembershipManager tests membership manager creation.
func TestGetMembershipManager(t *testing.T) {
	// This test requires a real LDAP client, so skip in unit tests
	// It should be tested in integration/acceptance tests where
	// a proper LDAP client is configured
	t.Skip("getMembershipManager requires LDAP client - test in integration tests")
}

// Benchmark tests for plan modifier functions.
func BenchmarkValidateMemberIdentifiers(b *testing.B) {
	members := []string{
		"CN=TestUser1,CN=Users,DC=example,DC=com",
		"CN=TestUser2,CN=Users,DC=example,DC=com",
		"550e8400-e29b-41d4-a716-446655440000",
		"user@example.com",
		"EXAMPLE\\user",
		"S-1-5-21-123456789-123456789-123456789-1001",
	}

	// Test validation directly using the normalizer for benchmarks
	normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, member := range members {
			_ = normalizer.ValidateIdentifier(member)
		}
	}
}

// Test helper function to create various member identifier formats.
func createTestMembers(count int) []string {
	members := make([]string, count)

	for i := 0; i < count; i++ {
		switch i % 5 {
		case 0:
			members[i] = "CN=TestUser" + string(rune(i)) + ",CN=Users,DC=example,DC=com"
		case 1:
			members[i] = "550e8400-e29b-41d4-a716-44665544000" + string(rune(i))
		case 2:
			members[i] = "user" + string(rune(i)) + "@example.com"
		case 3:
			members[i] = "EXAMPLE\\user" + string(rune(i))
		case 4:
			members[i] = "S-1-5-21-123456789-123456789-123456789-100" + string(rune(i))
		}
	}

	return members
}

// Benchmark with different member counts.
func BenchmarkValidateMemberIdentifiers10(b *testing.B) {
	members := createTestMembers(10)
	normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, member := range members {
			_ = normalizer.ValidateIdentifier(member)
		}
	}
}

func BenchmarkValidateMemberIdentifiers100(b *testing.B) {
	members := createTestMembers(100)
	normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, member := range members {
			_ = normalizer.ValidateIdentifier(member)
		}
	}
}

func BenchmarkValidateMemberIdentifiers1000(b *testing.B) {
	members := createTestMembers(1000)
	normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, member := range members {
			_ = normalizer.ValidateIdentifier(member)
		}
	}
}
