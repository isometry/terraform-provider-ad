package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/isometry/terraform-provider-ad/internal/ldap"
)

// Benchmark tests for critical operations

// BenchmarkGroupSearch benchmarks group search operations.
func BenchmarkGroupSearch(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	helper := NewBenchmarkHelper(b)
	defer helper.Close()

	ctx := context.Background()
	groupManager := ldap.NewGroupManager(helper.client, helper.config.BaseDN)

	// Create test groups
	testGroups, err := helper.CreateTestGroups(ctx, 100)
	if err != nil {
		b.Fatalf("Failed to create test groups: %v", err)
	}
	defer helper.CleanupTestGroups(ctx, testGroups)

	b.ResetTimer()

	// Benchmark searching for groups
	b.Run("SearchByFilter", func(b *testing.B) {
		filter := "(objectClass=group)"
		for i := 0; i < b.N; i++ {
			_, err := groupManager.SearchGroups(ctx, filter, []string{"objectGUID", "name"})
			if err != nil {
				b.Fatalf("Search failed: %v", err)
			}
		}
	})

	b.Run("GetByID", func(b *testing.B) {
		groupID := testGroups[0] // Use first test group
		for i := 0; i < b.N; i++ {
			_, err := groupManager.GetGroup(ctx, groupID)
			if err != nil {
				b.Fatalf("GetGroup failed: %v", err)
			}
		}
	})
}

// BenchmarkGroupMembership benchmarks group membership operations.
func BenchmarkGroupMembership(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	helper := NewBenchmarkHelper(b)
	defer helper.Close()

	ctx := context.Background()
	// Create test groups
	testGroups, err := helper.CreateTestGroups(ctx, 10)
	if err != nil {
		b.Fatalf("Failed to create test groups: %v", err)
	}
	defer helper.CleanupTestGroups(ctx, testGroups)

	// Create a group with many members
	memberGroups, err := helper.CreateTestGroups(ctx, 50)
	if err != nil {
		b.Fatalf("Failed to create member groups: %v", err)
	}
	defer helper.CleanupTestGroups(ctx, memberGroups)

	// Convert member group IDs to DNs
	groupManager := ldap.NewGroupManager(helper.client, helper.config.BaseDN)
	memberDNs := make([]string, len(memberGroups))
	for i, groupID := range memberGroups {
		group, err := groupManager.GetGroup(ctx, groupID)
		if err != nil {
			b.Fatalf("Failed to get member group %d: %v", i, err)
		}
		memberDNs[i] = group.DistinguishedName
	}

	// Add members to first test group
	mainGroupID := testGroups[0]
	membershipManager := ldap.NewGroupMembershipManager(helper.client, helper.config.BaseDN)
	err = membershipManager.SetGroupMembers(ctx, mainGroupID, memberDNs)
	if err != nil {
		b.Fatalf("Failed to set members: %v", err)
	}

	b.ResetTimer()

	b.Run("GetMembers", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := membershipManager.GetGroupMembers(ctx, mainGroupID)
			if err != nil {
				b.Fatalf("GetMembers failed: %v", err)
			}
		}
	})

	b.Run("AddMember", func(b *testing.B) {
		targetGroupID := testGroups[1] // Use second test group
		memberDN := memberDNs[0]       // Use first member DN

		for i := 0; i < b.N; i++ {
			// Add member
			err := membershipManager.AddGroupMembers(ctx, targetGroupID, []string{memberDN})
			if err != nil {
				b.Logf("AddMember may have failed (expected for duplicate adds): %v", err)
			}

			// Remove member for next iteration (except last one)
			if i < b.N-1 {
				err = membershipManager.RemoveGroupMembers(ctx, targetGroupID, []string{memberDN})
				if err != nil {
					b.Logf("RemoveMember may have failed: %v", err)
				}
			}
		}
	})
}

// BenchmarkUserSearch benchmarks user search operations.
func BenchmarkUserSearch(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	helper := NewBenchmarkHelper(b)
	defer helper.Close()

	ctx := context.Background()
	userReader := ldap.NewUserReader(helper.client, helper.config.BaseDN)

	b.ResetTimer()

	b.Run("SearchByFilter", func(b *testing.B) {
		filter := "(objectClass=user)"
		for i := 0; i < b.N; i++ {
			_, err := userReader.SearchUsers(ctx, filter, []string{"objectGUID", "userPrincipalName"})
			if err != nil {
				b.Fatalf("Search failed: %v", err)
			}
		}
	})

	b.Run("GetByUPN", func(b *testing.B) {
		upn := "Administrator@" + helper.config.Domain
		for i := 0; i < b.N; i++ {
			_, err := userReader.GetUserByUPN(ctx, upn)
			if err != nil && !ldap.IsNotFoundError(err) {
				b.Fatalf("GetByUPN failed: %v", err)
			}
		}
	})
}

// BenchmarkConnectionPool benchmarks connection pool performance.
func BenchmarkConnectionPool(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	config := GetTestConfig()
	ldapConfig := &ldap.ConnectionConfig{
		Domain:         config.Domain,
		LDAPURLs:       []string{config.LDAPURL},
		Username:       config.Username,
		Password:       config.Password,
		KerberosKeytab: config.Keytab,
		KerberosRealm:  config.Realm,
	}

	b.Run("ClientCreation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			client, err := ldap.NewClient(ldapConfig)
			if err != nil {
				b.Fatalf("Failed to create client: %v", err)
			}
			client.Close()
		}
	})

	b.Run("ConcurrentConnections", func(b *testing.B) {
		client, err := ldap.NewClient(ldapConfig)
		if err != nil {
			b.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// Test simple LDAP operation
				req := &ldap.SearchRequest{
					BaseDN:     config.BaseDN,
					Scope:      ldap.ScopeWholeSubtree,
					Filter:     "(objectClass=domain)",
					Attributes: []string{"distinguishedName"},
					SizeLimit:  1,
				}
				_, err := client.Search(context.Background(), req)
				if err != nil {
					b.Fatalf("Search failed: %v", err)
				}
			}
		})
	})
}

// BenchmarkPagination benchmarks paginated search operations.
func BenchmarkPagination(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	helper := NewBenchmarkHelper(b)
	defer helper.Close()

	ctx := context.Background()

	// Test different page sizes
	pageSizes := []int{10, 50, 100, 500}

	for _, pageSize := range pageSizes {
		b.Run(fmt.Sprintf("PageSize_%d", pageSize), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				req := &ldap.SearchRequest{
					BaseDN:     helper.config.BaseDN,
					Scope:      ldap.ScopeWholeSubtree,
					Filter:     "(objectClass=*)",
					Attributes: []string{"objectGUID"},
					SizeLimit:  pageSize,
				}
				_, err := helper.client.SearchWithPaging(ctx, req)
				if err != nil {
					b.Fatalf("Paginated search failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkNormalizer benchmarks member identifier normalization.
func BenchmarkNormalizer(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	helper := NewBenchmarkHelper(b)
	defer helper.Close()

	ctx := context.Background()
	normalizer := ldap.NewMemberNormalizer(helper.client, helper.config.BaseDN)

	// Create a test group to get its various identifiers
	testGroups, err := helper.CreateTestGroups(ctx, 1)
	if err != nil {
		b.Fatalf("Failed to create test group: %v", err)
	}
	defer helper.CleanupTestGroups(ctx, testGroups)

	groupManager := ldap.NewGroupManager(helper.client, helper.config.BaseDN)
	group, err := groupManager.GetGroup(ctx, testGroups[0])
	if err != nil {
		b.Fatalf("Failed to get test group: %v", err)
	}

	b.ResetTimer()

	// Test normalization of different identifier types
	b.Run("NormalizeGUID", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := normalizer.NormalizeToDN(group.ObjectGUID)
			if err != nil {
				b.Fatalf("GUID normalization failed: %v", err)
			}
		}
	})

	b.Run("NormalizeDN", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := normalizer.NormalizeToDN(group.DistinguishedName)
			if err != nil {
				b.Fatalf("DN normalization failed: %v", err)
			}
		}
	})

	b.Run("NormalizeSAM", func(b *testing.B) {
		samName := helper.config.Domain + "\\" + group.SAMAccountName
		for i := 0; i < b.N; i++ {
			_, err := normalizer.NormalizeToDN(samName)
			if err != nil {
				b.Fatalf("SAM normalization failed: %v", err)
			}
		}
	})
}

// BenchmarkMemoryUsage benchmarks memory usage during operations.
func BenchmarkMemoryUsage(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	helper := NewBenchmarkHelper(b)
	defer helper.Close()

	ctx := context.Background()
	groupManager := ldap.NewGroupManager(helper.client, helper.config.BaseDN)

	// Create a large number of test groups
	testGroups, err := helper.CreateTestGroups(ctx, 500)
	if err != nil {
		b.Fatalf("Failed to create test groups: %v", err)
	}
	defer helper.CleanupTestGroups(ctx, testGroups)

	b.ResetTimer()

	b.Run("LargeResultSet", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			filter := "(objectClass=group)"
			results, err := groupManager.SearchGroups(ctx, filter, []string{
				"objectGUID", "distinguishedName", "name", "sAMAccountName",
				"description", "groupType", "member",
			})
			if err != nil {
				b.Fatalf("Large search failed: %v", err)
			}

			// Process results to simulate real usage
			for _, result := range results {
				_ = result.ObjectGUID
				_ = result.DistinguishedName
				_ = result.Name
			}
		}
	})
}

// BenchmarkErrorHandling benchmarks error handling performance.
func BenchmarkErrorHandling(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	helper := NewBenchmarkHelper(b)
	defer helper.Close()

	ctx := context.Background()
	groupManager := ldap.NewGroupManager(helper.client, helper.config.BaseDN)

	b.ResetTimer()

	b.Run("NotFoundErrors", func(b *testing.B) {
		nonExistentGUID := "550e8400-e29b-41d4-a716-446655440000"
		for i := 0; i < b.N; i++ {
			_, err := groupManager.GetGroup(ctx, nonExistentGUID)
			if err == nil {
				b.Fatal("Expected not found error")
			}
			if !ldap.IsNotFoundError(err) {
				b.Fatalf("Unexpected error type: %v", err)
			}
		}
	})

	b.Run("InvalidFilter", func(b *testing.B) {
		invalidFilter := "(invalid filter syntax"
		for i := 0; i < b.N; i++ {
			_, err := groupManager.SearchGroups(ctx, invalidFilter, []string{"objectGUID"})
			if err == nil {
				b.Fatal("Expected filter error")
			}
		}
	})
}

// BenchmarkConcurrency tests concurrent operations.
func BenchmarkConcurrency(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	helper := NewBenchmarkHelper(b)
	defer helper.Close()

	ctx := context.Background()
	groupManager := ldap.NewGroupManager(helper.client, helper.config.BaseDN)

	// Create test groups
	testGroups, err := helper.CreateTestGroups(ctx, 10)
	if err != nil {
		b.Fatalf("Failed to create test groups: %v", err)
	}
	defer helper.CleanupTestGroups(ctx, testGroups)

	b.ResetTimer()

	b.Run("ConcurrentReads", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				groupID := testGroups[i%len(testGroups)]
				_, err := groupManager.GetGroup(ctx, groupID)
				if err != nil {
					b.Fatalf("Concurrent read failed: %v", err)
				}
				i++
			}
		})
	})

	b.Run("ConcurrentSearches", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				filter := "(objectClass=group)"
				_, err := groupManager.SearchGroups(ctx, filter, []string{"objectGUID"})
				if err != nil {
					b.Fatalf("Concurrent search failed: %v", err)
				}
			}
		})
	})
}

// Performance regression test.
func BenchmarkPerformanceRegression(b *testing.B) {
	if !IsAccTest() {
		b.Skip("Skipping benchmark - set TF_ACC=1 to run")
	}

	helper := NewBenchmarkHelper(b)
	defer helper.Close()

	// Create test function with maxTime captured in closure
	maxTime := 100 * time.Millisecond // Max 100ms per operation

	// Baseline performance expectations (adjust based on your environment)
	tests := []struct {
		name     string
		maxTime  time.Duration
		testFunc func(b *testing.B)
	}{
		{
			name:    "GroupGetByID",
			maxTime: maxTime,
			testFunc: func(b *testing.B) {
				ctx := context.Background()
				groupManager := ldap.NewGroupManager(helper.client, helper.config.BaseDN)

				// Create a test group
				testGroups, err := helper.CreateTestGroups(ctx, 1)
				if err != nil {
					b.Fatalf("Failed to create test group: %v", err)
				}
				defer helper.CleanupTestGroups(ctx, testGroups)

				groupID := testGroups[0]

				b.ResetTimer()
				start := time.Now()

				for i := 0; i < b.N; i++ {
					_, err := groupManager.GetGroup(ctx, groupID)
					if err != nil {
						b.Fatalf("GetGroup failed: %v", err)
					}
				}

				elapsed := time.Since(start)
				avgTime := elapsed / time.Duration(b.N)

				if avgTime > maxTime {
					b.Fatalf("Performance regression: average time %v exceeds maximum %v", avgTime, maxTime)
				}
			},
		},
	}

	for _, test := range tests {
		b.Run(test.name, test.testFunc)
	}
}
