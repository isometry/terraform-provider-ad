package ldap_test

import (
	"context"
	"fmt"
	"log"

	"github.com/isometry/terraform-provider-ad/internal/ldap"
)

// ExampleUserReader_GetUser demonstrates how to retrieve a user by various identifiers.
func ExampleUserReader_GetUser() {
	// Assume we have a configured LDAP client
	var client ldap.Client
	baseDN := "DC=example,DC=com"

	reader := ldap.NewUserReader(client, baseDN)
	ctx := context.Background()

	// Get user by Distinguished Name
	user, err := reader.GetUser(ctx, "CN=John Doe,OU=Users,DC=example,DC=com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found user: %s (%s)\n", user.DisplayName, user.UserPrincipalName)

	// Get user by User Principal Name (auto-detected)
	user, err = reader.GetUser(ctx, "john.doe@example.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found user: %s (%s)\n", user.DisplayName, user.SAMAccountName)

	// Get user by SAM Account Name (auto-detected)
	user, err = reader.GetUser(ctx, "john.doe")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Account enabled: %t\n", user.AccountEnabled)
}

// ExampleUserReader_SearchUsersWithFilter demonstrates how to search for users with filters.
func ExampleUserReader_SearchUsersWithFilter() {
	var client ldap.Client
	baseDN := "DC=example,DC=com"

	reader := ldap.NewUserReader(client, baseDN)
	ctx := context.Background()

	// Search for enabled users in Engineering department
	filter := &ldap.UserSearchFilter{
		Department: "Engineering",
		Enabled:    boolPtr(true),
	}

	users, err := reader.SearchUsersWithFilter(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d engineers:\n", len(users))
	for _, user := range users {
		fmt.Printf("- %s (%s) - %s\n", user.DisplayName, user.EmailAddress, user.Title)
	}
}

// ExampleUserReader_SearchUsers demonstrates basic user search.
func ExampleUserReader_SearchUsers() {
	var client ldap.Client
	baseDN := "DC=example,DC=com"

	reader := ldap.NewUserReader(client, baseDN)
	ctx := context.Background()

	// Search for all users with email addresses
	users, err := reader.SearchUsers(ctx, "(mail=*)", []string{
		"displayName", "mail", "department", "title",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Users with email addresses:\n")
	for _, user := range users {
		fmt.Printf("%s <%s> - %s, %s\n",
			user.DisplayName, user.EmailAddress, user.Department, user.Title)
	}
}

// ExampleUserReader_GetUserStats demonstrates getting user statistics.
func ExampleUserReader_GetUserStats() {
	var client ldap.Client
	baseDN := "DC=example,DC=com"

	reader := ldap.NewUserReader(client, baseDN)
	ctx := context.Background()

	stats, err := reader.GetUserStats(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("User Statistics:\n")
	fmt.Printf("Total users: %d\n", stats["total"])
	fmt.Printf("Enabled: %d\n", stats["enabled"])
	fmt.Printf("Disabled: %d\n", stats["disabled"])
}

func boolPtr(b bool) *bool {
	return &b
}
