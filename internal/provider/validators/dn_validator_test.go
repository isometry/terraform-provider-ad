package validators_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/isometry/terraform-provider-ad/internal/provider/validators"
)

func TestDNValidator(t *testing.T) {
	t.Parallel()

	type testCase struct {
		val         types.String
		expectError bool
		summary     string
		detail      string
	}

	testCases := map[string]testCase{
		"valid DN simple": {
			val:         types.StringValue("CN=Test,DC=example,DC=com"),
			expectError: false,
		},
		"valid DN complex": {
			val:         types.StringValue("CN=John Doe,OU=Users,OU=IT,DC=corp,DC=example,DC=com"),
			expectError: false,
		},
		"valid DN with escaped characters": {
			val:         types.StringValue("CN=Test\\, User,OU=Users,DC=example,DC=com"),
			expectError: false,
		},
		"valid DN with spaces": {
			val:         types.StringValue("CN=Test User,OU=Domain Users,DC=example,DC=com"),
			expectError: false,
		},
		"invalid DN empty": {
			val:         types.StringValue(""),
			expectError: true,
			summary:     "Invalid Distinguished Name",
			detail:      "The value \"\" is not a valid Distinguished Name format:",
		},
		"invalid DN malformed": {
			val:         types.StringValue("invalid-dn"),
			expectError: true,
			summary:     "Invalid Distinguished Name",
			detail:      "The value \"invalid-dn\" is not a valid Distinguished Name format:",
		},
		"valid DN with empty value": {
			val:         types.StringValue("CN=,DC=example,DC=com"),
			expectError: false,
		},
		"invalid DN missing attribute": {
			val:         types.StringValue("=Test,DC=example,DC=com"),
			expectError: true,
			summary:     "Invalid Distinguished Name",
			detail:      "The value \"=Test,DC=example,DC=com\" is not a valid Distinguished Name format:",
		},
		"null value": {
			val:         types.StringNull(),
			expectError: false,
		},
		"unknown value": {
			val:         types.StringUnknown(),
			expectError: false,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := validator.StringRequest{
				Path:        path.Root("test"),
				ConfigValue: test.val,
			}
			response := validator.StringResponse{}

			validators.IsValidDN().ValidateString(t.Context(), request, &response)

			if !response.Diagnostics.HasError() && test.expectError {
				t.Fatal("expected error, got no error")
			}

			if response.Diagnostics.HasError() && !test.expectError {
				t.Fatalf("got unexpected error: %s", response.Diagnostics)
			}

			if test.expectError {
				if len(response.Diagnostics) != 1 {
					t.Fatalf("expected exactly 1 error, got %d", len(response.Diagnostics))
				}

				err := response.Diagnostics[0]
				if err.Summary() != test.summary {
					t.Errorf("expected summary %q, got %q", test.summary, err.Summary())
				}

				// Check that the detail contains our expected prefix
				if test.detail != "" {
					if len(err.Detail()) < len(test.detail) || err.Detail()[:len(test.detail)] != test.detail {
						t.Errorf("expected detail to start with %q, got %q", test.detail, err.Detail())
					}
				}
			}
		})
	}
}

func TestDNValidatorDescription(t *testing.T) {
	validator := validators.IsValidDN()

	expected := "value must be a valid Distinguished Name (DN)"
	if validator.Description(t.Context()) != expected {
		t.Errorf("expected description %q, got %q", expected, validator.Description(t.Context()))
	}

	if validator.MarkdownDescription(t.Context()) != expected {
		t.Errorf("expected markdown description %q, got %q", expected, validator.MarkdownDescription(t.Context()))
	}
}
