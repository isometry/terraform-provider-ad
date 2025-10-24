package validators

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestCaseInsensitiveOneOf(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		validator validator.String
		input     types.String
		expectErr bool
	}{
		"valid-exact-match": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("Global"),
			expectErr: false,
		},
		"valid-lowercase": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("global"),
			expectErr: false,
		},
		"valid-uppercase": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("GLOBAL"),
			expectErr: false,
		},
		"valid-mixed-case": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("gLoBaL"),
			expectErr: false,
		},
		"valid-with-whitespace": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("  Global  "),
			expectErr: false,
		},
		"valid-universal-lowercase": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("universal"),
			expectErr: false,
		},
		"valid-domainlocal-mixed": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("DomainLocal"),
			expectErr: false,
		},
		"valid-domainlocal-lowercase": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("domainlocal"),
			expectErr: false,
		},
		"invalid-value": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("Invalid"),
			expectErr: true,
		},
		"invalid-partial-match": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringValue("Glob"),
			expectErr: true,
		},
		"valid-category-security": {
			validator: CaseInsensitiveOneOf("Security", "Distribution"),
			input:     types.StringValue("security"),
			expectErr: false,
		},
		"valid-category-distribution-caps": {
			validator: CaseInsensitiveOneOf("Security", "Distribution"),
			input:     types.StringValue("DISTRIBUTION"),
			expectErr: false,
		},
		"null-value": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringNull(),
			expectErr: false,
		},
		"unknown-value": {
			validator: CaseInsensitiveOneOf("Global", "Universal", "DomainLocal"),
			input:     types.StringUnknown(),
			expectErr: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := validator.StringRequest{
				Path:        path.Root("test"),
				ConfigValue: testCase.input,
			}
			resp := validator.StringResponse{}

			testCase.validator.ValidateString(context.Background(), req, &resp)

			if testCase.expectErr && !resp.Diagnostics.HasError() {
				t.Fatal("expected error, got none")
			}

			if !testCase.expectErr && resp.Diagnostics.HasError() {
				t.Fatalf("unexpected error: %s", resp.Diagnostics)
			}
		})
	}
}

func TestCaseInsensitiveOneOf_Description(t *testing.T) {
	t.Parallel()

	v := CaseInsensitiveOneOf("Global", "Universal", "DomainLocal")
	desc := v.Description(context.Background())

	if desc == "" {
		t.Fatal("expected non-empty description")
	}

	// Check that description contains the valid values
	containsValues := false
	for _, expected := range []string{"Global", "Universal", "DomainLocal"} {
		if strings.Contains(desc, expected) {
			containsValues = true
			break
		}
	}

	if !containsValues {
		t.Fatalf("expected description to contain valid values, got: %s", desc)
	}
}

func TestCaseInsensitiveOneOf_MarkdownDescription(t *testing.T) {
	t.Parallel()

	v := CaseInsensitiveOneOf("Global", "Universal", "DomainLocal")
	mdDesc := v.MarkdownDescription(context.Background())
	desc := v.Description(context.Background())

	if mdDesc != desc {
		t.Fatalf("expected markdown description to match description, got: %s vs %s", mdDesc, desc)
	}
}
