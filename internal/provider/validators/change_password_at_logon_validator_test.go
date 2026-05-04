package validators_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/isometry/terraform-provider-ad/internal/provider/validators"
)

// testConfigSchema returns a schema containing the two attributes the
// validator inspects: password (WriteOnly, Optional) and
// change_password_at_logon (Optional, Computed).
func testConfigSchema() schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
			},
			"change_password_at_logon": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
		},
	}
}

// makeConfig constructs a tfsdk.Config using the raw tftypes.Value supplied
// for each attribute. Passing a nil value yields the attribute's null value.
func makeConfig(password, changePasswordAtLogon tftypes.Value) tfsdk.Config {
	objType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"password":                 tftypes.String,
			"change_password_at_logon": tftypes.Bool,
		},
	}
	raw := tftypes.NewValue(objType, map[string]tftypes.Value{
		"password":                 password,
		"change_password_at_logon": changePasswordAtLogon,
	})
	return tfsdk.Config{Schema: testConfigSchema(), Raw: raw}
}

func TestChangePasswordAtLogonRequiresPassword_ValidateResource(t *testing.T) {
	t.Parallel()

	stringVal := func(v string) tftypes.Value {
		return tftypes.NewValue(tftypes.String, v)
	}
	stringNull := tftypes.NewValue(tftypes.String, nil)
	stringUnknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)

	boolVal := func(v bool) tftypes.Value {
		return tftypes.NewValue(tftypes.Bool, v)
	}
	boolNull := tftypes.NewValue(tftypes.Bool, nil)
	boolUnknown := tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)

	tests := map[string]struct {
		password              tftypes.Value
		changePasswordAtLogon tftypes.Value
		expectError           bool
		expectSummary         string
		expectDetailContains  string
	}{
		"change_false_no_password_errors": {
			password:              stringNull,
			changePasswordAtLogon: boolVal(false),
			expectError:           true,
			expectSummary:         "change_password_at_logon = false requires a password",
			expectDetailContains:  "not supported for passwordless accounts",
		},
		"change_false_empty_password_errors": {
			password:              stringVal(""),
			changePasswordAtLogon: boolVal(false),
			expectError:           true,
			expectSummary:         "change_password_at_logon = false requires a password",
			expectDetailContains:  "passwordless accounts",
		},
		"change_false_with_password_ok": {
			password:              stringVal("Sekret!1"),
			changePasswordAtLogon: boolVal(false),
			expectError:           false,
		},
		"change_true_no_password_ok": {
			password:              stringNull,
			changePasswordAtLogon: boolVal(true),
			expectError:           false,
		},
		"change_true_with_password_ok": {
			password:              stringVal("Sekret!1"),
			changePasswordAtLogon: boolVal(true),
			expectError:           false,
		},
		"change_null_no_password_ok": {
			password:              stringNull,
			changePasswordAtLogon: boolNull,
			expectError:           false,
		},
		"change_null_with_password_ok": {
			password:              stringVal("Sekret!1"),
			changePasswordAtLogon: boolNull,
			expectError:           false,
		},
		"change_unknown_ok": {
			password:              stringNull,
			changePasswordAtLogon: boolUnknown,
			expectError:           false,
		},
		"change_false_password_unknown_defers": {
			// When password is unknown, validation must be deferred until
			// final plan: no error raised here.
			password:              stringUnknown,
			changePasswordAtLogon: boolVal(false),
			expectError:           false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := makeConfig(tc.password, tc.changePasswordAtLogon)

			req := resource.ValidateConfigRequest{Config: cfg}
			resp := &resource.ValidateConfigResponse{}

			validators.ChangePasswordAtLogonRequiresPassword().ValidateResource(t.Context(), req, resp)

			if resp.Diagnostics.HasError() && !tc.expectError {
				t.Fatalf("unexpected error diagnostics: %s", resp.Diagnostics)
			}
			if !resp.Diagnostics.HasError() && tc.expectError {
				t.Fatalf("expected error diagnostics, got none")
			}

			if tc.expectError {
				if len(resp.Diagnostics.Errors()) != 1 {
					t.Fatalf("expected exactly 1 error diagnostic, got %d: %s",
						len(resp.Diagnostics.Errors()), resp.Diagnostics)
				}
				d := resp.Diagnostics.Errors()[0]
				if d.Summary() != tc.expectSummary {
					t.Errorf("expected summary %q, got %q", tc.expectSummary, d.Summary())
				}
				if tc.expectDetailContains != "" && !strings.Contains(d.Detail(), tc.expectDetailContains) {
					t.Errorf("expected detail to contain %q, got %q", tc.expectDetailContains, d.Detail())
				}
			}
		})
	}
}

func TestChangePasswordAtLogonRequiresPassword_Descriptions(t *testing.T) {
	t.Parallel()

	v := validators.ChangePasswordAtLogonRequiresPassword()

	desc := v.Description(t.Context())
	if desc == "" {
		t.Error("expected non-empty description")
	}
	if !strings.Contains(desc, "change_password_at_logon") {
		t.Errorf("expected description to mention change_password_at_logon, got %q", desc)
	}
	if !strings.Contains(desc, "password") {
		t.Errorf("expected description to mention password, got %q", desc)
	}

	md := v.MarkdownDescription(t.Context())
	if md == "" {
		t.Error("expected non-empty markdown description")
	}
	if !strings.Contains(md, "change_password_at_logon") {
		t.Errorf("expected markdown description to mention change_password_at_logon, got %q", md)
	}
}
