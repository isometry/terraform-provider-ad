package planmodifiers_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/isometry/terraform-provider-ad/internal/provider/planmodifiers"
)

func TestDefaultChangePasswordAtLogon_Descriptions(t *testing.T) {
	t.Parallel()

	m := planmodifiers.DefaultChangePasswordAtLogon()

	desc := m.Description(t.Context())
	if desc == "" {
		t.Error("expected non-empty description")
	}
	if !strings.Contains(desc, "change_password_at_logon") {
		t.Errorf("expected description to mention change_password_at_logon, got %q", desc)
	}
	if !strings.Contains(desc, "password") {
		t.Errorf("expected description to mention password, got %q", desc)
	}

	md := m.MarkdownDescription(t.Context())
	if md == "" {
		t.Error("expected non-empty markdown description")
	}
	if !strings.Contains(md, "change_password_at_logon") {
		t.Errorf("expected markdown description to mention change_password_at_logon, got %q", md)
	}
}

func TestDefaultChangePasswordAtLogon_PlanModifyBool(t *testing.T) {
	t.Parallel()

	// Schema mirrors the relevant subset of the user resource: a WriteOnly
	// password attribute and an Optional+Computed change_password_at_logon
	// attribute. The modifier only reads password from Config.
	s := schema.Schema{
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
	attrTypes := map[string]tftypes.Type{
		"password":                 tftypes.String,
		"change_password_at_logon": tftypes.Bool,
	}
	objType := tftypes.Object{AttributeTypes: attrTypes}

	stringValue := func(v *string) tftypes.Value {
		if v == nil {
			return tftypes.NewValue(tftypes.String, nil)
		}
		return tftypes.NewValue(tftypes.String, *v)
	}
	boolValue := func(v *bool) tftypes.Value {
		if v == nil {
			return tftypes.NewValue(tftypes.Bool, nil)
		}
		return tftypes.NewValue(tftypes.Bool, *v)
	}
	unknownString := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)

	makeObj := func(password, change tftypes.Value) tftypes.Value {
		return tftypes.NewValue(objType, map[string]tftypes.Value{
			"password":                 password,
			"change_password_at_logon": change,
		})
	}
	nullRaw := tftypes.NewValue(objType, nil)

	ptrStr := func(s string) *string { return &s }

	tests := map[string]struct {
		// Inputs to the plan modifier
		configRaw   tftypes.Value
		planRaw     tftypes.Value
		stateRaw    tftypes.Value
		configValue types.Bool
		stateValue  types.Bool
		planValue   types.Bool

		// Expected output
		expected types.Bool
	}{
		"create_with_password_defaults_false": {
			configRaw:   makeObj(stringValue(ptrStr("Sekret!1")), boolValue(nil)),
			planRaw:     makeObj(stringValue(ptrStr("Sekret!1")), tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(false),
		},
		"create_without_password_defaults_true": {
			configRaw:   makeObj(stringValue(nil), boolValue(nil)),
			planRaw:     makeObj(stringValue(nil), tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(true),
		},
		"create_with_empty_password_defaults_true": {
			configRaw:   makeObj(stringValue(ptrStr("")), boolValue(nil)),
			planRaw:     makeObj(stringValue(ptrStr("")), tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(true),
		},
		"user_explicit_true_preserved_with_password": {
			configRaw:   makeObj(stringValue(ptrStr("Sekret!1")), boolValue(new(true))),
			planRaw:     makeObj(stringValue(ptrStr("Sekret!1")), boolValue(new(true))),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(true),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"user_explicit_false_preserved_with_password": {
			configRaw:   makeObj(stringValue(ptrStr("Sekret!1")), boolValue(new(false))),
			planRaw:     makeObj(stringValue(ptrStr("Sekret!1")), boolValue(new(false))),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(false),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(false),
			expected:    types.BoolValue(false),
		},
		"user_explicit_true_preserved_without_password": {
			configRaw:   makeObj(stringValue(nil), boolValue(new(true))),
			planRaw:     makeObj(stringValue(nil), boolValue(new(true))),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(true),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"update_no_config_no_password_defaults_true": {
			// Update phase: state exists, config still leaves change null.
			// Modifier still applies (it is not gated to Create).
			configRaw:   makeObj(stringValue(nil), boolValue(nil)),
			planRaw:     makeObj(stringValue(nil), tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			stateRaw:    makeObj(stringValue(nil), boolValue(new(true))),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(true),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(true),
		},
		"update_no_config_with_password_defaults_false": {
			configRaw:   makeObj(stringValue(ptrStr("Sekret!1")), boolValue(nil)),
			planRaw:     makeObj(stringValue(ptrStr("Sekret!1")), tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			stateRaw:    makeObj(stringValue(ptrStr("Sekret!1")), boolValue(new(false))),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(false),
		},
		"unknown_config_with_password_defaults_false": {
			// Only explicit (non-null, non-unknown) user config values are
			// respected; an Unknown ConfigValue falls through to the
			// password-based default. With a password set, default is false.
			configRaw:   makeObj(stringValue(ptrStr("Sekret!1")), tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			planRaw:     makeObj(stringValue(ptrStr("Sekret!1")), tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			stateRaw:    nullRaw,
			configValue: types.BoolUnknown(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(false),
		},
		"unknown_config_without_password_defaults_true": {
			// Mirror of the above but without a password: defaults to true.
			configRaw:   makeObj(stringValue(nil), tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			planRaw:     makeObj(stringValue(nil), tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			stateRaw:    nullRaw,
			configValue: types.BoolUnknown(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(true),
		},
		"unknown_password_defaults_true": {
			// Unknown password is treated as "not set" for defaulting purposes.
			configRaw:   makeObj(unknownString, boolValue(nil)),
			planRaw:     makeObj(unknownString, tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(true),
		},
		"destroy_leaves_plan_value_alone": {
			// Destroy: plan.Raw is null. The modifier's config read returns
			// null for password -> defaults to true. We document the current
			// behaviour; callers typically skip destroy at the resource level.
			configRaw:   nullRaw,
			planRaw:     nullRaw,
			stateRaw:    makeObj(stringValue(ptrStr("Sekret!1")), boolValue(new(false))),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolNull(),
			expected:    types.BoolValue(true),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := planmodifier.BoolRequest{
				Path:        path.Root("change_password_at_logon"),
				ConfigValue: tc.configValue,
				StateValue:  tc.stateValue,
				PlanValue:   tc.planValue,
				Plan:        tfsdk.Plan{Schema: s, Raw: tc.planRaw},
				State:       tfsdk.State{Schema: s, Raw: tc.stateRaw},
				Config:      tfsdk.Config{Schema: s, Raw: tc.configRaw},
			}
			resp := &planmodifier.BoolResponse{PlanValue: req.PlanValue}

			planmodifiers.DefaultChangePasswordAtLogon().PlanModifyBool(t.Context(), req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %s", resp.Diagnostics)
			}
			if !resp.PlanValue.Equal(tc.expected) {
				t.Errorf("expected plan value %s, got %s", tc.expected, resp.PlanValue)
			}
		})
	}
}
