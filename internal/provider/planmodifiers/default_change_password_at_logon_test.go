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
	if !strings.Contains(strings.ToLower(desc), "update") {
		t.Errorf("expected description to mention update semantics, got %q", desc)
	}

	md := m.MarkdownDescription(t.Context())
	if md == "" {
		t.Error("expected non-empty markdown description")
	}
	if !strings.Contains(md, "change_password_at_logon") {
		t.Errorf("expected markdown description to mention change_password_at_logon, got %q", md)
	}
	if !strings.Contains(strings.ToLower(md), "update") {
		t.Errorf("expected markdown description to mention update semantics, got %q", md)
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
	unknownBool := tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)

	makeObj := func(password, change tftypes.Value) tftypes.Value {
		return tftypes.NewValue(objType, map[string]tftypes.Value{
			"password":                 password,
			"change_password_at_logon": change,
		})
	}
	nullRaw := tftypes.NewValue(objType, nil)

	ptrStr := func(s string) *string { return &s }
	ptrBool := func(b bool) *bool { return &b }

	const concretePassword = "Sekret!1"

	type testCase struct {
		configRaw   tftypes.Value
		planRaw     tftypes.Value
		stateRaw    tftypes.Value
		configValue types.Bool
		stateValue  types.Bool
		planValue   types.Bool
		expected    types.Bool
	}

	tests := map[string]testCase{
		"passthrough_explicit_config_value_create": {
			configRaw:   makeObj(stringValue(ptrStr(concretePassword)), boolValue(ptrBool(true))),
			planRaw:     makeObj(stringValue(ptrStr(concretePassword)), boolValue(ptrBool(true))),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(true),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"passthrough_explicit_config_false_update": {
			configRaw:   makeObj(stringValue(nil), boolValue(ptrBool(false))),
			planRaw:     makeObj(stringValue(nil), boolValue(ptrBool(false))),
			stateRaw:    makeObj(stringValue(nil), boolValue(ptrBool(true))),
			configValue: types.BoolValue(false),
			stateValue:  types.BoolValue(true),
			planValue:   types.BoolValue(false),
			expected:    types.BoolValue(false),
		},
		"create_null_password_defaults_true": {
			configRaw:   makeObj(stringValue(nil), boolValue(nil)),
			planRaw:     makeObj(stringValue(nil), unknownBool),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(true),
		},
		"create_empty_password_defaults_true": {
			configRaw:   makeObj(stringValue(ptrStr("")), boolValue(nil)),
			planRaw:     makeObj(stringValue(ptrStr("")), unknownBool),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(true),
		},
		"create_concrete_password_defaults_false": {
			configRaw:   makeObj(stringValue(ptrStr(concretePassword)), boolValue(nil)),
			planRaw:     makeObj(stringValue(ptrStr(concretePassword)), unknownBool),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(false),
		},
		// Unknown password (ephemeral source) defers to apply.
		"create_unknown_password_defers_unknown": {
			configRaw:   makeObj(unknownString, boolValue(nil)),
			planRaw:     makeObj(unknownString, unknownBool),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolUnknown(),
		},
		"update_state_false_null_password_preserved": {
			configRaw:   makeObj(stringValue(nil), boolValue(nil)),
			planRaw:     makeObj(stringValue(nil), unknownBool),
			stateRaw:    makeObj(stringValue(nil), boolValue(ptrBool(false))),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(false),
		},
		"update_state_true_null_password_preserved": {
			configRaw:   makeObj(stringValue(nil), boolValue(nil)),
			planRaw:     makeObj(stringValue(nil), unknownBool),
			stateRaw:    makeObj(stringValue(nil), boolValue(ptrBool(true))),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(true),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(true),
		},
		// On Update the modifier must never consult config.password —
		// preserve state regardless of password presence.
		"update_state_false_concrete_password_preserved": {
			configRaw:   makeObj(stringValue(ptrStr(concretePassword)), boolValue(nil)),
			planRaw:     makeObj(stringValue(ptrStr(concretePassword)), unknownBool),
			stateRaw:    makeObj(stringValue(ptrStr(concretePassword)), boolValue(ptrBool(false))),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolValue(false),
		},
		"update_state_true_concrete_password_preserved": {
			configRaw:   makeObj(stringValue(ptrStr(concretePassword)), boolValue(nil)),
			planRaw:     makeObj(stringValue(ptrStr(concretePassword)), unknownBool),
			stateRaw:    makeObj(stringValue(ptrStr(concretePassword)), boolValue(ptrBool(true))),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(true),
			planValue:   types.BoolUnknown(),
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
