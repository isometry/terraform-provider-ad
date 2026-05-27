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

func TestEnabledRequiresPassword_Descriptions(t *testing.T) {
	t.Parallel()

	m := planmodifiers.EnabledRequiresPassword(path.Root("password"))

	desc := m.Description(t.Context())
	if !strings.Contains(desc, "password") {
		t.Errorf("expected description to mention password, got %q", desc)
	}

	md := m.MarkdownDescription(t.Context())
	if !strings.Contains(md, "password") {
		t.Errorf("expected markdown description to mention password, got %q", md)
	}
}

func TestEnabledRequiresPassword_PlanModifyBool(t *testing.T) {
	t.Parallel()

	// change_password_at_logon mirrors AD's pwdLastSet=0; the modifier reads
	// it from State as the "no usable credential" discriminator on Update.
	s := schema.Schema{
		Attributes: map[string]schema.Attribute{
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
			},
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"change_password_at_logon": schema.BoolAttribute{
				Computed: true,
			},
		},
	}
	attrTypes := map[string]tftypes.Type{
		"password":                 tftypes.String,
		"enabled":                  tftypes.Bool,
		"change_password_at_logon": tftypes.Bool,
	}
	objType := tftypes.Object{AttributeTypes: attrTypes}

	boolValue := func(v *bool) tftypes.Value {
		if v == nil {
			return tftypes.NewValue(tftypes.Bool, nil)
		}
		return tftypes.NewValue(tftypes.Bool, *v)
	}
	stringPassword := func(v *string) tftypes.Value {
		if v == nil {
			return tftypes.NewValue(tftypes.String, nil)
		}
		return tftypes.NewValue(tftypes.String, *v)
	}

	makeRaw := func(password tftypes.Value, enabled, cpal *bool) tftypes.Value {
		return tftypes.NewValue(objType, map[string]tftypes.Value{
			"password":                 password,
			"enabled":                  boolValue(enabled),
			"change_password_at_logon": boolValue(cpal),
		})
	}

	nullRaw := tftypes.NewValue(objType, nil)

	ptrBool := func(b bool) *bool { return &b }
	ptrStr := func(s string) *string { return &s }

	// Unknown password (e.g. sourced from an unresolved ephemeral resource).
	unknownPassword := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)

	tests := map[string]struct {
		configRaw   tftypes.Value
		planRaw     tftypes.Value
		stateRaw    tftypes.Value
		configValue types.Bool
		stateValue  types.Bool
		planValue   types.Bool
		expected    types.Bool
	}{
		"create_password_null_plan_true_is_forced_false": {
			configRaw:   makeRaw(stringPassword(nil), ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(true), nil),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(true),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(false),
		},
		"create_password_empty_string_plan_true_is_forced_false": {
			configRaw:   makeRaw(stringPassword(ptrStr("")), ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(ptrStr("")), ptrBool(true), nil),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(true),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(false),
		},
		"create_password_concrete_plan_true_unchanged": {
			configRaw:   makeRaw(stringPassword(ptrStr("Sekret!1")), ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(ptrStr("Sekret!1")), ptrBool(true), nil),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(true),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"create_password_unknown_plan_true_deferred": {
			configRaw:   makeRaw(unknownPassword, ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(true), nil),
			stateRaw:    nullRaw,
			configValue: types.BoolUnknown(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"update_state_true_password_null_plan_true_preserved": {
			configRaw:   makeRaw(stringPassword(nil), ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(true), nil),
			stateRaw:    makeRaw(stringPassword(nil), ptrBool(true), nil),
			configValue: types.BoolValue(true),
			stateValue:  types.BoolValue(true),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"update_state_true_password_null_plan_defaulted_true_preserved": {
			configRaw:   makeRaw(stringPassword(nil), nil, nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(true), nil),
			stateRaw:    makeRaw(stringPassword(nil), ptrBool(true), nil),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(true),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		// schema Default(true) synthesises a true plan; the modifier must
		// defeat it so subsequent plans agree with state (false).
		"update_state_false_config_null_plan_defaulted_true_preserved": {
			configRaw:   makeRaw(stringPassword(nil), nil, nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(true), nil),
			stateRaw:    makeRaw(stringPassword(nil), ptrBool(false), nil),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(false),
		},
		"update_state_false_password_null_plan_true_trust_user": {
			configRaw:   makeRaw(stringPassword(nil), ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(true), nil),
			stateRaw:    makeRaw(stringPassword(nil), ptrBool(false), nil),
			configValue: types.BoolValue(true),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"update_state_true_password_concrete_plan_true_unchanged": {
			configRaw:   makeRaw(stringPassword(ptrStr("Sekret!1")), ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(ptrStr("Sekret!1")), ptrBool(true), nil),
			stateRaw:    makeRaw(stringPassword(ptrStr("Sekret!1")), ptrBool(true), nil),
			configValue: types.BoolValue(true),
			stateValue:  types.BoolValue(true),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"destroy_leaves_plan_alone": {
			configRaw:   nullRaw,
			planRaw:     nullRaw,
			stateRaw:    makeRaw(stringPassword(nil), ptrBool(true), nil),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(true),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"create_plan_value_null_unchanged": {
			configRaw:   makeRaw(stringPassword(nil), nil, nil),
			planRaw:     makeRaw(stringPassword(nil), nil, nil),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolNull(),
			expected:    types.BoolNull(),
		},
		"create_plan_value_unknown_unchanged": {
			configRaw:   makeRaw(stringPassword(nil), nil, nil),
			planRaw:     makeRaw(stringPassword(nil), nil, nil),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolUnknown(),
			expected:    types.BoolUnknown(),
		},
		"create_plan_value_false_unchanged": {
			configRaw:   makeRaw(stringPassword(nil), ptrBool(false), nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(false), nil),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(false),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(false),
			expected:    types.BoolValue(false),
		},
		// State has pwdLastSet=0 (no usable credential); AD would refuse the
		// enable with 0000052D / ERROR_PASSWORD_RESTRICTION when no rotation
		// password is supplied.
		"update_cpal_true_config_true_no_password_forced_false": {
			configRaw:   makeRaw(stringPassword(nil), ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(true), nil),
			stateRaw:    makeRaw(stringPassword(nil), ptrBool(false), ptrBool(true)),
			configValue: types.BoolValue(true),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(false),
		},
		"update_cpal_true_config_true_with_password_unchanged": {
			configRaw:   makeRaw(stringPassword(ptrStr("Sekret!1")), ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(ptrStr("Sekret!1")), ptrBool(true), nil),
			stateRaw:    makeRaw(stringPassword(nil), ptrBool(false), ptrBool(true)),
			configValue: types.BoolValue(true),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"update_cpal_false_config_true_no_password_unchanged": {
			configRaw:   makeRaw(stringPassword(nil), ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(true), nil),
			stateRaw:    makeRaw(stringPassword(nil), ptrBool(false), ptrBool(false)),
			configValue: types.BoolValue(true),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"update_cpal_true_config_true_password_unknown_deferred": {
			configRaw:   makeRaw(unknownPassword, ptrBool(true), nil),
			planRaw:     makeRaw(stringPassword(nil), ptrBool(true), nil),
			stateRaw:    makeRaw(stringPassword(nil), ptrBool(false), ptrBool(true)),
			configValue: types.BoolValue(true),
			stateValue:  types.BoolValue(false),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := planmodifier.BoolRequest{
				Path:        path.Root("enabled"),
				ConfigValue: tc.configValue,
				StateValue:  tc.stateValue,
				PlanValue:   tc.planValue,
				Plan:        tfsdk.Plan{Schema: s, Raw: tc.planRaw},
				State:       tfsdk.State{Schema: s, Raw: tc.stateRaw},
				Config:      tfsdk.Config{Schema: s, Raw: tc.configRaw},
			}
			resp := &planmodifier.BoolResponse{PlanValue: req.PlanValue}

			planmodifiers.EnabledRequiresPassword(path.Root("password")).PlanModifyBool(t.Context(), req, resp)

			if !resp.PlanValue.Equal(tc.expected) {
				t.Errorf("expected plan value %s, got %s", tc.expected, resp.PlanValue)
			}
			if resp.Diagnostics.HasError() {
				t.Errorf("unexpected diagnostics: %s", resp.Diagnostics)
			}
		})
	}
}
