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

	// Schema mirrors the relevant subset of the user resource: a WriteOnly
	// password attribute and a computed/optional enabled attribute. The
	// modifier only reads password from Config, so the schema just has to
	// describe both attributes with compatible types.
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
		},
	}
	attrTypes := map[string]tftypes.Type{
		"password": tftypes.String,
		"enabled":  tftypes.Bool,
	}
	objType := tftypes.Object{AttributeTypes: attrTypes}

	boolValue := func(v *bool) tftypes.Value {
		if v == nil {
			return tftypes.NewValue(tftypes.Bool, nil)
		}
		return tftypes.NewValue(tftypes.Bool, *v)
	}
	stringValue := func(v *string) tftypes.Value {
		if v == nil {
			return tftypes.NewValue(tftypes.String, nil)
		}
		return tftypes.NewValue(tftypes.String, *v)
	}

	makeRaw := func(password *string, enabled *bool) tftypes.Value {
		return tftypes.NewValue(objType, map[string]tftypes.Value{
			"password": stringValue(password),
			"enabled":  boolValue(enabled),
		})
	}

	nullRaw := tftypes.NewValue(objType, nil)

	ptrBool := func(b bool) *bool { return &b }
	ptrStr := func(s string) *string { return &s }

	tests := map[string]struct {
		configRaw   tftypes.Value
		planRaw     tftypes.Value
		stateRaw    tftypes.Value
		configValue types.Bool
		stateValue  types.Bool
		planValue   types.Bool
		expected    types.Bool
	}{
		"no_password_plan_true_is_forced_false": {
			configRaw:   makeRaw(nil, ptrBool(true)),
			planRaw:     makeRaw(nil, ptrBool(true)),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(true),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(false),
		},
		"no_password_empty_string_plan_true_is_forced_false": {
			configRaw:   makeRaw(ptrStr(""), ptrBool(true)),
			planRaw:     makeRaw(ptrStr(""), ptrBool(true)),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(true),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(false),
		},
		"no_password_plan_false_unchanged": {
			configRaw:   makeRaw(nil, ptrBool(false)),
			planRaw:     makeRaw(nil, ptrBool(false)),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(false),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(false),
			expected:    types.BoolValue(false),
		},
		"password_set_plan_true_unchanged": {
			configRaw:   makeRaw(ptrStr("Sekret!1"), ptrBool(true)),
			planRaw:     makeRaw(ptrStr("Sekret!1"), ptrBool(true)),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(true),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"password_set_plan_false_unchanged": {
			configRaw:   makeRaw(ptrStr("Sekret!1"), ptrBool(false)),
			planRaw:     makeRaw(ptrStr("Sekret!1"), ptrBool(false)),
			stateRaw:    nullRaw,
			configValue: types.BoolValue(false),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolValue(false),
			expected:    types.BoolValue(false),
		},
		"destroy_leaves_plan_alone": {
			configRaw:   nullRaw,
			planRaw:     nullRaw,
			stateRaw:    makeRaw(nil, ptrBool(true)),
			configValue: types.BoolNull(),
			stateValue:  types.BoolValue(true),
			planValue:   types.BoolValue(true),
			expected:    types.BoolValue(true),
		},
		"null_plan_null_state_unchanged": {
			// Create without a concrete plan value yet (e.g. framework has
			// not resolved it). The attribute's Default runs first and establishes
			// the plan value; this modifier should not synthesize one.
			configRaw:   makeRaw(nil, nil),
			planRaw:     makeRaw(nil, nil),
			stateRaw:    nullRaw,
			configValue: types.BoolNull(),
			stateValue:  types.BoolNull(),
			planValue:   types.BoolNull(),
			expected:    types.BoolNull(),
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
