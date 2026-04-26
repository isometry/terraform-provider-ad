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

func TestPasswordLastSetUnknown_Descriptions(t *testing.T) {
	t.Parallel()

	m := planmodifiers.PasswordLastSetUnknown()

	desc := m.Description(t.Context())
	if !strings.Contains(desc, "password_version") {
		t.Errorf("expected description to mention password_version, got %q", desc)
	}

	md := m.MarkdownDescription(t.Context())
	if !strings.Contains(md, "password_version") {
		t.Errorf("expected markdown description to mention password_version, got %q", md)
	}
}

func TestPasswordLastSetUnknown_PlanModifyString(t *testing.T) {
	t.Parallel()

	// Schema mirrors the relevant subset of the user resource: a
	// password_version attribute and a computed password_last_set attribute.
	s := schema.Schema{
		Attributes: map[string]schema.Attribute{
			"password_version": schema.Int64Attribute{
				Optional: true,
				Computed: true,
			},
			"password_last_set": schema.StringAttribute{
				Computed: true,
			},
		},
	}
	attrTypes := map[string]tftypes.Type{
		"password_version":  tftypes.Number,
		"password_last_set": tftypes.String,
	}
	objType := tftypes.Object{AttributeTypes: attrTypes}

	int64Value := func(v *int64) tftypes.Value {
		if v == nil {
			return tftypes.NewValue(tftypes.Number, nil)
		}
		return tftypes.NewValue(tftypes.Number, *v)
	}
	stringValue := func(v *string) tftypes.Value {
		if v == nil {
			return tftypes.NewValue(tftypes.String, nil)
		}
		return tftypes.NewValue(tftypes.String, *v)
	}
	unknownNumber := tftypes.NewValue(tftypes.Number, tftypes.UnknownValue)

	makeRaw := func(passwordVersion tftypes.Value, lastSet *string) tftypes.Value {
		return tftypes.NewValue(objType, map[string]tftypes.Value{
			"password_version":  passwordVersion,
			"password_last_set": stringValue(lastSet),
		})
	}

	nullRaw := tftypes.NewValue(objType, nil)

	ptrInt := func(i int64) *int64 { return &i }
	ptrStr := func(s string) *string { return &s }

	tests := map[string]struct {
		configRaw  tftypes.Value
		planRaw    tftypes.Value
		stateRaw   tftypes.Value
		stateValue types.String
		planValue  types.String
		expected   types.String
	}{
		"create_marks_plan_unknown": {
			// Create: state is null, plan is a fresh object. The server will
			// supply password_last_set, so the plan must be Unknown.
			configRaw:  makeRaw(int64Value(ptrInt(0)), nil),
			planRaw:    makeRaw(int64Value(ptrInt(0)), nil),
			stateRaw:   nullRaw,
			stateValue: types.StringNull(),
			planValue:  types.StringUnknown(),
			expected:   types.StringUnknown(),
		},
		"destroy_is_noop": {
			// Destroy: plan is null. PlanValue (the null plan value) must be
			// preserved as-is.
			configRaw:  nullRaw,
			planRaw:    nullRaw,
			stateRaw:   makeRaw(int64Value(ptrInt(1)), ptrStr("2026-04-19T14:24:40Z")),
			stateValue: types.StringValue("2026-04-19T14:24:40Z"),
			planValue:  types.StringNull(),
			expected:   types.StringNull(),
		},
		"update_password_version_unchanged_preserves_state": {
			// Update with password_version unchanged: use state for unknown.
			configRaw:  makeRaw(int64Value(ptrInt(1)), nil),
			planRaw:    makeRaw(int64Value(ptrInt(1)), nil),
			stateRaw:   makeRaw(int64Value(ptrInt(1)), ptrStr("2026-04-19T14:24:40Z")),
			stateValue: types.StringValue("2026-04-19T14:24:40Z"),
			planValue:  types.StringUnknown(),
			expected:   types.StringValue("2026-04-19T14:24:40Z"),
		},
		"update_password_version_null_to_value_marks_unknown": {
			// Update where password_version transitions from null to a value.
			// AD will rewrite the password and bump pwdLastSet, so the plan
			// should not pin any expected value.
			configRaw:  makeRaw(int64Value(ptrInt(1)), nil),
			planRaw:    makeRaw(int64Value(ptrInt(1)), nil),
			stateRaw:   makeRaw(int64Value(nil), ptrStr("2026-04-19T14:24:40Z")),
			stateValue: types.StringValue("2026-04-19T14:24:40Z"),
			planValue:  types.StringUnknown(),
			expected:   types.StringUnknown(),
		},
		"update_password_version_changed_marks_unknown": {
			// Update where password_version increments: plan must be Unknown
			// to tolerate the one-second clock skew on pwdLastSet.
			configRaw:  makeRaw(int64Value(ptrInt(2)), nil),
			planRaw:    makeRaw(int64Value(ptrInt(2)), nil),
			stateRaw:   makeRaw(int64Value(ptrInt(1)), ptrStr("2026-04-19T14:24:40Z")),
			stateValue: types.StringValue("2026-04-19T14:24:40Z"),
			planValue:  types.StringUnknown(),
			expected:   types.StringUnknown(),
		},
		"update_plan_password_version_unknown_marks_unknown": {
			// Update where plan password_version is Unknown: we cannot prove
			// the version will not change, so mark the plan Unknown.
			configRaw:  makeRaw(unknownNumber, nil),
			planRaw:    makeRaw(unknownNumber, nil),
			stateRaw:   makeRaw(int64Value(ptrInt(1)), ptrStr("2026-04-19T14:24:40Z")),
			stateValue: types.StringValue("2026-04-19T14:24:40Z"),
			planValue:  types.StringUnknown(),
			expected:   types.StringUnknown(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := planmodifier.StringRequest{
				Path:       path.Root("password_last_set"),
				StateValue: tc.stateValue,
				PlanValue:  tc.planValue,
				Plan:       tfsdk.Plan{Schema: s, Raw: tc.planRaw},
				State:      tfsdk.State{Schema: s, Raw: tc.stateRaw},
				Config:     tfsdk.Config{Schema: s, Raw: tc.configRaw},
			}
			resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}

			planmodifiers.PasswordLastSetUnknown().PlanModifyString(t.Context(), req, resp)

			if !resp.PlanValue.Equal(tc.expected) {
				t.Errorf("expected plan value %s, got %s", tc.expected, resp.PlanValue)
			}
			if resp.Diagnostics.HasError() {
				t.Errorf("unexpected diagnostics: %s", resp.Diagnostics)
			}
		})
	}
}
