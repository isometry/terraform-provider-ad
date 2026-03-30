package planmodifiers

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestNullForEmptyString(t *testing.T) {
	t.Parallel()

	s := schema.Schema{
		Attributes: map[string]schema.Attribute{
			"managed_by": schema.StringAttribute{Optional: true, Computed: true},
		},
	}
	attrTypes := map[string]tftypes.Type{"managed_by": tftypes.String}

	makePlan := func(v tftypes.Value) tfsdk.Plan {
		return tfsdk.Plan{
			Schema: s,
			Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: attrTypes}, map[string]tftypes.Value{"managed_by": v}),
		}
	}
	makeState := func(v tftypes.Value) tfsdk.State {
		return tfsdk.State{
			Schema: s,
			Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: attrTypes}, map[string]tftypes.Value{"managed_by": v}),
		}
	}

	dn := "CN=Someone,OU=Users,DC=example,DC=com"

	tests := map[string]struct {
		config    types.String
		state     types.String
		planValue types.String // plan value entering this modifier (after UseStateForUnknown)
		plan      tfsdk.Plan
		stateSDK  tfsdk.State
		nullPlan  bool // true if plan.Raw should be null (destroy)
		expected  types.String
	}{
		"empty_config_null_state_suppresses_diff": {
			config:    types.StringValue(""),
			state:     types.StringNull(),
			planValue: types.StringValue(""),
			plan:      makePlan(tftypes.NewValue(tftypes.String, "")),
			stateSDK:  makeState(tftypes.NewValue(tftypes.String, nil)),
			expected:  types.StringNull(),
		},
		"empty_config_real_state_allows_clear": {
			config:    types.StringValue(""),
			state:     types.StringValue(dn),
			planValue: types.StringValue(""),
			plan:      makePlan(tftypes.NewValue(tftypes.String, "")),
			stateSDK:  makeState(tftypes.NewValue(tftypes.String, dn)),
			expected:  types.StringValue(""),
		},
		"real_config_null_state_unchanged": {
			config:    types.StringValue(dn),
			state:     types.StringNull(),
			planValue: types.StringValue(dn),
			plan:      makePlan(tftypes.NewValue(tftypes.String, dn)),
			stateSDK:  makeState(tftypes.NewValue(tftypes.String, nil)),
			expected:  types.StringValue(dn),
		},
		"null_config_preserves_state_from_prior_modifier": {
			config:    types.StringNull(),
			state:     types.StringValue(dn),
			planValue: types.StringValue(dn), // UseStateForUnknown already set this
			plan:      makePlan(tftypes.NewValue(tftypes.String, dn)),
			stateSDK:  makeState(tftypes.NewValue(tftypes.String, dn)),
			expected:  types.StringValue(dn),
		},
		"destroy_unchanged": {
			config:    types.StringValue(""),
			state:     types.StringNull(),
			planValue: types.StringValue(""),
			nullPlan:  true,
			stateSDK:  makeState(tftypes.NewValue(tftypes.String, nil)),
			expected:  types.StringValue(""),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			plan := tc.plan
			if tc.nullPlan {
				plan = tfsdk.Plan{
					Schema: s,
					Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: attrTypes}, nil),
				}
			}

			req := planmodifier.StringRequest{
				ConfigValue: tc.config,
				StateValue:  tc.state,
				PlanValue:   tc.planValue,
				Plan:        plan,
				State:       tc.stateSDK,
			}
			resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}

			NullForEmptyString().PlanModifyString(t.Context(), req, resp)

			if !resp.PlanValue.Equal(tc.expected) {
				t.Errorf("expected plan value %s, got %s", tc.expected, resp.PlanValue)
			}
			if resp.Diagnostics.HasError() {
				t.Errorf("unexpected errors: %s", resp.Diagnostics)
			}
		})
	}
}
