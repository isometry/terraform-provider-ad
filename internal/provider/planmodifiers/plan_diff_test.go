package planmodifiers_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/isometry/terraform-provider-ad/internal/provider/planmodifiers"
)

// planDiffSchema constructs a schema covering a mix of attribute types so the
// generic PlanDiffersFromState helper can be exercised across String, Int64,
// Bool, List and Map.
func planDiffSchema() schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name":    schema.StringAttribute{Optional: true, Computed: true},
			"count":   schema.Int64Attribute{Optional: true, Computed: true},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true},
			"tags": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
			},
		},
	}
}

// planDiffObjectType returns the tftypes.Object matching planDiffSchema.
func planDiffObjectType() tftypes.Object {
	return tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"name":    tftypes.String,
			"count":   tftypes.Number,
			"enabled": tftypes.Bool,
			"tags":    tftypes.List{ElementType: tftypes.String},
			"labels":  tftypes.Map{ElementType: tftypes.String},
		},
	}
}

func makeDiffPlan(t *testing.T, attrs map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	return tfsdk.Plan{
		Schema: planDiffSchema(),
		Raw:    tftypes.NewValue(planDiffObjectType(), attrs),
	}
}

func makeDiffState(t *testing.T, attrs map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	return tfsdk.State{
		Schema: planDiffSchema(),
		Raw:    tftypes.NewValue(planDiffObjectType(), attrs),
	}
}

func TestPlanDiffersFromState(t *testing.T) {
	t.Parallel()

	objType := planDiffObjectType()

	strVal := func(s string) tftypes.Value { return tftypes.NewValue(tftypes.String, s) }
	strNull := tftypes.NewValue(tftypes.String, nil)
	strUnknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	intVal := func(i int64) tftypes.Value { return tftypes.NewValue(tftypes.Number, i) }
	intNull := tftypes.NewValue(tftypes.Number, nil)
	boolVal := func(b bool) tftypes.Value { return tftypes.NewValue(tftypes.Bool, b) }
	boolNull := tftypes.NewValue(tftypes.Bool, nil)

	listType := tftypes.List{ElementType: tftypes.String}
	listVal := func(items ...string) tftypes.Value {
		vals := make([]tftypes.Value, len(items))
		for i, s := range items {
			vals[i] = tftypes.NewValue(tftypes.String, s)
		}
		return tftypes.NewValue(listType, vals)
	}
	listNull := tftypes.NewValue(listType, nil)

	mapType := tftypes.Map{ElementType: tftypes.String}
	mapVal := func(entries map[string]string) tftypes.Value {
		vals := make(map[string]tftypes.Value, len(entries))
		for k, v := range entries {
			vals[k] = tftypes.NewValue(tftypes.String, v)
		}
		return tftypes.NewValue(mapType, vals)
	}
	mapNull := tftypes.NewValue(mapType, nil)

	// baselineValues produces a populated attribute map so individual cases
	// can diverge only where they need to.
	baselineValues := func() map[string]tftypes.Value {
		return map[string]tftypes.Value{
			"name":    strVal("foo"),
			"count":   intVal(1),
			"enabled": boolVal(true),
			"tags":    listVal("a", "b"),
			"labels":  mapVal(map[string]string{"env": "prod"}),
		}
	}

	tests := map[string]struct {
		plan     tfsdk.Plan
		state    tfsdk.State
		wantDiff bool
	}{
		"identical_no_diff": {
			plan:     makeDiffPlan(t, baselineValues()),
			state:    makeDiffState(t, baselineValues()),
			wantDiff: false,
		},
		"changed_string_diff": {
			plan: makeDiffPlan(t, map[string]tftypes.Value{
				"name":    strVal("bar"),
				"count":   intVal(1),
				"enabled": boolVal(true),
				"tags":    listVal("a", "b"),
				"labels":  mapVal(map[string]string{"env": "prod"}),
			}),
			state:    makeDiffState(t, baselineValues()),
			wantDiff: true,
		},
		"changed_int64_diff": {
			plan: makeDiffPlan(t, map[string]tftypes.Value{
				"name":    strVal("foo"),
				"count":   intVal(42),
				"enabled": boolVal(true),
				"tags":    listVal("a", "b"),
				"labels":  mapVal(map[string]string{"env": "prod"}),
			}),
			state:    makeDiffState(t, baselineValues()),
			wantDiff: true,
		},
		"changed_bool_diff": {
			plan: makeDiffPlan(t, map[string]tftypes.Value{
				"name":    strVal("foo"),
				"count":   intVal(1),
				"enabled": boolVal(false),
				"tags":    listVal("a", "b"),
				"labels":  mapVal(map[string]string{"env": "prod"}),
			}),
			state:    makeDiffState(t, baselineValues()),
			wantDiff: true,
		},
		"changed_list_diff": {
			plan: makeDiffPlan(t, map[string]tftypes.Value{
				"name":    strVal("foo"),
				"count":   intVal(1),
				"enabled": boolVal(true),
				"tags":    listVal("a", "b", "c"),
				"labels":  mapVal(map[string]string{"env": "prod"}),
			}),
			state:    makeDiffState(t, baselineValues()),
			wantDiff: true,
		},
		"changed_map_diff": {
			plan: makeDiffPlan(t, map[string]tftypes.Value{
				"name":    strVal("foo"),
				"count":   intVal(1),
				"enabled": boolVal(true),
				"tags":    listVal("a", "b"),
				"labels":  mapVal(map[string]string{"env": "dev"}),
			}),
			state:    makeDiffState(t, baselineValues()),
			wantDiff: true,
		},
		"unknown_plan_value_not_a_diff": {
			// Plan has an Unknown where state has a known value. Unknown
			// values get resolved via UseStateForUnknown, so must NOT be
			// interpreted as drift.
			plan: makeDiffPlan(t, map[string]tftypes.Value{
				"name":    strUnknown,
				"count":   intVal(1),
				"enabled": boolVal(true),
				"tags":    listVal("a", "b"),
				"labels":  mapVal(map[string]string{"env": "prod"}),
			}),
			state:    makeDiffState(t, baselineValues()),
			wantDiff: false,
		},
		"null_plan_where_state_has_value_is_diff": {
			// Plan nulls out a previously set value: a real removal.
			plan: makeDiffPlan(t, map[string]tftypes.Value{
				"name":    strNull,
				"count":   intVal(1),
				"enabled": boolVal(true),
				"tags":    listVal("a", "b"),
				"labels":  mapVal(map[string]string{"env": "prod"}),
			}),
			state:    makeDiffState(t, baselineValues()),
			wantDiff: true,
		},
		"both_null_no_diff": {
			plan: makeDiffPlan(t, map[string]tftypes.Value{
				"name":    strNull,
				"count":   intNull,
				"enabled": boolNull,
				"tags":    listNull,
				"labels":  mapNull,
			}),
			state: makeDiffState(t, map[string]tftypes.Value{
				"name":    strNull,
				"count":   intNull,
				"enabled": boolNull,
				"tags":    listNull,
				"labels":  mapNull,
			}),
			wantDiff: false,
		},
		"destroy_null_plan_no_diff": {
			// plan.Raw is null -> destroy phase. Helper returns false.
			plan: tfsdk.Plan{
				Schema: planDiffSchema(),
				Raw:    tftypes.NewValue(objType, nil),
			},
			state:    makeDiffState(t, baselineValues()),
			wantDiff: false,
		},
		"create_null_state_no_diff": {
			// state.Raw is null -> create phase. Helper returns false.
			plan: makeDiffPlan(t, baselineValues()),
			state: tfsdk.State{
				Schema: planDiffSchema(),
				Raw:    tftypes.NewValue(objType, nil),
			},
			wantDiff: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gotDiff, diags := planmodifiers.PlanDiffersFromState(t.Context(), tc.plan, tc.state)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %s", diags)
			}
			if gotDiff != tc.wantDiff {
				t.Errorf("expected diff=%v, got diff=%v", tc.wantDiff, gotDiff)
			}
		})
	}
}

// TestPlanDiffersFromState_UnknownTopLevelPlan verifies the early-return
// when plan.Raw itself is Unknown (e.g. framework has not resolved anything
// yet). The helper should treat that as "no diff".
func TestPlanDiffersFromState_UnknownTopLevelPlan(t *testing.T) {
	t.Parallel()

	plan := tfsdk.Plan{
		Schema: planDiffSchema(),
		Raw:    tftypes.NewValue(planDiffObjectType(), tftypes.UnknownValue),
	}
	state := makeDiffState(t, map[string]tftypes.Value{
		"name":    tftypes.NewValue(tftypes.String, "foo"),
		"count":   tftypes.NewValue(tftypes.Number, int64(1)),
		"enabled": tftypes.NewValue(tftypes.Bool, true),
		"tags":    tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{}),
		"labels":  tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{}),
	})

	gotDiff, diags := planmodifiers.PlanDiffersFromState(t.Context(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags)
	}
	if gotDiff {
		t.Errorf("expected no diff when plan.Raw is Unknown, got diff=true")
	}
}

// TestPlanDiffersFromState_UnknownTopLevelState verifies that an Unknown
// state yields no diff.
func TestPlanDiffersFromState_UnknownTopLevelState(t *testing.T) {
	t.Parallel()

	plan := makeDiffPlan(t, map[string]tftypes.Value{
		"name":    tftypes.NewValue(tftypes.String, "foo"),
		"count":   tftypes.NewValue(tftypes.Number, int64(1)),
		"enabled": tftypes.NewValue(tftypes.Bool, true),
		"tags":    tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{}),
		"labels":  tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{}),
	})
	state := tfsdk.State{
		Schema: planDiffSchema(),
		Raw:    tftypes.NewValue(planDiffObjectType(), tftypes.UnknownValue),
	}

	gotDiff, diags := planmodifiers.PlanDiffersFromState(t.Context(), plan, state)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags)
	}
	if gotDiff {
		t.Errorf("expected no diff when state.Raw is Unknown, got diff=true")
	}
}
