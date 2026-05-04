package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// PlanDiffersFromState reports whether the plan represents a real change from
// state, ignoring attributes whose planned value is Unknown. Unknown plan
// values are expected to be resolved independently via UseStateForUnknown (or
// equivalent) plan modifiers; they therefore must not be interpreted as drift
// by callers that want to detect "is this resource being updated?".
//
// The comparison is shallow: it walks the top-level attributes of the plan
// and state objects and compares each pair of tftypes.Values. For each
// attribute:
//
//   - If plan is Unknown, the attribute is treated as equal (skip).
//   - If plan and state are both Null, the attribute is equal.
//   - Otherwise, attributes are compared via tftypes.Value.Equal.
//
// Null or Unknown top-level plan/state objects are treated as "no diff" so
// callers (which generally skip create/destroy anyway) get a safe default.
func PlanDiffersFromState(_ context.Context, plan tfsdk.Plan, state tfsdk.State) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	if plan.Raw.IsNull() || !plan.Raw.IsKnown() {
		return false, diags
	}
	if state.Raw.IsNull() || !state.Raw.IsKnown() {
		return false, diags
	}

	planType := plan.Raw.Type()
	if !planType.Is(tftypes.Object{}) {
		// Fall back to whole-value equality for non-object roots.
		return !plan.Raw.Equal(state.Raw), diags
	}

	planAttrs := map[string]tftypes.Value{}
	if err := plan.Raw.As(&planAttrs); err != nil {
		diags.AddError(
			"Unable to decode plan object for diff",
			err.Error(),
		)
		return false, diags
	}

	stateAttrs := map[string]tftypes.Value{}
	if err := state.Raw.As(&stateAttrs); err != nil {
		diags.AddError(
			"Unable to decode state object for diff",
			err.Error(),
		)
		return false, diags
	}

	for name, planVal := range planAttrs {
		// Unknown plan values are resolved independently; treat as equal.
		if !planVal.IsKnown() {
			continue
		}

		stateVal, ok := stateAttrs[name]
		if !ok {
			// Attribute absent from state but known in plan -> drift.
			return true, diags
		}

		if planVal.IsNull() && stateVal.IsNull() {
			continue
		}

		if !planVal.Equal(stateVal) {
			return true, diags
		}
	}

	return false, diags
}
