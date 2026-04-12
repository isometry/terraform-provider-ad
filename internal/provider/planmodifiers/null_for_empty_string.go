package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure nullForEmptyString implements planmodifier.String.
var _ planmodifier.String = nullForEmptyString{}

// nullForEmptyString is a plan modifier that normalizes an empty string config
// value to null when the state value is already null.
type nullForEmptyString struct{}

// NullForEmptyString returns a plan modifier that normalizes an empty string
// config value to null when the state value is already null. This prevents
// perpetual diffs for clearable Optional+Computed attributes where "" in config
// means "clear this attribute" and null in state means "attribute is absent."
//
// When the state has a real value, "" flows through unchanged so the Update
// method knows to send the clear operation to the backend.
func NullForEmptyString() planmodifier.String {
	return nullForEmptyString{}
}

func (m nullForEmptyString) Description(_ context.Context) string {
	return "normalizes empty string to null when the attribute is already absent"
}

func (m nullForEmptyString) MarkdownDescription(_ context.Context) string {
	return "normalizes empty string to null when the attribute is already absent"
}

func (m nullForEmptyString) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If the resource is being destroyed, do nothing.
	if req.Plan.Raw.IsNull() {
		return
	}

	if !req.ConfigValue.IsNull() && !req.ConfigValue.IsUnknown() &&
		req.ConfigValue.ValueString() == "" &&
		req.StateValue.IsNull() {
		resp.PlanValue = types.StringNull()
	}
}
