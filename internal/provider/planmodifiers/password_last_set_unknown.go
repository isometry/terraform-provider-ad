package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure planmodifier.String is implemented.
var _ planmodifier.String = passwordLastSetUnknown{}

// passwordLastSetUnknown is a plan modifier for the computed
// password_last_set attribute on the ad_user resource.
//
// On Create: the server fills in the value, so the plan value is marked
// Unknown.
//
// On Destroy: the modifier is a no-op.
//
// On Update: when the sibling password_version attribute is changing (or
// transitioning from null), the password is about to be rewritten, causing
// AD to automatically update pwdLastSet. Because the provider formats
// pwdLastSet to RFC3339 (one-second resolution) from wall-clock time read
// back from the server, small timing differences between the write and the
// subsequent read can push the timestamp across a second boundary. Pinning
// the planned value via UseStateForUnknown in this case produces
// "inconsistent result after apply" errors. This modifier marks the plan
// value Unknown whenever password_version is changing, and otherwise
// preserves the state value (the UseStateForUnknown behaviour).
type passwordLastSetUnknown struct{}

// PasswordLastSetUnknown returns a plan modifier that marks the
// password_last_set attribute as Unknown whenever a password reset is
// planned (detected via a change to the sibling password_version
// attribute), and otherwise preserves the existing state value.
func PasswordLastSetUnknown() planmodifier.String {
	return passwordLastSetUnknown{}
}

// Description returns a human-readable description of the plan modifier.
func (m passwordLastSetUnknown) Description(_ context.Context) string {
	return "marks password_last_set as unknown when password_version is changing (a password reset is planned); otherwise preserves the state value"
}

// MarkdownDescription returns a markdown description of the plan modifier.
func (m passwordLastSetUnknown) MarkdownDescription(_ context.Context) string {
	return "marks `password_last_set` as unknown when `password_version` is changing (a password reset is planned); otherwise preserves the state value"
}

// PlanModifyString implements the plan modification logic.
func (m passwordLastSetUnknown) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Destroy: no-op. The plan is null; leave resp.PlanValue as-is.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Create: the server will supply the value. Mark Unknown.
	if req.State.Raw.IsNull() {
		resp.PlanValue = types.StringUnknown()
		return
	}

	// Update: compare the planned and state values of password_version. If
	// the planned value is Unknown, we cannot be certain it will not
	// change, so mark password_last_set Unknown as well.
	var planVersion types.Int64
	diags := req.Plan.GetAttribute(ctx, path.Root("password_version"), &planVersion)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var stateVersion types.Int64
	diags = req.State.GetAttribute(ctx, path.Root("password_version"), &stateVersion)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if planVersion.IsUnknown() {
		resp.PlanValue = types.StringUnknown()
		return
	}

	// If the planned password_version differs from the state value (this
	// also covers the null -> value transition), a password reset is
	// planned; the server will update pwdLastSet, so do not pin the plan.
	if !planVersion.Equal(stateVersion) {
		resp.PlanValue = types.StringUnknown()
		return
	}

	// Otherwise, preserve the existing state value (UseStateForUnknown).
	resp.PlanValue = req.StateValue
}
