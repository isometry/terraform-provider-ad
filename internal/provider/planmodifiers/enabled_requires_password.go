package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure planmodifier.Bool is implemented.
var _ planmodifier.Bool = enabledRequiresPassword{}

// enabledRequiresPassword forces the plan value of a boolean "enabled"
// attribute to false when the companion password attribute at passwordPath
// is unset (null or empty string) in the configuration.
//
// Active Directory refuses to enable a user account that has no password,
// so the plan should reflect what the server will actually produce. Running
// at the attribute level ensures the corrected value is visible to the
// resource-level ModifyPlan, which uses "enabled" (among other drivers) to
// decide whether user_account_control should be marked Unknown.
type enabledRequiresPassword struct {
	passwordPath path.Path
}

// EnabledRequiresPassword returns a plan modifier that forces enabled=false
// in the plan when the password attribute at passwordPath is not set in the
// configuration. Intended to run AFTER the attribute's Default so it can
// correct an already-established plan value.
func EnabledRequiresPassword(passwordPath path.Path) planmodifier.Bool {
	return enabledRequiresPassword{passwordPath: passwordPath}
}

// Description returns a human-readable description of the plan modifier.
func (m enabledRequiresPassword) Description(_ context.Context) string {
	return "forces enabled=false in the plan when no password is configured, reflecting that AD cannot enable a passwordless account"
}

// MarkdownDescription returns a markdown description of the plan modifier.
func (m enabledRequiresPassword) MarkdownDescription(_ context.Context) string {
	return "forces `enabled` to `false` in the plan when no `password` is configured, reflecting that AD cannot enable a passwordless account"
}

// PlanModifyBool implements the plan modification logic.
func (m enabledRequiresPassword) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// Destroy path: leave plan alone.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Nothing to correct if the plan value is not a concrete true.
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() || !req.PlanValue.ValueBool() {
		return
	}

	// Read the password attribute from config. Password is WriteOnly, so it
	// is only available through Config, never Plan or State.
	var password types.String
	diags := req.Config.GetAttribute(ctx, m.passwordPath, &password)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Password is set: AD will accept enabled=true; leave plan alone.
	if !password.IsNull() && !password.IsUnknown() && password.ValueString() != "" {
		return
	}

	// No password configured and plan would enable the account: force false.
	resp.PlanValue = types.BoolValue(false)
}
