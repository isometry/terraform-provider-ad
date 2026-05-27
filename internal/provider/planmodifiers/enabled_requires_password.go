package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure planmodifier.Bool is implemented.
var _ planmodifier.Bool = enabledRequiresPassword{}

// enabledRequiresPassword aligns the plan value of a boolean "enabled"
// attribute with what AD will actually accept, given that the companion
// password attribute is WriteOnly (only present in req.Config, never plan
// or state).
//
// On Create, AD refuses to enable a passwordless account, so when no
// password is configured the plan is forced to false.
//
// On Update, config.password is null for any user not managing its password
// through Terraform (e.g. imports), so its absence cannot be used as a
// proxy for "no credential". Instead:
//   - When config.enabled is omitted, the schema Default(true) would
//     otherwise produce a redundant diff after every Apply; the prior
//     state value is preserved.
//   - When config.enabled is explicitly true and state.change_password_at_logon
//     is true (AD pwdLastSet=0, i.e. no usable credential), AD will reject
//     the enable with 0000052D / ERROR_PASSWORD_RESTRICTION unless a
//     password is supplied for rotation; the plan is forced to false.
//
// When config.password is Unknown (e.g. sourced from an ephemeral resource),
// the modifier defers and lets AD surface the real outcome at apply time.
type enabledRequiresPassword struct {
	passwordPath path.Path
}

// EnabledRequiresPassword returns a plan modifier that aligns enabled with
// what AD will accept based on the password attribute at passwordPath and
// (on Update) the prior state's change_password_at_logon. Intended to run
// AFTER the attribute's Default so it can correct an already-established
// plan value.
func EnabledRequiresPassword(passwordPath path.Path) planmodifier.Bool {
	return enabledRequiresPassword{passwordPath: passwordPath}
}

// Description returns a human-readable description of the plan modifier.
func (m enabledRequiresPassword) Description(_ context.Context) string {
	return "aligns enabled with what AD will accept given the configured password and prior state"
}

// MarkdownDescription returns a markdown description of the plan modifier.
func (m enabledRequiresPassword) MarkdownDescription(_ context.Context) string {
	return "aligns `enabled` with what AD will accept given the configured `password` and prior state"
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

	// Password is WriteOnly: only available through Config.
	var password types.String
	diags := req.Config.GetAttribute(ctx, m.passwordPath, &password)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if password.IsUnknown() {
		return
	}
	passwordSupplied := !password.IsNull() && password.ValueString() != ""

	if req.State.Raw.IsNull() {
		if !passwordSupplied {
			resp.PlanValue = types.BoolValue(false)
		}
		return
	}

	// Omitted-from-config: defeat the schema Default so it doesn't induce a
	// redundant diff after every Apply.
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		resp.PlanValue = req.StateValue
		return
	}

	// Explicit config.enabled=true with no usable credential in AD
	// (pwdLastSet=0) and no rotation password: AD would reject the enable
	// with 0000052D / ERROR_PASSWORD_RESTRICTION.
	var stateCPAL types.Bool
	if d := req.State.GetAttribute(ctx, path.Root("change_password_at_logon"), &stateCPAL); d.HasError() {
		return
	}
	if !stateCPAL.IsNull() && !stateCPAL.IsUnknown() && stateCPAL.ValueBool() && !passwordSupplied {
		resp.PlanValue = types.BoolValue(false)
	}
}
