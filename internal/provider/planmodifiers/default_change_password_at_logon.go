package planmodifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure planmodifier.Bool is implemented.
var _ planmodifier.Bool = &defaultChangePasswordAtLogon{}

// defaultChangePasswordAtLogon implements the plan modifier for the
// change_password_at_logon attribute. The password-conditional default is a
// Create-time concept: AD ties the initial value of pwdLastSet to whether a
// password was supplied at object creation, so we emulate that on Create.
//
// Behaviour:
//
//   - If the user explicitly configures a value, respect it.
//   - On Update (the prior state is non-null), preserve the prior state value.
//     The WriteOnly password attribute is generally null on Update for users
//     not managing the password through Terraform, so synthesising a value
//     from config.password would override real AD state and force destructive
//     diffs (e.g. pwdLastSet = 0) on every plan for imported users.
//   - On Create with Unknown config.password (e.g. sourced from an ephemeral
//     resource), defer the default to apply time by marking the plan value
//     Unknown.
//   - On Create with null/empty config.password, default to true (AD will
//     require the user to change their password at next logon for a
//     passwordless account).
//   - On Create with a concrete config.password, default to false.
type defaultChangePasswordAtLogon struct{}

// DefaultChangePasswordAtLogon returns a plan modifier that defaults the
// change_password_at_logon attribute on Create based on whether a password is
// set in the configuration, and preserves the prior state value on Update.
func DefaultChangePasswordAtLogon() planmodifier.Bool {
	return defaultChangePasswordAtLogon{}
}

// Description returns a human-readable description of the plan modifier.
func (m defaultChangePasswordAtLogon) Description(_ context.Context) string {
	return "On Create, defaults change_password_at_logon to true when no password is set, false otherwise. On Update, preserves the prior state value."
}

// MarkdownDescription returns a markdown description of the plan modifier.
func (m defaultChangePasswordAtLogon) MarkdownDescription(_ context.Context) string {
	return "On Create, defaults `change_password_at_logon` to `true` when no `password` is set, `false` otherwise. On Update, preserves the prior state value."
}

// PlanModifyBool implements the plan modification logic.
func (m defaultChangePasswordAtLogon) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// If the user explicitly configured a value, respect it.
	if !req.ConfigValue.IsNull() && !req.ConfigValue.IsUnknown() {
		return
	}

	// Update phase: the prior state is non-null. Preserve the existing state
	// value rather than synthesising a new value from the WriteOnly password
	// attribute (which is typically null on Update for imported users not
	// managing their password through Terraform).
	if !req.State.Raw.IsNull() {
		resp.PlanValue = req.StateValue
		return
	}

	// Create phase: read the WriteOnly password attribute from Config.
	var password types.String
	diags := req.Config.GetAttribute(ctx, path.Root("password"), &password)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Unknown config.password (e.g. sourced from an ephemeral resource) defers
	// the default to apply time so the value is resolved once the password is
	// known.
	if password.IsUnknown() {
		resp.PlanValue = types.BoolUnknown()
		return
	}

	if password.IsNull() || password.ValueString() == "" {
		resp.PlanValue = types.BoolValue(true)
		return
	}

	resp.PlanValue = types.BoolValue(false)
}
