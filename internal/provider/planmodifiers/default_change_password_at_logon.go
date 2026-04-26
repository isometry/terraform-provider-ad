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
// change_password_at_logon attribute. Its default value depends on whether
// a password is set in the configuration:
//   - When no password is set, AD effectively requires the user to change
//     the password at next logon, so the default is true.
//   - When a password is set, the default is false.
//
// This matches Active Directory's actual behavior and avoids "Provider
// produced inconsistent result after apply" errors for passwordless accounts.
type defaultChangePasswordAtLogon struct{}

// DefaultChangePasswordAtLogon returns a plan modifier that defaults the
// change_password_at_logon attribute based on whether a password is set
// in the configuration.
func DefaultChangePasswordAtLogon() planmodifier.Bool {
	return defaultChangePasswordAtLogon{}
}

// Description returns a human-readable description of the plan modifier.
func (m defaultChangePasswordAtLogon) Description(_ context.Context) string {
	return "Defaults change_password_at_logon to true when no password is set, false otherwise."
}

// MarkdownDescription returns a markdown description of the plan modifier.
func (m defaultChangePasswordAtLogon) MarkdownDescription(_ context.Context) string {
	return "Defaults `change_password_at_logon` to `true` when no `password` is set, `false` otherwise."
}

// PlanModifyBool implements the plan modification logic.
func (m defaultChangePasswordAtLogon) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// If the user explicitly configured a value, respect it.
	if !req.ConfigValue.IsNull() && !req.ConfigValue.IsUnknown() {
		return
	}

	// Read the password attribute from config (WriteOnly attributes are
	// only accessible through Config, never Plan or State).
	var password types.String
	diags := req.Config.GetAttribute(ctx, path.Root("password"), &password)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if password.IsNull() || password.IsUnknown() || password.ValueString() == "" {
		resp.PlanValue = types.BoolValue(true)
		return
	}

	resp.PlanValue = types.BoolValue(false)
}
