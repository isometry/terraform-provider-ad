package validators

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interface.
var _ resource.ConfigValidator = &changePasswordAtLogonValidator{}

// changePasswordAtLogonValidator rejects configurations that set
// change_password_at_logon = false for accounts with no password, because
// Active Directory requires such accounts to change their password at
// first logon.
type changePasswordAtLogonValidator struct{}

// Description returns a human-readable description of the validator.
func (v changePasswordAtLogonValidator) Description(_ context.Context) string {
	return "change_password_at_logon = false requires a password to be set"
}

// MarkdownDescription returns a markdown description of the validator.
func (v changePasswordAtLogonValidator) MarkdownDescription(_ context.Context) string {
	return "`change_password_at_logon = false` requires a `password` to be set"
}

// ValidateResource performs the validation.
func (v changePasswordAtLogonValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var changePasswordAtLogon types.Bool
	diags := req.Config.GetAttribute(ctx, path.Root("change_password_at_logon"), &changePasswordAtLogon)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Only validate when an explicit false value is configured.
	if changePasswordAtLogon.IsNull() || changePasswordAtLogon.IsUnknown() {
		return
	}
	if changePasswordAtLogon.ValueBool() {
		return
	}

	var password types.String
	diags = req.Config.GetAttribute(ctx, path.Root("password"), &password)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip if password is unknown; re-validation will occur when it's resolved.
	if password.IsUnknown() {
		return
	}

	if !password.IsNull() && password.ValueString() != "" {
		return
	}

	resp.Diagnostics.AddAttributeError(
		path.Root("change_password_at_logon"),
		"change_password_at_logon = false requires a password",
		"Setting change_password_at_logon = false is not supported for passwordless accounts. "+
			"AD requires the user to change their password at first logon when no password has been set. "+
			"Either set a password or remove the change_password_at_logon = false setting.",
	)
}

// ChangePasswordAtLogonRequiresPassword returns a resource config validator
// that rejects change_password_at_logon = false when no password is set.
func ChangePasswordAtLogonRequiresPassword() resource.ConfigValidator {
	return changePasswordAtLogonValidator{}
}
