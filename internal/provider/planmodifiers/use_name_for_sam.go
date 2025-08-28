package planmodifiers

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var samAccountNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// useNameForSAMAccountName implements the plan modifier.
type useNameForSAMAccountName struct {
	forUser bool // true for users (20 char limit), false for groups (64 char limit)
}

// UseNameForSAMAccountName returns a plan modifier that sets sam_account_name
// to the value of name if sam_account_name is not explicitly configured,
// provided the name is valid for use as a SAM account name.
// The forUser parameter determines the character limit: true for users (20 chars), false for groups (64 chars).
func UseNameForSAMAccountName(forUser bool) planmodifier.String {
	return useNameForSAMAccountName{
		forUser: forUser,
	}
}

// Description returns a human-readable description of the plan modifier.
func (m useNameForSAMAccountName) Description(_ context.Context) string {
	objectType := "group"
	if m.forUser {
		objectType = "user"
	}
	return fmt.Sprintf("uses the value of name if sam_account_name is not explicitly configured for %s objects", objectType)
}

// MarkdownDescription returns a markdown description of the plan modifier.
func (m useNameForSAMAccountName) MarkdownDescription(_ context.Context) string {
	objectType := "group"
	if m.forUser {
		objectType = "user"
	}
	return fmt.Sprintf("uses the value of `name` if `sam_account_name` is not explicitly configured for %s objects", objectType)
}

// PlanModifyString implements the plan modification logic.
func (m useNameForSAMAccountName) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If sam_account_name is explicitly set by user or will be computed, use it as-is
	if !req.ConfigValue.IsNull() && !req.ConfigValue.IsUnknown() {
		return
	}

	// If sam_account_name is unknown (will be computed), don't modify it
	if req.ConfigValue.IsUnknown() {
		return
	}

	// Get the name attribute value from the plan
	var name types.String
	diags := req.Plan.GetAttribute(ctx, path.Root("name"), &name)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip if name is unknown (will be computed) or null
	if name.IsUnknown() || name.IsNull() {
		return
	}

	nameStr := name.ValueString()

	// Determine character limit based on object type
	charLimit := 64 // Default for groups
	objectType := "group"
	if m.forUser {
		charLimit = 20
		objectType = "user"
	}

	// Check if name is too long for SAM account name
	if len(nameStr) > charLimit {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"SAM Account Name Required",
			fmt.Sprintf(
				"The %s name '%s' is %d characters long, which exceeds the %d character limit for SAM account names. "+
					"Please explicitly specify a 'sam_account_name' that is %d characters or less.",
				objectType, nameStr, len(nameStr), charLimit, charLimit,
			),
		)
		return
	}

	// Check if name contains invalid characters for SAM account name
	if !samAccountNameRegex.MatchString(nameStr) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"SAM Account Name Required",
			fmt.Sprintf(
				"The %s name '%s' contains characters that are not valid for SAM account names. "+
					"SAM account names can only contain letters, numbers, dots, underscores, and hyphens. "+
					"Please explicitly specify a valid 'sam_account_name'.",
				objectType, nameStr,
			),
		)
		return
	}

	// Name is valid for use as SAM account name - set it as the plan value
	resp.PlanValue = types.StringValue(nameStr)
}
