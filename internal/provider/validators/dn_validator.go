package validators

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Ensure the implementation satisfies the expected interface.
var _ validator.String = dnValidator{}

// dnValidator validates that a string is a properly formatted Distinguished Name (DN).
type dnValidator struct{}

// Description describes the validation in plain text.
func (v dnValidator) Description(_ context.Context) string {
	return "value must be a valid Distinguished Name (DN)"
}

// MarkdownDescription describes the validation in Markdown.
func (v dnValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v dnValidator) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	// Skip validation for unknown or null values
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}

	value := request.ConfigValue.ValueString()

	// Validate DN syntax using go-ldap library
	if value == "" {
		response.Diagnostics.AddAttributeError(
			request.Path,
			"Invalid Distinguished Name",
			"The value \"\" is not a valid Distinguished Name format: DN cannot be empty",
		)
		return
	}

	if _, err := ldap.ParseDN(value); err != nil {
		response.Diagnostics.AddAttributeError(
			request.Path,
			"Invalid Distinguished Name",
			fmt.Sprintf("The value %q is not a valid Distinguished Name format: %s", value, err.Error()),
		)
	}
}

// IsValidDN returns a validator which ensures that any configured
// attribute value is a valid Distinguished Name (DN).
//
// Unknown values and null values are skipped from validation.
func IsValidDN() validator.String {
	return dnValidator{}
}
