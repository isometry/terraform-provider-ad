package validators

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Ensure the implementation satisfies the expected interface.
var _ validator.String = caseInsensitiveOneOfValidator{}

// caseInsensitiveOneOfValidator validates that a string matches one of the allowed values,
// ignoring case differences. The validator normalizes the input to the canonical form.
type caseInsensitiveOneOfValidator struct {
	validValues []string
}

// Description describes the validation in plain text.
func (v caseInsensitiveOneOfValidator) Description(_ context.Context) string {
	return fmt.Sprintf("value must be one of: %s (case-insensitive)", strings.Join(v.validValues, ", "))
}

// MarkdownDescription describes the validation in Markdown.
func (v caseInsensitiveOneOfValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v caseInsensitiveOneOfValidator) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	// Skip validation for unknown or null values
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}

	value := request.ConfigValue.ValueString()
	normalizedInput := strings.ToLower(strings.TrimSpace(value))

	// Check if the normalized value matches any of the valid values
	for _, validValue := range v.validValues {
		if normalizedInput == strings.ToLower(validValue) {
			return // Valid match found
		}
	}

	// No match found, add error
	response.Diagnostics.AddAttributeError(
		request.Path,
		"Invalid Value",
		fmt.Sprintf(
			"The value %q is not valid. Must be one of: %s (case-insensitive)",
			value,
			strings.Join(v.validValues, ", "),
		),
	)
}

// CaseInsensitiveOneOf returns a validator which ensures that any configured
// attribute value matches one of the provided values, ignoring case differences.
//
// This validator is useful for attributes where multiple case variations are acceptable
// but should be normalized to a canonical form (e.g., "Global", "global", "GLOBAL").
//
// Unknown values and null values are skipped from validation.
func CaseInsensitiveOneOf(values ...string) validator.String {
	return caseInsensitiveOneOfValidator{
		validValues: values,
	}
}
