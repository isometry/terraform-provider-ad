package types

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ basetypes.StringTypable                    = DNStringType{}
	_ basetypes.StringValuable                   = DNStringValue{}
	_ basetypes.StringValuableWithSemanticEquals = DNStringValue{}
)

// DNStringType is a custom string type for Distinguished Names that implements
// case-insensitive semantic equality. This prevents drift detection when
// Active Directory returns DNs with different case than user configuration.
type DNStringType struct {
	basetypes.StringType
}

// String returns a human readable string of the type name.
func (t DNStringType) String() string {
	return "DNStringType"
}

// ValueType returns the Value type.
func (t DNStringType) ValueType(ctx context.Context) attr.Value {
	return DNStringValue{}
}

// Equal returns true if the given type is equivalent.
func (t DNStringType) Equal(o attr.Type) bool {
	other, ok := o.(DNStringType)
	if !ok {
		return false
	}

	return t.StringType.Equal(other.StringType)
}

// ValueFromString returns a StringValuable type given a StringValue.
func (t DNStringType) ValueFromString(ctx context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	value := DNStringValue{
		StringValue: in,
	}

	return value, nil
}

// ValueFromTerraform returns a Value given a tftypes.Value.
func (t DNStringType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}

	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("expected basetypes.StringValue, got: %T", attrValue)
	}

	stringValuable, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("could not create DNStringValue: %v", diags.Errors())
	}

	return stringValuable, nil
}

// DNStringValue is a DN string value with case-insensitive semantic equality.
type DNStringValue struct {
	basetypes.StringValue
}

// Equal returns true if the given value is equivalent.
func (v DNStringValue) Equal(o attr.Value) bool {
	other, ok := o.(DNStringValue)
	if !ok {
		return false
	}

	return v.StringValue.Equal(other.StringValue)
}

// Type returns the type of the value.
func (v DNStringValue) Type(ctx context.Context) attr.Type {
	return DNStringType{}
}

// StringSemanticEquals implements case-insensitive DN comparison.
// This compares DNs by normalizing both values and checking if they represent
// the same Distinguished Name, regardless of case differences in attribute types.
func (v DNStringValue) StringSemanticEquals(ctx context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	newValue, ok := newValuable.(DNStringValue)
	if !ok {
		diags.AddError(
			"Semantic Equality Check Error",
			"An unexpected value type was received while attempting to perform semantic equality checks. "+
				"This is always an error in the provider. Please report the following to the provider developer:\n\n"+
				fmt.Sprintf("Expected DNStringValue, but got: %T", newValuable),
		)
		return false, diags
	}

	// If either value is null or unknown, they can only be equal if both are the same state
	if v.IsNull() || v.IsUnknown() || newValue.IsNull() || newValue.IsUnknown() {
		return v.Equal(newValue), diags
	}

	oldDN := v.ValueString()
	newDN := newValue.ValueString()

	// If both are empty, they're equal
	if oldDN == "" && newDN == "" {
		return true, diags
	}

	// Normalize both DNs for comparison
	oldNormalized, err1 := ldapclient.NormalizeDNCase(oldDN)
	newNormalized, err2 := ldapclient.NormalizeDNCase(newDN)

	// If either DN fails to normalize, fall back to case-insensitive string comparison
	if err1 != nil || err2 != nil {
		return strings.EqualFold(oldDN, newDN), diags
	}

	// Compare normalized DNs (should be identical if they represent the same DN)
	return oldNormalized == newNormalized, diags
}

// DNString is a helper function to create a DNStringValue.
func DNString(value string) DNStringValue {
	return DNStringValue{
		StringValue: basetypes.NewStringValue(value),
	}
}

// DNStringNull is a helper function to create a null DNStringValue.
func DNStringNull() DNStringValue {
	return DNStringValue{
		StringValue: basetypes.NewStringNull(),
	}
}

// DNStringUnknown is a helper function to create an unknown DNStringValue.
func DNStringUnknown() DNStringValue {
	return DNStringValue{
		StringValue: basetypes.NewStringUnknown(),
	}
}
