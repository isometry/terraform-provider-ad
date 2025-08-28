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
	_ basetypes.SetTypable                    = DNStringSetType{}
	_ basetypes.SetValuable                   = DNStringSetValue{}
	_ basetypes.SetValuableWithSemanticEquals = DNStringSetValue{}
)

// DNStringSetType is a custom set type for sets of Distinguished Names
// that implements case-insensitive semantic equality.
type DNStringSetType struct {
	basetypes.SetType
}

// NewDNStringSetType creates a new DNStringSetType with proper element type initialization.
func NewDNStringSetType() DNStringSetType {
	return DNStringSetType{
		SetType: basetypes.SetType{
			ElemType: basetypes.StringType{},
		},
	}
}

// String returns a human readable string of the type name.
func (t DNStringSetType) String() string {
	return "DNStringSetType"
}

// ValueType returns the Value type.
func (t DNStringSetType) ValueType(ctx context.Context) attr.Value {
	return DNStringSetValue{}
}

// Equal returns true if the given type is equivalent.
func (t DNStringSetType) Equal(o attr.Type) bool {
	other, ok := o.(DNStringSetType)
	if !ok {
		return false
	}

	return t.SetType.Equal(other.SetType)
}

// ValueFromSet returns a SetValuable type given a SetValue.
func (t DNStringSetType) ValueFromSet(ctx context.Context, in basetypes.SetValue) (basetypes.SetValuable, diag.Diagnostics) {
	value := DNStringSetValue{
		SetValue: in,
	}

	return value, nil
}

// ValueFromTerraform returns a Value given a tftypes.Value.
func (t DNStringSetType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.SetType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}

	setValue, ok := attrValue.(basetypes.SetValue)
	if !ok {
		return nil, fmt.Errorf("expected basetypes.SetValue, got: %T", attrValue)
	}

	setValuable, diags := t.ValueFromSet(ctx, setValue)
	if diags.HasError() {
		return nil, fmt.Errorf("could not create DNStringSetValue: %v", diags.Errors())
	}

	return setValuable, nil
}

// DNStringSetValue is a set of DN strings with case-insensitive semantic equality.
type DNStringSetValue struct {
	basetypes.SetValue
}

// Equal returns true if the given value is equivalent.
func (v DNStringSetValue) Equal(o attr.Value) bool {
	other, ok := o.(DNStringSetValue)
	if !ok {
		return false
	}

	return v.SetValue.Equal(other.SetValue)
}

// Type returns the type of the value.
func (v DNStringSetValue) Type(ctx context.Context) attr.Type {
	return DNStringSetType{
		SetType: basetypes.SetType{
			ElemType: basetypes.StringType{},
		},
	}
}

// SetSemanticEquals implements case-insensitive DN set comparison.
// This compares sets of DNs by normalizing all DNs in both sets and checking
// if they contain the same Distinguished Names, regardless of case differences.
func (v DNStringSetValue) SetSemanticEquals(ctx context.Context, newValuable basetypes.SetValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	newValue, ok := newValuable.(DNStringSetValue)
	if !ok {
		diags.AddError(
			"Semantic Equality Check Error",
			"An unexpected value type was received while attempting to perform semantic equality checks. "+
				"This is always an error in the provider. Please report the following to the provider developer:\n\n"+
				fmt.Sprintf("Expected DNStringSetValue, but got: %T", newValuable),
		)
		return false, diags
	}

	// If either value is null or unknown, they can only be equal if both are the same state
	if v.IsNull() || v.IsUnknown() || newValue.IsNull() || newValue.IsUnknown() {
		return v.Equal(newValue), diags
	}

	// Convert both sets to string slices
	var oldStrings, newStrings []string

	diags.Append(v.ElementsAs(ctx, &oldStrings, false)...)
	if diags.HasError() {
		return false, diags
	}

	diags.Append(newValue.ElementsAs(ctx, &newStrings, false)...)
	if diags.HasError() {
		return false, diags
	}

	// If the sets have different sizes, they can't be equal
	if len(oldStrings) != len(newStrings) {
		return false, diags
	}

	// Normalize all DNs and compare sets
	oldNormalized, err := ldapclient.NormalizeDNCaseBatch(oldStrings)
	if err != nil {
		// If normalization fails, fall back to case-insensitive string comparison
		return v.fallbackStringSetComparison(oldStrings, newStrings), diags
	}

	newNormalized, err := ldapclient.NormalizeDNCaseBatch(newStrings)
	if err != nil {
		// If normalization fails, fall back to case-insensitive string comparison
		return v.fallbackStringSetComparison(oldStrings, newStrings), diags
	}

	// Create maps for O(n) comparison instead of O(n²)
	oldMap := make(map[string]bool)
	for _, dn := range oldNormalized {
		oldMap[dn] = true
	}

	newMap := make(map[string]bool)
	for _, dn := range newNormalized {
		newMap[dn] = true
	}

	// Check if both maps contain the same keys
	if len(oldMap) != len(newMap) {
		return false, diags
	}

	for dn := range oldMap {
		if !newMap[dn] {
			return false, diags
		}
	}

	return true, diags
}

// fallbackStringSetComparison performs case-insensitive string set comparison
// when DN normalization fails.
func (v DNStringSetValue) fallbackStringSetComparison(oldStrings, newStrings []string) bool {
	if len(oldStrings) != len(newStrings) {
		return false
	}

	// Create a map of lowercase versions for O(n) comparison
	oldMap := make(map[string]bool)
	for _, s := range oldStrings {
		oldMap[strings.ToLower(s)] = true
	}

	newMap := make(map[string]bool)
	for _, s := range newStrings {
		newMap[strings.ToLower(s)] = true
	}

	if len(oldMap) != len(newMap) {
		return false
	}

	for s := range oldMap {
		if !newMap[s] {
			return false
		}
	}

	return true
}

// DNStringSet is a helper function to create a DNStringSetValue from a slice of strings.
func DNStringSet(ctx context.Context, elements []string) (DNStringSetValue, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Convert strings to attr.Value slice
	attrValues := make([]attr.Value, len(elements))
	for i, element := range elements {
		attrValues[i] = basetypes.NewStringValue(element)
	}

	setValue, setDiags := basetypes.NewSetValue(basetypes.StringType{}, attrValues)
	diags.Append(setDiags...)
	if diags.HasError() {
		return DNStringSetValue{}, diags
	}

	return DNStringSetValue{
		SetValue: setValue,
	}, diags
}

// DNStringSetNull is a helper function to create a null DNStringSetValue.
func DNStringSetNull(ctx context.Context) DNStringSetValue {
	return DNStringSetValue{
		SetValue: basetypes.NewSetNull(basetypes.StringType{}),
	}
}

// DNStringSetUnknown is a helper function to create an unknown DNStringSetValue.
func DNStringSetUnknown(ctx context.Context) DNStringSetValue {
	return DNStringSetValue{
		SetValue: basetypes.NewSetUnknown(basetypes.StringType{}),
	}
}
