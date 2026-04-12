package planmodifiers

import (
	"context"
	"fmt"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	customtypes "github.com/isometry/terraform-provider-ad/internal/provider/types"
)

// Ensure computeDN implements planmodifier.String.
var _ planmodifier.String = computeDN{}

// computeDN is a plan modifier that computes the expected DN from planned
// name and parent attributes, preventing "inconsistent result after apply"
// errors when a resource is moved.
type computeDN struct {
	rdnPrefix  string // "CN" or "OU"
	parentAttr string // "container" or "path"
}

// ComputeDN returns a plan modifier that predicts the DN during planning
// based on the planned name and parent (container/path) attributes.
// rdnPrefix is the RDN attribute type ("CN" for groups/users, "OU" for OUs).
// parentAttr is the name of the attribute holding the parent DN ("container" or "path").
func ComputeDN(rdnPrefix string, parentAttr string) planmodifier.String {
	return computeDN{
		rdnPrefix:  rdnPrefix,
		parentAttr: parentAttr,
	}
}

func (m computeDN) Description(_ context.Context) string {
	return fmt.Sprintf("computes the DN from the planned name and %s attributes", m.parentAttr)
}

func (m computeDN) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("computes the DN from the planned `name` and `%s` attributes", m.parentAttr)
}

func (m computeDN) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If the resource is being destroyed, do nothing
	if req.Plan.Raw.IsNull() {
		return
	}

	// Get the planned name
	var name types.String
	diags := req.Plan.GetAttribute(ctx, path.Root("name"), &name)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the planned parent attribute as custom DN type
	var parent customtypes.DNStringValue
	diags = req.Plan.GetAttribute(ctx, path.Root(m.parentAttr), &parent)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If either value is unknown, we can't compute the DN — mark it unknown
	if name.IsUnknown() || parent.IsUnknown() {
		resp.PlanValue = types.StringUnknown()
		return
	}

	// If either value is null, leave the plan value unchanged
	if name.IsNull() || parent.IsNull() {
		return
	}

	// Compute the expected DN and normalize case
	computedDN := fmt.Sprintf("%s=%s,%s", m.rdnPrefix, ldap.EscapeDN(name.ValueString()), parent.ValueString())
	normalizedDN, err := ldapclient.NormalizeDNCase(computedDN)
	if err != nil {
		// Fall back to raw computed DN if normalization fails
		normalizedDN = computedDN
	}
	resp.PlanValue = types.StringValue(normalizedDN)
}
