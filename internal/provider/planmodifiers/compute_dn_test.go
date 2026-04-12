package planmodifiers

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	customtypes "github.com/isometry/terraform-provider-ad/internal/provider/types"
)

func testSchema(parentAttr string) schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
			},
			parentAttr: schema.StringAttribute{
				Required:   true,
				CustomType: customtypes.DNStringType{},
			},
			"dn": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func makePlan(t *testing.T, parentAttr string, name, parent, dn tftypes.Value) tfsdk.Plan {
	t.Helper()
	return tfsdk.Plan{
		Schema: testSchema(parentAttr),
		Raw: tftypes.NewValue(tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"name":     tftypes.String,
				parentAttr: tftypes.String,
				"dn":       tftypes.String,
			},
		}, map[string]tftypes.Value{
			"name":     name,
			parentAttr: parent,
			"dn":       dn,
		}),
	}
}

func makeState(t *testing.T, parentAttr string, name, parent, dn tftypes.Value) tfsdk.State {
	t.Helper()
	return tfsdk.State{
		Schema: testSchema(parentAttr),
		Raw: tftypes.NewValue(tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"name":     tftypes.String,
				parentAttr: tftypes.String,
				"dn":       tftypes.String,
			},
		}, map[string]tftypes.Value{
			"name":     name,
			parentAttr: parent,
			"dn":       dn,
		}),
	}
}

func TestComputeDN_BothKnown_Group(t *testing.T) {
	modifier := ComputeDN("CN", "container")

	plan := makePlan(t, "container",
		tftypes.NewValue(tftypes.String, "TestGroup"),
		tftypes.NewValue(tftypes.String, "OU=Groups,DC=example,DC=com"),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	)

	state := makeState(t, "container",
		tftypes.NewValue(tftypes.String, "TestGroup"),
		tftypes.NewValue(tftypes.String, "OU=OldGroups,DC=example,DC=com"),
		tftypes.NewValue(tftypes.String, "CN=TestGroup,OU=OldGroups,DC=example,DC=com"),
	)

	req := planmodifier.StringRequest{
		Plan:       plan,
		State:      state,
		PlanValue:  types.StringUnknown(),
		StateValue: types.StringValue("CN=TestGroup,OU=OldGroups,DC=example,DC=com"),
	}

	var resp planmodifier.StringResponse
	modifier.PlanModifyString(t.Context(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}

	expected := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	if resp.PlanValue.ValueString() != expected {
		t.Errorf("expected DN %q, got %q", expected, resp.PlanValue.ValueString())
	}
}

func TestComputeDN_BothKnown_OU(t *testing.T) {
	modifier := ComputeDN("OU", "path")

	plan := makePlan(t, "path",
		tftypes.NewValue(tftypes.String, "TestOU"),
		tftypes.NewValue(tftypes.String, "DC=example,DC=com"),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	)

	state := makeState(t, "path",
		tftypes.NewValue(tftypes.String, "TestOU"),
		tftypes.NewValue(tftypes.String, "OU=Parent,DC=example,DC=com"),
		tftypes.NewValue(tftypes.String, "OU=TestOU,OU=Parent,DC=example,DC=com"),
	)

	req := planmodifier.StringRequest{
		Plan:       plan,
		State:      state,
		PlanValue:  types.StringUnknown(),
		StateValue: types.StringValue("OU=TestOU,OU=Parent,DC=example,DC=com"),
	}

	var resp planmodifier.StringResponse
	modifier.PlanModifyString(t.Context(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}

	expected := "OU=TestOU,DC=example,DC=com"
	if resp.PlanValue.ValueString() != expected {
		t.Errorf("expected DN %q, got %q", expected, resp.PlanValue.ValueString())
	}
}

func TestComputeDN_NameUnknown(t *testing.T) {
	modifier := ComputeDN("CN", "container")

	plan := makePlan(t, "container",
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		tftypes.NewValue(tftypes.String, "OU=Groups,DC=example,DC=com"),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	)

	req := planmodifier.StringRequest{
		Plan:      plan,
		State:     tfsdk.State{},
		PlanValue: types.StringUnknown(),
	}

	var resp planmodifier.StringResponse
	modifier.PlanModifyString(t.Context(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}

	if !resp.PlanValue.IsUnknown() {
		t.Errorf("expected unknown DN, got %q", resp.PlanValue.ValueString())
	}
}

func TestComputeDN_ParentUnknown(t *testing.T) {
	modifier := ComputeDN("CN", "container")

	plan := makePlan(t, "container",
		tftypes.NewValue(tftypes.String, "TestGroup"),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	)

	req := planmodifier.StringRequest{
		Plan:      plan,
		State:     tfsdk.State{},
		PlanValue: types.StringUnknown(),
	}

	var resp planmodifier.StringResponse
	modifier.PlanModifyString(t.Context(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}

	if !resp.PlanValue.IsUnknown() {
		t.Errorf("expected unknown DN, got %q", resp.PlanValue.ValueString())
	}
}

func TestComputeDN_Create(t *testing.T) {
	modifier := ComputeDN("CN", "container")

	plan := makePlan(t, "container",
		tftypes.NewValue(tftypes.String, "NewGroup"),
		tftypes.NewValue(tftypes.String, "OU=Groups,DC=example,DC=com"),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	)

	req := planmodifier.StringRequest{
		Plan:      plan,
		State:     tfsdk.State{},
		PlanValue: types.StringUnknown(),
	}

	var resp planmodifier.StringResponse
	modifier.PlanModifyString(t.Context(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}

	expected := "CN=NewGroup,OU=Groups,DC=example,DC=com"
	if resp.PlanValue.ValueString() != expected {
		t.Errorf("expected DN %q, got %q", expected, resp.PlanValue.ValueString())
	}
}

func TestComputeDN_Destroy(t *testing.T) {
	modifier := ComputeDN("CN", "container")

	s := testSchema("container")
	plan := tfsdk.Plan{
		Schema: s,
		Raw: tftypes.NewValue(tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"name":      tftypes.String,
				"container": tftypes.String,
				"dn":        tftypes.String,
			},
		}, nil),
	}

	req := planmodifier.StringRequest{
		Plan:      plan,
		PlanValue: types.StringUnknown(),
	}

	resp := planmodifier.StringResponse{
		PlanValue: types.StringUnknown(),
	}
	modifier.PlanModifyString(t.Context(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}

	// Plan value should remain unchanged for destroy
	if !resp.PlanValue.IsUnknown() {
		t.Errorf("expected plan value to remain unknown during destroy, got %q", resp.PlanValue.ValueString())
	}
}

func TestComputeDN_NoChange(t *testing.T) {
	modifier := ComputeDN("CN", "container")

	plan := makePlan(t, "container",
		tftypes.NewValue(tftypes.String, "TestGroup"),
		tftypes.NewValue(tftypes.String, "OU=Groups,DC=example,DC=com"),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	)

	state := makeState(t, "container",
		tftypes.NewValue(tftypes.String, "TestGroup"),
		tftypes.NewValue(tftypes.String, "OU=Groups,DC=example,DC=com"),
		tftypes.NewValue(tftypes.String, "CN=TestGroup,OU=Groups,DC=example,DC=com"),
	)

	req := planmodifier.StringRequest{
		Plan:       plan,
		State:      state,
		PlanValue:  types.StringUnknown(),
		StateValue: types.StringValue("CN=TestGroup,OU=Groups,DC=example,DC=com"),
	}

	var resp planmodifier.StringResponse
	modifier.PlanModifyString(t.Context(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}

	// Even when nothing changes, the modifier should still compute the DN
	expected := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	if resp.PlanValue.ValueString() != expected {
		t.Errorf("expected DN %q, got %q", expected, resp.PlanValue.ValueString())
	}
}

func TestComputeDN_SpecialCharacters(t *testing.T) {
	modifier := ComputeDN("CN", "container")

	plan := makePlan(t, "container",
		tftypes.NewValue(tftypes.String, "Doe, John + Admin"),
		tftypes.NewValue(tftypes.String, "OU=Groups,DC=example,DC=com"),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	)

	req := planmodifier.StringRequest{
		Plan:      plan,
		State:     tfsdk.State{},
		PlanValue: types.StringUnknown(),
	}

	var resp planmodifier.StringResponse
	modifier.PlanModifyString(t.Context(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}

	// After EscapeDN + NormalizeDNCase (which round-trips through ParseDN),
	// the DN value escaping is preserved during reconstruction
	expected := `CN=Doe\, John \+ Admin,OU=Groups,DC=example,DC=com`
	if resp.PlanValue.ValueString() != expected {
		t.Errorf("expected DN %q, got %q", expected, resp.PlanValue.ValueString())
	}
}

func TestComputeDN_NormalizesCase(t *testing.T) {
	modifier := ComputeDN("CN", "container")

	// Parent uses lowercase attribute types — normalization should uppercase them
	plan := makePlan(t, "container",
		tftypes.NewValue(tftypes.String, "TestGroup"),
		tftypes.NewValue(tftypes.String, "ou=Groups,dc=example,dc=com"),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	)

	req := planmodifier.StringRequest{
		Plan:      plan,
		State:     tfsdk.State{},
		PlanValue: types.StringUnknown(),
	}

	var resp planmodifier.StringResponse
	modifier.PlanModifyString(t.Context(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}

	expected := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	if resp.PlanValue.ValueString() != expected {
		t.Errorf("expected normalized DN %q, got %q", expected, resp.PlanValue.ValueString())
	}
}

func TestComputeDN_Description(t *testing.T) {
	modifier, ok := ComputeDN("CN", "container").(computeDN)
	if !ok {
		t.Fatal("expected computeDN type")
	}

	desc := modifier.Description(t.Context())
	if desc == "" {
		t.Error("expected non-empty description")
	}

	mdDesc := modifier.MarkdownDescription(t.Context())
	if mdDesc == "" {
		t.Error("expected non-empty markdown description")
	}
}
