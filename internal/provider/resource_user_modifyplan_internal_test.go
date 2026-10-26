package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	customtypes "github.com/isometry/terraform-provider-ad/internal/provider/types"
)

// volatileUserAttributes change on the server independently of Terraform.
var volatileUserAttributes = []string{
	"account_locked_out", "password_not_required", "user_account_control",
	"member_of", "primary_group", "last_logon", "account_expires",
}

// Guard against re-removing UseStateForUnknown. The framework marks every
// Computed attribute with null config Unknown as soon as the proposed plan
// differs from prior state in ANY attribute, before plan modifiers run (e.g.
// enabled's Default true vs. state false, later restored by a modifier).
// Only UseStateForUnknown repairs those hidden unknowns
// (terraform-plugin-framework internal/fwserver/server_planresourcechange.go).
// Unit tests cannot reproduce that pre-modifier marking; see the acceptance
// tests. ModifyPlan marks these Unknown again on real changes.
func TestUserResource_VolatileAttributesUseStateForUnknown(t *testing.T) {
	t.Parallel()

	resp := &resource.SchemaResponse{}
	(&UserResource{}).Schema(context.Background(), resource.SchemaRequest{}, resp)

	for _, name := range volatileUserAttributes {
		var mods []string
		switch a := resp.Schema.Attributes[name].(type) {
		case schema.BoolAttribute:
			for _, m := range a.PlanModifiers {
				mods = append(mods, fmt.Sprintf("%T", m))
			}
		case schema.StringAttribute:
			for _, m := range a.PlanModifiers {
				mods = append(mods, fmt.Sprintf("%T", m))
			}
		case schema.Int64Attribute:
			for _, m := range a.PlanModifiers {
				mods = append(mods, fmt.Sprintf("%T", m))
			}
		case schema.ListAttribute:
			for _, m := range a.PlanModifiers {
				mods = append(mods, fmt.Sprintf("%T", m))
			}
		default:
			t.Fatalf("%s: unexpected attribute type %T", name, a)
		}
		found := false
		for _, m := range mods {
			found = found || strings.Contains(m, "useStateForUnknown")
		}
		if !found {
			t.Errorf("%s must use UseStateForUnknown, got %v", name, mods)
		}
	}
}

// volatileUnknown reports which volatile attributes (and when_changed) in m are unknown.
func volatileUnknown(m *UserResourceModel) map[string]bool {
	return map[string]bool{
		"account_locked_out":    m.AccountLockedOut.IsUnknown(),
		"password_not_required": m.PasswordNotRequired.IsUnknown(),
		"user_account_control":  m.UserAccountControl.IsUnknown(),
		"member_of":             m.MemberOf.IsUnknown(),
		"primary_group":         m.PrimaryGroup.IsUnknown(),
		"last_logon":            m.LastLogon.IsUnknown(),
		"account_expires":       m.AccountExpires.IsUnknown(),
		"when_changed":          m.WhenChanged.IsUnknown(),
	}
}

func populatedUserState() UserResourceModel {
	state := baseUserModel()
	state.AccountLockedOut = types.BoolValue(false)
	state.UserAccountControl = types.Int64Value(512)
	state.PasswordNotRequired = types.BoolValue(false)
	state.MemberOf, _ = types.ListValueFrom(context.Background(), types.StringType, []string{"CN=A,DC=example,DC=com"})
	state.PrimaryGroup = types.StringValue("Domain Users")
	state.LastLogon = types.StringValue("2024-01-01T00:00:00Z")
	state.AccountExpires = types.StringValue("2030-01-01T00:00:00Z")
	state.WhenChanged = types.StringValue("2024-01-01T00:00:00Z")
	return state
}

func TestUserResource_ModifyPlan_RealChangeMarksVolatileUnknown(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*UserResourceModel){
		"description": func(m *UserResourceModel) { m.Description = types.StringValue("new") },
		"enabled":     func(m *UserResourceModel) { m.Enabled = types.BoolValue(false) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := populatedUserState()
			plan := state
			mutate(&plan)
			config := baseUserModel()

			out, resp := runUserModifyPlan(t, &plan, &state, &config)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}
			for attr, unknown := range volatileUnknown(out) {
				if !unknown {
					t.Errorf("%s must be unknown on a real change", attr)
				}
			}
		})
	}
}

func TestUserResource_ModifyPlan_UACDriverOnlyChange(t *testing.T) {
	t.Parallel()

	state := populatedUserState()
	plan := state
	plan.PasswordNeverExpires = types.BoolValue(!state.PasswordNeverExpires.ValueBool())
	config := baseUserModel()

	out, resp := runUserModifyPlan(t, &plan, &state, &config)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if !out.UserAccountControl.IsUnknown() {
		t.Errorf("user_account_control must be unknown when a UAC driver changes")
	}
}

func baseUserModel() UserResourceModel {
	return UserResourceModel{
		Name:            types.StringValue("alice"),
		PrincipalName:   types.StringValue("alice@example.com"),
		SAMAccountName:  types.StringValue("alice"),
		Container:       customtypes.DNString("CN=Users,DC=example,DC=com"),
		DN:              customtypes.DNString("CN=alice,CN=Users,DC=example,DC=com"),
		Enabled:         types.BoolValue(true),
		PasswordVersion: types.Int64Value(0),
		MemberOf:        types.ListNull(types.StringType),
	}
}

func runUserModifyPlan(t *testing.T, plan, state, config *UserResourceModel) (*UserResourceModel, *resource.ModifyPlanResponse) {
	t.Helper()

	ctx := context.Background()
	r := &UserResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	tfType := schemaResp.Schema.Type().TerraformType(ctx)

	mk := func(m *UserResourceModel) tftypes.Value {
		s := tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(tfType, nil)}
		if m != nil {
			if diags := s.Set(ctx, m); diags.HasError() {
				t.Fatalf("failed to build model: %v", diags.Errors())
			}
		}
		return s.Raw
	}

	p := tfsdk.Plan{Schema: schemaResp.Schema, Raw: mk(plan)}
	req := resource.ModifyPlanRequest{
		Plan:   p,
		State:  tfsdk.State{Schema: schemaResp.Schema, Raw: mk(state)},
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: mk(config)},
	}
	resp := &resource.ModifyPlanResponse{Plan: p}
	r.ModifyPlan(ctx, req, resp)

	var out UserResourceModel
	if !resp.Plan.Raw.IsNull() && !resp.Diagnostics.HasError() {
		if diags := resp.Plan.Get(ctx, &out); diags.HasError() {
			t.Fatalf("failed to read resulting plan: %v", diags.Errors())
		}
	}
	return &out, resp
}

func TestUserResource_ModifyPlan_NoChangeKeepsComputedValuesKnown(t *testing.T) {
	t.Parallel()

	state := populatedUserState()
	plan := state
	config := baseUserModel()

	out, resp := runUserModifyPlan(t, &plan, &state, &config)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	for attr, unknown := range volatileUnknown(out) {
		if unknown {
			t.Errorf("%s must stay known on a no-change plan", attr)
		}
	}
}

func TestUserResource_ModifyPlan_ChangePasswordAtLogon(t *testing.T) {
	t.Parallel()

	cfg := func(cpal types.Bool, pw types.String) *UserResourceModel {
		c := baseUserModel()
		c.ChangePasswordAtLogon = cpal
		c.Password = pw
		return &c
	}
	st := func(cpal bool) *UserResourceModel {
		s := baseUserModel()
		s.ChangePasswordAtLogon = types.BoolValue(cpal)
		s.UserAccountControl = types.Int64Value(512)
		s.WhenChanged = types.StringValue("2024-01-01T00:00:00Z")
		return &s
	}
	f, tr := types.BoolValue(false), types.BoolValue(true)

	tests := []struct {
		name    string
		state   *UserResourceModel // nil = create
		config  *UserResourceModel
		wantErr bool
	}{
		{"create false no password", nil, cfg(f, types.StringNull()), true},
		{"create false empty password", nil, cfg(f, types.StringValue("")), true},
		{"create false with password", nil, cfg(f, types.StringValue("pw")), false},
		{"create false unknown password", nil, cfg(f, types.StringUnknown()), false},
		{"create true no password", nil, cfg(tr, types.StringNull()), false},
		{"create omitted", nil, cfg(types.BoolNull(), types.StringNull()), false},
		{"update imported false->false no password", st(false), cfg(f, types.StringNull()), false},
		{"update true->false no password", st(true), cfg(f, types.StringNull()), true},
		{"update true->false with password", st(true), cfg(f, types.StringValue("pw")), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			plan := baseUserModel()
			plan.ChangePasswordAtLogon = tc.config.ChangePasswordAtLogon
			plan.Password = tc.config.Password
			if tc.state != nil {
				plan.UserAccountControl = tc.state.UserAccountControl
				plan.WhenChanged = tc.state.WhenChanged
			} else {
				plan.UserAccountControl = types.Int64Unknown()
				plan.WhenChanged = types.StringUnknown()
			}
			_, resp := runUserModifyPlan(t, &plan, tc.state, tc.config)
			if got := resp.Diagnostics.HasError(); got != tc.wantErr {
				t.Fatalf("HasError = %v, want %v: %v", got, tc.wantErr, resp.Diagnostics)
			}
		})
	}
}
