package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	customtypes "github.com/isometry/terraform-provider-ad/internal/provider/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &GroupMembershipResource{}
var _ resource.ResourceWithImportState = &GroupMembershipResource{}

func NewGroupMembershipResource() resource.Resource {
	return &GroupMembershipResource{}
}

// GroupMembershipResource defines the resource implementation.
type GroupMembershipResource struct {
	client ldapclient.Client
}

// GroupMembershipResourceModel describes the resource data model.
type GroupMembershipResourceModel struct {
	ID      types.String                 `tfsdk:"id"`       // Group objectGUID (same as group_id)
	GroupID types.String                 `tfsdk:"group_id"` // Group objectGUID (required)
	Members customtypes.DNStringSetValue `tfsdk:"members"`  // Set of member identifiers (required)
}

func (r *GroupMembershipResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_membership"
}

func (r *GroupMembershipResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the membership of an Active Directory group. This resource allows you to define the complete set of members for a group, with automatic anti-drift protection through identifier normalization.\n\n" +
			"**Anti-Drift Protection**: This resource automatically normalizes all member identifiers to distinguished names (DNs) to prevent configuration drift. " +
			"For example, specifying a member as `john@example.com` (UPN) in your configuration will not cause drift even if Active Directory stores it as `CN=John Doe,OU=Users,DC=example,DC=com` (DN).\n\n" +
			"**Supported Identifier Formats**:\n" +
			"- Distinguished Name (DN): `CN=John Doe,OU=Users,DC=example,DC=com`\n" +
			"- User Principal Name (UPN): `john@example.com`\n" +
			"- SAM Account Name: `DOMAIN\\john` or `john`\n" +
			"- Object GUID: `550e8400-e29b-41d4-a716-446655440000`\n" +
			"- Security Identifier (SID): `S-1-5-21-123456789-123456789-123456789-1001`",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The resource identifier, which is the objectGUID of the group. This is the same value as `group_id`.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"group_id": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the group whose membership is being managed. This must be the GUID of an existing Active Directory group.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"members": schema.SetAttribute{
				MarkdownDescription: "Set of group member identifiers. Members can be specified using any supported identifier format (DN, UPN, SAM, GUID, or SID). " +
					"The resource automatically normalizes all identifiers to distinguished names to prevent configuration drift. " +
					"**Note**: This resource manages the complete membership set - members not listed here will be removed from the group.",
				Required:    true,
				ElementType: types.StringType,
				CustomType:  customtypes.DNStringSetType{},
			},
		},
	}
}

func (r *GroupMembershipResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(ldapclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected ldapclient.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

// getMembershipManager creates a GroupMembershipManager from the client.
func (r *GroupMembershipResource) getMembershipManager(ctx context.Context) (*ldapclient.GroupMembershipManager, error) {
	// Get base DN from client
	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get base DN from LDAP server: %w", err)
	}

	// Create and return GroupMembershipManager
	return ldapclient.NewGroupMembershipManager(r.client, baseDN), nil
}

func (r *GroupMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GroupMembershipResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating AD group membership", map[string]any{
		"group_id": data.GroupID.ValueString(),
	})

	// Create GroupMembershipManager
	membershipManager, err := r.getMembershipManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Membership Manager",
			err.Error(),
		)
		return
	}

	// Extract member identifiers from the set
	var members []string
	resp.Diagnostics.Append(data.Members.ElementsAs(ctx, &members, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Setting group members", map[string]any{
		"group_id":     data.GroupID.ValueString(),
		"member_count": len(members),
		"members":      members,
	})

	// Validate member identifiers (only if we have members)
	if len(members) > 0 {
		if err := membershipManager.ValidateMembers(members); err != nil {
			resp.Diagnostics.AddError(
				"Invalid Member Identifiers",
				fmt.Sprintf("One or more member identifiers are invalid: %s", err.Error()),
			)
			return
		}
	}

	// Set the complete membership using the anti-drift operation
	err = membershipManager.SetGroupMembers(ctx, data.GroupID.ValueString(), members)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Setting Group Members",
			"Could not set group members, unexpected error: "+err.Error(),
		)
		return
	}

	// Set the ID to be the same as group_id for resource tracking
	data.ID = data.GroupID

	// Refresh the state to get normalized member DNs
	err = r.refreshMembershipState(ctx, membershipManager, &data)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Refreshing Membership State",
			"Group membership was created but could not refresh state: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Created AD group membership", map[string]any{
		"group_id":           data.GroupID.ValueString(),
		"normalized_members": data.Members,
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GroupMembershipResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading AD group membership", map[string]any{
		"group_id": data.GroupID.ValueString(),
	})

	// Create GroupMembershipManager
	membershipManager, err := r.getMembershipManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Membership Manager",
			err.Error(),
		)
		return
	}

	// Check if the group still exists by trying to get its members
	_, err = membershipManager.GetGroupMembers(ctx, data.GroupID.ValueString())
	if err != nil {
		// Check if the group was not found (has been deleted)
		if ldapErr, ok := err.(*ldapclient.LDAPError); ok {
			if strings.Contains(ldapErr.Error(), "not found") {
				tflog.Debug(ctx, "Group not found, removing from state", map[string]any{
					"group_id": data.GroupID.ValueString(),
				})
				resp.State.RemoveResource(ctx)
				return
			}
		}

		resp.Diagnostics.AddError(
			"Error Reading Group Membership",
			fmt.Sprintf("Could not read membership for group ID %s: %s", data.GroupID.ValueString(), err.Error()),
		)
		return
	}

	// Refresh the membership state with current data from AD
	err = r.refreshMembershipState(ctx, membershipManager, &data)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Refreshing Membership State",
			err.Error(),
		)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data GroupMembershipResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating AD group membership", map[string]any{
		"group_id": data.GroupID.ValueString(),
	})

	// Create GroupMembershipManager
	membershipManager, err := r.getMembershipManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Membership Manager",
			err.Error(),
		)
		return
	}

	// Extract new member identifiers from the plan
	var members []string
	resp.Diagnostics.Append(data.Members.ElementsAs(ctx, &members, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating group members", map[string]any{
		"group_id":     data.GroupID.ValueString(),
		"member_count": len(members),
		"members":      members,
	})

	// Validate member identifiers (only if we have members)
	if len(members) > 0 {
		if err := membershipManager.ValidateMembers(members); err != nil {
			resp.Diagnostics.AddError(
				"Invalid Member Identifiers",
				fmt.Sprintf("One or more member identifiers are invalid: %s", err.Error()),
			)
			return
		}
	}

	// Set the complete membership (this handles the delta calculation internally)
	err = membershipManager.SetGroupMembers(ctx, data.GroupID.ValueString(), members)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Group Members",
			"Could not update group members, unexpected error: "+err.Error(),
		)
		return
	}

	// Refresh the state to get normalized member DNs
	err = r.refreshMembershipState(ctx, membershipManager, &data)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Refreshing Membership State",
			"Group membership was updated but could not refresh state: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Updated AD group membership", map[string]any{
		"group_id":           data.GroupID.ValueString(),
		"normalized_members": data.Members,
	})

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GroupMembershipResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting AD group membership", map[string]any{
		"group_id": data.GroupID.ValueString(),
	})

	// Create GroupMembershipManager
	membershipManager, err := r.getMembershipManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Membership Manager",
			err.Error(),
		)
		return
	}

	// Clear all members from the group (empty slice means remove all)
	err = membershipManager.SetGroupMembers(ctx, data.GroupID.ValueString(), []string{})
	if err != nil {
		// If the group no longer exists, that's fine - the membership is effectively deleted
		if ldapErr, ok := err.(*ldapclient.LDAPError); ok {
			if strings.Contains(ldapErr.Error(), "not found") {
				tflog.Debug(ctx, "Group not found during delete, membership already removed", map[string]any{
					"group_id": data.GroupID.ValueString(),
				})
				return
			}
		}

		resp.Diagnostics.AddError(
			"Error Deleting Group Membership",
			"Could not clear group members, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Deleted AD group membership", map[string]any{
		"group_id": data.GroupID.ValueString(),
	})
}

func (r *GroupMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by group GUID
	groupGUID := strings.TrimSpace(req.ID)

	tflog.Debug(ctx, "Importing AD group membership", map[string]any{
		"group_id": groupGUID,
	})

	// Validate that the import ID looks like a GUID
	if !r.isGUID(groupGUID) {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Import ID must be a valid group objectGUID. Got: %s", groupGUID),
		)
		return
	}

	// Create GroupMembershipManager
	membershipManager, err := r.getMembershipManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Membership Manager",
			err.Error(),
		)
		return
	}

	// Verify the group exists and get its current members
	currentMembers, err := membershipManager.GetGroupMembers(ctx, groupGUID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Group Membership",
			fmt.Sprintf("Could not get members for group with GUID %s: %s", groupGUID, err.Error()),
		)
		return
	}

	// Create the resource model
	var data GroupMembershipResourceModel
	data.ID = types.StringValue(groupGUID)
	data.GroupID = types.StringValue(groupGUID)

	// Convert current members to a custom DN set
	if len(currentMembers) > 0 {
		membersSet, diags := customtypes.DNStringSet(ctx, currentMembers)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Members = membersSet
	} else {
		// Empty membership
		emptySet, diags := customtypes.DNStringSet(ctx, []string{})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Members = emptySet
	}

	tflog.Debug(ctx, "Imported AD group membership", map[string]any{
		"group_id":     groupGUID,
		"member_count": len(currentMembers),
	})

	// Set the resource state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)

	// Set the ID for Terraform
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), groupGUID)...)
}

// refreshMembershipState updates the model with current membership from Active Directory.
// This ensures the state contains normalized DNs and reflects the actual AD state.
func (r *GroupMembershipResource) refreshMembershipState(ctx context.Context, membershipManager *ldapclient.GroupMembershipManager, model *GroupMembershipResourceModel) error {
	// Get current members from AD (already normalized as DNs)
	currentMembers, err := membershipManager.GetGroupMembers(ctx, model.GroupID.ValueString())
	if err != nil {
		return fmt.Errorf("could not get current group members: %w", err)
	}

	// Convert to custom DN set
	membersSet, diags := customtypes.DNStringSet(ctx, currentMembers)
	if diags.HasError() {
		return fmt.Errorf("could not create members DN set: %v", diags.Errors())
	}

	model.Members = membersSet

	tflog.Trace(ctx, "Refreshed membership state", map[string]any{
		"group_id":           model.GroupID.ValueString(),
		"member_count":       len(currentMembers),
		"normalized_members": currentMembers,
	})

	return nil
}

// isGUID checks if a string looks like a GUID.
func (r *GroupMembershipResource) isGUID(s string) bool {
	// Use the same GUID validation as the group resource
	// GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	return len(s) == 36 &&
		s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}
