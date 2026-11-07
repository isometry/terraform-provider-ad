package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	"github.com/isometry/terraform-provider-ad/internal/utils"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &GroupMemberResource{}
var _ resource.ResourceWithImportState = &GroupMemberResource{}

// NewGroupMemberResource creates a new instance of the group member resource.
func NewGroupMemberResource() resource.Resource {
	return &GroupMemberResource{}
}

// GroupMemberResource manages a single member of a group without touching any
// other member (unlike GroupMembershipResource, which owns the whole set).
type GroupMemberResource struct {
	client       ldapclient.Client
	cacheManager *ldapclient.CacheManager
}

// GroupMemberResourceModel describes the resource data model.
type GroupMemberResourceModel struct {
	ID            types.String `tfsdk:"id"`             // "<group-guid>/<member-guid>"
	GroupID       types.String `tfsdk:"group_id"`       // Group objectGUID
	Member        types.String `tfsdk:"member"`         // Member identifier, verbatim as configured
	MemberDetails types.Object `tfsdk:"member_details"` // MemberDetailModel of the resolved member
}

func (r *GroupMemberResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_member"
}

func (r *GroupMemberResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a single member of an Active Directory group. This resource is **non-authoritative**: " +
			"it adds one member to a group and removes only that member on destroy, leaving every other member of the group untouched. " +
			"A member that is already in the group when the resource is created is adopted. " +
			"If the member is removed from the group outside of Terraform, the next apply adds it again.\n\n" +
			"**Supported Identifier Formats** for `member`:\n" +
			"- Distinguished Name (DN): `CN=John Doe,OU=Users,DC=example,DC=com`\n" +
			"- Object GUID: `550e8400-e29b-41d4-a716-446655440000`\n" +
			"- User Principal Name (UPN): `john@example.com`\n" +
			"- SAM Account Name: `DOMAIN\\john` or `john`\n" +
			"- Security Identifier (SID): `S-1-5-21-123456789-123456789-123456789-1001`\n\n" +
			"Changing `group_id` or `member` replaces the resource, even when the new `member` value is another identifier of the same object.\n\n" +
			"Import sets `member` to the member's objectGUID. If the configuration names the member another way (UPN, DN, ...), the next apply replaces the resource, removing and re-adding the member; " +
			"to avoid this, set `member` to the objectGUID (e.g. a reference to the object's `id`) after import.\n\n" +
			"~> **Warning:** Do not use `ad_group_member` together with `ad_group_membership` for the same group. " +
			"`ad_group_membership` is authoritative and removes every member it does not list, including members managed by `ad_group_member`.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The resource identifier, `<group-guid>/<member-guid>`.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"group_id": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the group. This must be the GUID of an existing Active Directory group.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"member": schema.StringAttribute{
				MarkdownDescription: "The member to add to the group, in any supported identifier format: " +
					"Distinguished Name (DN), Object GUID, User Principal Name (UPN), SAM Account Name, or Security Identifier (SID). " +
					"A `DOMAIN\\account` SAM name is validated against the NetBIOS name of the domain the provider is configured for. " +
					"The value is kept exactly as configured. An identifier that cannot be resolved is an error.",
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"member_details": schema.SingleNestedAttribute{
				MarkdownDescription: "The resolved identity of the member. `dn` is refreshed from Active Directory, so it follows renames and moves of the member.",
				Computed:            true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"dn": schema.StringAttribute{Computed: true, MarkdownDescription: "The member's distinguished name."},
					"id": schema.StringAttribute{Computed: true, MarkdownDescription: "The member's objectGUID (canonical hyphenated form)."},
				},
			},
		},
	}
}

func (r *GroupMemberResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*ldapclient.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *ldapclient.ProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = providerData.Client
	r.cacheManager = providerData.CacheManager
}

// newManagers creates a MemberNormalizer bound to ctx and a
// GroupMembershipManager, both for the directory's base DN.
func (r *GroupMemberResource) newManagers(ctx context.Context) (*ldapclient.MemberNormalizer, *ldapclient.GroupMembershipManager, error) {
	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get base DN from LDAP server: %w", err)
	}

	normalizer := ldapclient.NewMemberNormalizer(r.client, baseDN, r.cacheManager)
	normalizer.SetContext(ctx)
	return normalizer, ldapclient.NewGroupMembershipManager(ctx, r.client, baseDN, r.cacheManager), nil
}

func newMemberDetailsObject(dn, guid string) types.Object {
	return types.ObjectValueMust(memberDetailAttrTypes, map[string]attr.Value{
		"dn": types.StringValue(dn),
		"id": types.StringValue(guid),
	})
}

func (r *GroupMemberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GroupMemberResourceModel

	ctx = utils.InitializeLogging(ctx)

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := data.GroupID.ValueString()
	member := data.Member.ValueString()

	normalizer, membershipManager, err := r.newManagers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Group Membership Manager", err.Error())
		return
	}

	resolved, err := normalizer.Resolve(member)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("member"),
			"Member could not be resolved",
			fmt.Sprintf("Member '%s' could not be resolved: %s", member, err.Error()),
		)
		return
	}
	if resolved.GUID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("member"),
			"Member objectGUID could not be read",
			fmt.Sprintf("Member '%s' resolved to '%s', but its objectGUID could not be read. "+
				"Check that the provider's account is permitted to read objectGUID on this object.", member, resolved.DN),
		)
		return
	}

	tflog.Debug(ctx, "Adding AD group member", map[string]any{
		"group_id":    groupID,
		"member":      member,
		"member_dn":   resolved.DN,
		"member_guid": resolved.GUID,
	})

	// Writes the rename-immune "<GUID=...>" form; an existing member is a
	// conflict that AddGroupMembers treats as success, so it is adopted.
	err = membershipManager.AddGroupMembers(groupID, []string{resolved.DN}, map[string]string{resolved.DN: resolved.GUID})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Adding Group Member",
			fmt.Sprintf("Could not add member '%s' to group %s: %s", member, groupID, err.Error()),
		)
		return
	}

	data.ID = types.StringValue(groupID + "/" + resolved.GUID)
	data.MemberDetails = newMemberDetailsObject(resolved.DN, resolved.GUID)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupMemberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GroupMemberResourceModel

	ctx = utils.InitializeLogging(ctx)

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var details MemberDetailModel
	resp.Diagnostics.Append(data.MemberDetails.As(ctx, &details, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return
	}
	groupID := data.GroupID.ValueString()
	memberGUID := details.ID.ValueString()

	normalizer, membershipManager, err := r.newManagers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Group Membership Manager", err.Error())
		return
	}

	isMember, err := membershipManager.IsDirectMember(groupID, memberGUID)
	if err != nil {
		if isGroupNotFoundError(err) {
			tflog.Debug(ctx, "Group not found, removing from state", map[string]any{"group_id": groupID})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error Reading Group Member",
			fmt.Sprintf("Could not check membership of %s in group %s: %s", memberGUID, groupID, err.Error()),
		)
		return
	}
	if !isMember {
		tflog.Debug(ctx, "Member no longer in group, removing from state", map[string]any{
			"group_id":    groupID,
			"member_guid": memberGUID,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	resolved, err := normalizer.Resolve(memberGUID)
	if err != nil {
		tflog.Warn(ctx, "Could not refresh member DN; keeping the DN from state", map[string]any{
			"member_guid": memberGUID,
			"error":       err.Error(),
		})
	} else {
		data.MemberDetails = newMemberDetailsObject(resolved.DN, memberGUID)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is never called with a change: every configurable attribute
// requires replacement.
func (r *GroupMemberResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data GroupMemberResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupMemberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GroupMemberResourceModel

	ctx = utils.InitializeLogging(ctx)

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var details MemberDetailModel
	resp.Diagnostics.Append(data.MemberDetails.As(ctx, &details, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return
	}
	groupID := data.GroupID.ValueString()
	memberGUID := details.ID.ValueString()

	_, membershipManager, err := r.newManagers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Group Membership Manager", err.Error())
		return
	}

	err = membershipManager.RemoveGroupMemberByGUID(groupID, memberGUID)
	if err != nil {
		if isGroupNotFoundError(err) {
			tflog.Debug(ctx, "Group not found during delete, member already removed", map[string]any{"group_id": groupID})
			return
		}
		resp.Diagnostics.AddError(
			"Error Removing Group Member",
			fmt.Sprintf("Could not remove member %s from group %s: %s", memberGUID, groupID, err.Error()),
		)
	}
}

// parseGroupMemberImportID splits an import ID of the form
// "<group-guid>/<member-guid>" into its canonical (lowercase, hyphenated)
// GUIDs.
func parseGroupMemberImportID(importID string) (groupGUID, memberGUID string, err error) {
	parts := strings.Split(strings.TrimSpace(importID), "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected an import ID of the form <group-guid>/<member-guid>, got %q", importID)
	}

	guids := ldapclient.NewGUIDHandler()
	for i, part := range parts {
		if !guids.IsValidGUID(part) {
			return "", "", fmt.Errorf("%q in import ID %q is not a valid GUID", part, importID)
		}
		if parts[i], err = guids.NormalizeGUID(part); err != nil {
			return "", "", fmt.Errorf("%q in import ID %q is not a valid GUID: %w", part, importID, err)
		}
	}

	return parts[0], parts[1], nil
}

func (r *GroupMemberResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ctx = utils.InitializeLogging(ctx)

	groupGUID, memberGUID, err := parseGroupMemberImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", err.Error())
		return
	}

	normalizer, membershipManager, err := r.newManagers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Group Membership Manager", err.Error())
		return
	}

	resolved, err := normalizer.Resolve(memberGUID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Group Member",
			fmt.Sprintf("Could not find the member object with GUID %s: %s", memberGUID, err.Error()),
		)
		return
	}

	isMember, err := membershipManager.IsDirectMember(groupGUID, memberGUID)
	if err != nil {
		detail := fmt.Sprintf("Could not check membership of %s in group %s: %s", memberGUID, groupGUID, err.Error())
		if isGroupNotFoundError(err) {
			detail = fmt.Sprintf("Group %s does not exist.", groupGUID)
		}
		resp.Diagnostics.AddError("Error Importing Group Member", detail)
		return
	}
	if !isMember {
		resp.Diagnostics.AddError(
			"Error Importing Group Member",
			fmt.Sprintf("Object %s (%s) is not a direct member of group %s.", memberGUID, resolved.DN, groupGUID),
		)
		return
	}

	data := GroupMemberResourceModel{
		ID:            types.StringValue(groupGUID + "/" + memberGUID),
		GroupID:       types.StringValue(groupGUID),
		Member:        types.StringValue(memberGUID),
		MemberDetails: newMemberDetailsObject(resolved.DN, memberGUID),
	}

	tflog.Info(ctx, "Imported AD group member", map[string]any{
		"group_guid": groupGUID,
		"member_dn":  resolved.DN,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
