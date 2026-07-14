package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	"github.com/isometry/terraform-provider-ad/internal/utils"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &GroupMembershipResource{}
var _ resource.ResourceWithImportState = &GroupMembershipResource{}
var _ resource.ResourceWithModifyPlan = &GroupMembershipResource{}

// NewGroupMembershipResource creates a new instance of the group membership resource.
func NewGroupMembershipResource() resource.Resource {
	return &GroupMembershipResource{}
}

// GroupMembershipResource defines the resource implementation.
type GroupMembershipResource struct {
	client               ldapclient.Client
	cacheManager         *ldapclient.CacheManager
	ignoreMissingMembers bool
}

// GroupMembershipResourceModel describes the resource data model.
type GroupMembershipResourceModel struct {
	ID                   types.String `tfsdk:"id"`                     // Group objectGUID (same as group_id)
	GroupID              types.String `tfsdk:"group_id"`               // Group objectGUID (required)
	Members              types.Set    `tfsdk:"members"`                // Set of member identifiers (required, user-provided)
	MemberDetails        types.Set    `tfsdk:"member_details"`         // Set of MemberDetailModel: resolved (dn, id) pairs (computed)
	IgnoreMissingMembers types.Bool   `tfsdk:"ignore_missing_members"` // Per-resource override for ignore_missing_members (optional)
}

// MemberDetailModel describes a single resolved member — one element of
// MemberDetails. DN and ID (the member's objectGUID) are correlated together
// (unlike two independent flat Sets, which would lose that correlation): both
// are derived from the same identifier, in the same ModifyPlan resolution
// pass, from whatever format was used in `members`. ID is the empty string
// when unavailable (mirrors ldapclient.ResolvedIdentifier; never an error on
// its own).
type MemberDetailModel struct {
	DN types.String `tfsdk:"dn"`
	ID types.String `tfsdk:"id"`
}

// memberDetailAttrTypes/memberDetailObjectType describe the element type of
// the `member_details` SetNestedAttribute, used whenever code needs to
// construct or type-check a types.Set of MemberDetailModel outside of the
// schema.Schema definition itself (ModifyPlan, Create/Update, Read,
// ImportState).
var memberDetailAttrTypes = map[string]attr.Type{
	"dn": types.StringType,
	"id": types.StringType,
}

var memberDetailObjectType = types.ObjectType{AttrTypes: memberDetailAttrTypes}

func (r *GroupMembershipResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_membership"
}

func (r *GroupMembershipResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the membership of an Active Directory group. This resource allows you to define the complete set of members for a group, with automatic anti-drift protection through identifier normalization.\n\n" +
			"**Anti-Drift Protection**: This resource automatically normalizes all member identifiers to distinguished names (DNs) and object GUIDs internally while preserving your original configuration. " +
			"The `members` attribute retains exactly what you configure, while `member_details` shows the resolved `(dn, id)` pairs used for Active Directory operations. " +
			"Resolution happens once, at plan time; because an object's `objectGUID` never changes for its lifetime (unlike its DN, which changes on rename), that plan-time snapshot is trusted for the rest of the apply.\n\n" +
			"**Supported Identifier Formats**:\n" +
			"- Distinguished Name (DN): `CN=John Doe,OU=Users,DC=example,DC=com`\n" +
			"- Object GUID: `550e8400-e29b-41d4-a716-446655440000`\n" +
			"- User Principal Name (UPN): `john@example.com`\n" +
			"- SAM Account Name: `DOMAIN\\john` or `john`\n" +
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
				MarkdownDescription: "Set of group member identifiers. Members can be specified using any supported identifier format: " +
					"Distinguished Name (DN), Object GUID, User Principal Name (UPN), SAM Account Name, or Security Identifier (SID). " +
					"This attribute preserves your original configuration exactly as specified. " +
					"**Note**: This resource manages the complete membership set - members not listed here will be removed from the group.",
				Required:    true,
				ElementType: types.StringType,
			},
			"member_details": schema.SetNestedAttribute{
				MarkdownDescription: "The resolved identity of every group member: its distinguished name " +
					"(DN) and object GUID, both derived from whatever identifier format was used in `members`. " +
					"This is the authoritative source used for all Active Directory operations — resolved " +
					"once, at plan time, and immune to the member being renamed afterward (the GUID never " +
					"changes even when the DN does).",
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"dn": schema.StringAttribute{Computed: true, MarkdownDescription: "The member's distinguished name."},
						"id": schema.StringAttribute{Computed: true, MarkdownDescription: "The member's objectGUID (canonical hyphenated form)."},
					},
				},
			},
			"ignore_missing_members": schema.BoolAttribute{
				MarkdownDescription: "When `true`, member identifiers that cannot be resolved " +
					"(e.g., deleted AD objects) emit warnings instead of errors during planning, " +
					"and the unresolvable members are excluded from the group. " +
					"When `false` (strict mode), unresolvable members cause a planning error.\n\n" +
					"If not specified, inherits from the provider-level `ignore_missing_members` setting. " +
					"The effective default is `false` when neither resource nor provider specifies a value.",
				Optional: true,
			},
		},
	}
}

func (r *GroupMembershipResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.ignoreMissingMembers = providerData.IgnoreMissingMembers
}

// ModifyPlan implements resource.ResourceWithModifyPlan to resolve members
// during the planning phase, populating member_details for use in CRUD
// operations. Every branch below sets the WHOLE `member_details` Set to
// Unknown/Null/empty (never a Set containing individual unknown elements) —
// Create/Update's apply-time fallback (see extractMemberDetailsForWrite and
// resolveMembersForWriteFallback) relies on this invariant, checking only
// data.MemberDetails.IsUnknown()/IsNull() as a whole.
func (r *GroupMembershipResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Only process if we have a plan (not during destroy)
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan GroupMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Handle unknown group_id (when resource depends on group being created)
	if plan.GroupID.IsUnknown() {
		tflog.Debug(ctx, "Group ID is unknown during planning, cannot resolve members yet")
		// When group_id is unknown, we can't resolve members
		// Set member_details to unknown as well
		plan.MemberDetails = types.SetUnknown(memberDetailObjectType)
		resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
		return
	}

	// Always re-resolve member_details based on the current members in the plan
	// This ensures that when members change, member_details is updated accordingly

	// Handle unknown members (dependencies on resources not yet created during planning)
	if plan.Members.IsUnknown() {
		tflog.Debug(ctx, "Members is unknown during planning, setting member details to unknown", map[string]any{
			"group_id": plan.GroupID.ValueString(),
		})
		plan.MemberDetails = types.SetUnknown(memberDetailObjectType)
		resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
		return
	}

	// Handle null members
	if plan.Members.IsNull() {
		tflog.Debug(ctx, "Members is null during planning, setting member details to null", map[string]any{
			"group_id": plan.GroupID.ValueString(),
		})
		plan.MemberDetails = types.SetNull(memberDetailObjectType)
		resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
		return
	}

	// Extract member identifiers from the plan
	// Note: This may still fail if individual elements are unknown, which we handle below
	var members []string
	diags := plan.Members.ElementsAs(ctx, &members, false)
	if diags.HasError() {
		// Extraction failed, likely due to unknown elements within the set
		// This can happen when individual member identifiers depend on resources being created
		tflog.Debug(ctx, "Failed to extract members during planning (likely unknown elements), setting member details to unknown", map[string]any{
			"group_id": plan.GroupID.ValueString(),
			"errors":   diags.Errors(),
		})
		plan.MemberDetails = types.SetUnknown(memberDetailObjectType)
		resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
		return
	}

	tflog.Debug(ctx, "Resolving member identifiers during planning", map[string]any{
		"group_id":     plan.GroupID.ValueString(),
		"member_count": len(members),
		"members":      members,
	})

	// Handle empty members list
	if len(members) == 0 {
		plan.MemberDetails = types.SetValueMust(memberDetailObjectType, []attr.Value{})
		resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
		return
	}

	// Normalize member identifiers to DNs using MemberNormalizer
	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Getting Base DN During Planning",
			fmt.Sprintf("Could not get base DN from LDAP client for member normalization: %s", err.Error()),
		)
		return
	}

	// Create normalizer
	normalizer := ldapclient.NewMemberNormalizer(r.client, baseDN, r.cacheManager)

	// Resolve effective ignore_missing_members value
	// Priority: resource explicit > provider setting
	effectiveIgnoreMissing := r.effectiveIgnoreMissingMembers(ctx, plan.IgnoreMissingMembers)

	// Normalize all identifiers to DNs, applying ignore-missing semantics.
	resolvedMap, diags := r.resolveMembers(ctx, normalizer, members, effectiveIgnoreMissing)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build the resolved (dn, id) pairs in the same order as input (only
	// for successfully resolved members). Both DN and GUID come from the
	// SAME ResolvedIdentifier, so they are correlated by construction.
	memberDetails := make([]MemberDetailModel, 0, len(resolvedMap))
	for _, member := range members {
		if resolved, ok := resolvedMap[member]; ok {
			memberDetails = append(memberDetails, MemberDetailModel{
				DN: types.StringValue(resolved.DN),
				ID: types.StringValue(resolved.GUID),
			})
		}
		// Skip members that failed normalization (already reported above)
	}

	// Create the member details set and update the plan
	memberDetailsSet, diags := types.SetValueFrom(ctx, memberDetailObjectType, memberDetails)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.MemberDetails = memberDetailsSet

	tflog.Debug(ctx, "Resolved member identifiers during planning", map[string]any{
		"group_id":       plan.GroupID.ValueString(),
		"members":        members,
		"member_details": memberDetails,
	})

	// Save the updated plan
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

// effectiveIgnoreMissingMembers resolves the effective ignore_missing_members
// value from resource-level override > provider-level default precedence.
// Used identically by ModifyPlan (reading plan.IgnoreMissingMembers) and by
// Create/Update's fallback path, resolveMembersForWriteFallback (reading
// data.IgnoreMissingMembers) — same field, same precedence, just sourced
// from different model variables.
func (r *GroupMembershipResource) effectiveIgnoreMissingMembers(ctx context.Context, resourceValue types.Bool) bool {
	if !resourceValue.IsNull() && !resourceValue.IsUnknown() {
		value := resourceValue.ValueBool()
		tflog.Debug(ctx, "Using resource-level ignore_missing_members", map[string]any{
			"value": value,
		})
		return value
	}

	tflog.Debug(ctx, "Using provider-level ignore_missing_members", map[string]any{
		"value": r.ignoreMissingMembers,
	})
	return r.ignoreMissingMembers
}

// resolveMembers resolves verbatim member identifiers to their DN+GUID pairs
// at the current moment (live/cached), applying ignore-missing semantics.
// Used by ModifyPlan (plan time, populating member_details — the common
// case, trusted through apply since objectGUID never changes) and by
// resolveMembersForWriteFallback on behalf of Create/Update (apply time,
// immediately before the AD write — the exception path, used only when
// member_details is unknown/null because ModifyPlan itself could not
// resolve members, e.g. a member being created in the very same apply).
//
// Returns the map of successfully resolved identifiers, keyed by the
// caller's original, verbatim identifier string (mirrors
// MemberNormalizer.ResolveBatch). In strict mode (effectiveIgnoreMissing
// false), any resolution failure is fatal and the returned map must not be
// trusted (the caller should stop on resp.Diagnostics.HasError()). In
// ignore-missing mode, failures are reported as warnings and excluded from
// the returned map; if every member fails to resolve, an error diagnostic is
// added as a safety net to prevent accidentally emptying group membership.
func (r *GroupMembershipResource) resolveMembers(
	ctx context.Context,
	normalizer *ldapclient.MemberNormalizer,
	members []string,
	effectiveIgnoreMissing bool,
) (map[string]ldapclient.ResolvedIdentifier, diag.Diagnostics) {
	var diags diag.Diagnostics

	resolvedMap, failures := normalizer.ResolveBatch(members)

	// Handle any resolution failures
	if len(failures) > 0 {
		for identifier, err := range failures {
			msg := fmt.Sprintf("Member '%s' could not be resolved: %s", identifier, err.Error())

			if effectiveIgnoreMissing {
				tflog.Warn(ctx, "Ignoring unresolvable member", map[string]any{
					"identifier": identifier,
					"error":      err.Error(),
				})
				diags.AddWarning("Member could not be resolved", msg)
			} else {
				diags.AddError("Member could not be resolved", msg)
			}
		}

		// In strict mode, stop if there are any errors
		if !effectiveIgnoreMissing {
			return resolvedMap, diags
		}
	}

	// Safety net: prevent accidental group emptying when all members fail resolution
	if len(resolvedMap) == 0 && len(members) > 0 {
		diags.AddError(
			"All Members Failed to Resolve",
			"All configured members failed normalization. Refusing to proceed with empty membership. "+
				"Set ignore_missing_members = false to see individual errors, or remove invalid members from configuration.",
		)
	}

	return resolvedMap, diags
}

// extractMemberDetailsForWrite unpacks data.MemberDetails — the plan-time-
// resolved (dn, id) pairs computed once by ModifyPlan — into the DN list
// and DN->GUID map consumed by SetGroupMembers/AddGroupMembers to prefer
// AD's rename-immune "<GUID=...>" alternative-DN form when writing newly-
// added members.
//
// This is the common-case path for Create/Update and performs ZERO LDAP
// calls: the (dn, id) pairing was already resolved and correlated at the
// schema level by ModifyPlan, so this is pure in-memory unpacking. It is
// safe to trust member_details indefinitely through the apply because an
// AD object's objectGUID never changes for its lifetime, unlike its DN
// (which changes on rename) — capturing the GUID once, at plan time, is
// therefore safe even if a referenced object is renamed by an unordered
// sibling resource later in the very same apply: the write below uses the
// GUID-alt-DN form for any member whose GUID is known, so AD itself
// resolves it to whatever DN is current at write time, never the
// (possibly stale) DN string captured in member_details.
//
// Callers must only invoke this when data.MemberDetails is known (neither
// Unknown nor Null) — see resolveMembersForWriteFallback for the exception
// path.
func (r *GroupMembershipResource) extractMemberDetailsForWrite(
	ctx context.Context, data *GroupMembershipResourceModel,
) ([]string, map[string]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	var details []MemberDetailModel
	diags.Append(data.MemberDetails.ElementsAs(ctx, &details, false)...)
	if diags.HasError() {
		return nil, nil, diags
	}

	memberDNs := make([]string, 0, len(details))
	memberGUIDs := make(map[string]string, len(details))
	for _, detail := range details {
		dn := detail.DN.ValueString()
		memberDNs = append(memberDNs, dn)
		if guid := detail.ID.ValueString(); guid != "" {
			memberGUIDs[dn] = guid
		}
	}

	return memberDNs, memberGUIDs, diags
}

// resolveMembersForWriteFallback re-resolves a resource's verbatim `members`
// configuration fresh (live/cached), immediately before an AD write in
// Create or Update. This is the EXCEPTION path, used ONLY when
// data.MemberDetails is unknown or null — i.e. ModifyPlan itself could not
// resolve members at plan time (e.g. a member is itself a new object being
// created in the very same apply, referenced by a non-GUID identifier that
// requires an LDAP lookup which can't succeed until the object exists). In
// the common case (member_details fully known), Create/Update use
// extractMemberDetailsForWrite instead, which performs zero LDAP calls.
func (r *GroupMembershipResource) resolveMembersForWriteFallback(
	ctx context.Context, data *GroupMembershipResourceModel,
) ([]string, map[string]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	if data.Members.IsNull() || data.Members.IsUnknown() {
		return nil, nil, diags
	}

	var members []string
	diags.Append(data.Members.ElementsAs(ctx, &members, false)...)
	if diags.HasError() {
		return nil, nil, diags
	}

	if len(members) == 0 {
		return []string{}, nil, diags
	}

	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		diags.AddError(
			"Error Getting Base DN",
			fmt.Sprintf("Could not get base DN from LDAP client for member resolution: %s", err.Error()),
		)
		return nil, nil, diags
	}

	normalizer := ldapclient.NewMemberNormalizer(r.client, baseDN, r.cacheManager)
	effectiveIgnoreMissing := r.effectiveIgnoreMissingMembers(ctx, data.IgnoreMissingMembers)

	resolvedMap, resolveDiags := r.resolveMembers(ctx, normalizer, members, effectiveIgnoreMissing)
	diags.Append(resolveDiags...)
	if diags.HasError() {
		return nil, nil, diags
	}

	// Build the DN list (same order as configured members) and the DN->GUID
	// map used to prefer AD's rename-immune "<GUID=...>" alternative-DN form
	// when writing newly-added members.
	memberDNs := make([]string, 0, len(resolvedMap))
	memberGUIDs := make(map[string]string, len(resolvedMap))
	for _, member := range members {
		resolved, ok := resolvedMap[member]
		if !ok {
			continue // failed resolution, already reported above (ignore-missing mode)
		}
		memberDNs = append(memberDNs, resolved.DN)
		if resolved.GUID != "" {
			memberGUIDs[resolved.DN] = resolved.GUID
		}
	}

	return memberDNs, memberGUIDs, diags
}

// resolveMemberDetailsForWrite is the single entry point Create/Update use
// to obtain the DN list and DN->GUID map for an AD membership write. It
// takes the common-case, zero-LDAP-call path (extractMemberDetailsForWrite,
// unpacking the plan-time snapshot in data.MemberDetails) unless that
// snapshot is unknown or null, in which case it falls back to fresh
// resolution (resolveMembersForWriteFallback) as the explicit exception.
//
// A types.Set populated by ModifyPlan is only ever Unknown/Null as a whole
// (see ModifyPlan's doc comment) — never known-but-containing-individual-
// unknown-elements — so checking IsUnknown()/IsNull() on the whole Set is
// sufficient to detect the exception path; no per-element check is needed.
//
// In the fallback branch, data.MemberDetails is backfilled from the fresh
// resolution before returning: Terraform requires every computed attribute
// to be fully known once Create/Update completes, so an Unknown/Null
// member_details can never be left as-is in the saved state — it must be
// replaced with the same (dn, id) pairs that were just resolved for the
// write, keeping the persisted state internally consistent with what was
// actually applied to AD.
func (r *GroupMembershipResource) resolveMemberDetailsForWrite(
	ctx context.Context, data *GroupMembershipResourceModel,
) ([]string, map[string]string, diag.Diagnostics) {
	if !data.MemberDetails.IsUnknown() && !data.MemberDetails.IsNull() {
		return r.extractMemberDetailsForWrite(ctx, data)
	}

	tflog.Debug(ctx, "member_details unknown/null at apply time (ModifyPlan could not resolve members at plan time); falling back to fresh apply-time resolution", map[string]any{
		"group_id": data.GroupID.ValueString(),
	})

	memberDNs, memberGUIDs, diags := r.resolveMembersForWriteFallback(ctx, data)
	if diags.HasError() {
		return nil, nil, diags
	}

	details := make([]MemberDetailModel, 0, len(memberDNs))
	for _, dn := range memberDNs {
		details = append(details, MemberDetailModel{
			DN: types.StringValue(dn),
			ID: types.StringValue(memberGUIDs[dn]), // "" when absent, matching the empty-when-unavailable contract
		})
	}
	memberDetailsSet, setDiags := types.SetValueFrom(ctx, memberDetailObjectType, details)
	diags.Append(setDiags...)
	if diags.HasError() {
		return nil, nil, diags
	}
	data.MemberDetails = memberDetailsSet

	return memberDNs, memberGUIDs, diags
}

// getMembershipManager creates a GroupMembershipManager from the client.
func (r *GroupMembershipResource) getMembershipManager(ctx context.Context) (*ldapclient.GroupMembershipManager, error) {
	// Get base DN from client
	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get base DN from LDAP server: %w", err)
	}

	// Create and return GroupMembershipManager
	return ldapclient.NewGroupMembershipManager(ctx, r.client, baseDN, r.cacheManager), nil
}

func (r *GroupMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GroupMembershipResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

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

	// Use the plan-time-resolved (dn, id) pairs captured in
	// data.MemberDetails by ModifyPlan — the common case, requiring ZERO
	// LDAP calls here. Falls back to fresh resolution only if
	// member_details couldn't be resolved at plan time (see
	// resolveMemberDetailsForWrite), in which case data.MemberDetails is
	// backfilled from that fresh resolution so it is never left
	// Unknown/Null in resp.State.Set below.
	memberDNs, memberGUIDs, diags := r.resolveMemberDetailsForWrite(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Setting group members using plan-time-resolved details", map[string]any{
		"group_id":     data.GroupID.ValueString(),
		"member_count": len(memberDNs),
		"member_dns":   memberDNs,
	})

	// Set the complete membership using the resolved DNs, preferring AD's
	// rename-immune "<GUID=...>" alternative-DN form for members whose
	// GUID is known.
	err = membershipManager.SetGroupMembers(data.GroupID.ValueString(), memberDNs, memberGUIDs)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Setting Group Members",
			"Could not set group members, unexpected error: "+err.Error(),
		)
		return
	}

	// Set the ID to be the same as group_id for resource tracking
	data.ID = data.GroupID

	tflog.Debug(ctx, "Created AD group membership", map[string]any{
		"group_id":   data.GroupID.ValueString(),
		"member_dns": memberDNs,
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GroupMembershipResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

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
	_, err = membershipManager.GetGroupMembers(data.GroupID.ValueString())
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

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

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

	// Use the plan-time-resolved (dn, id) pairs captured in
	// data.MemberDetails by ModifyPlan — the common case, requiring ZERO
	// LDAP calls here. Falls back to fresh resolution only if
	// member_details couldn't be resolved at plan time (see
	// resolveMemberDetailsForWrite), in which case data.MemberDetails is
	// backfilled from that fresh resolution so it is never left
	// Unknown/Null in resp.State.Set below.
	memberDNs, memberGUIDs, diags := r.resolveMemberDetailsForWrite(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating group members using plan-time-resolved details", map[string]any{
		"group_id":     data.GroupID.ValueString(),
		"member_count": len(memberDNs),
		"member_dns":   memberDNs,
	})

	// Set the complete membership using the resolved DNs, preferring AD's
	// rename-immune "<GUID=...>" alternative-DN form for members whose
	// GUID is known.
	err = membershipManager.SetGroupMembers(data.GroupID.ValueString(), memberDNs, memberGUIDs)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Group Members",
			"Could not update group members, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Updated AD group membership", map[string]any{
		"group_id":   data.GroupID.ValueString(),
		"member_dns": memberDNs,
	})

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GroupMembershipResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

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

	// Clear all members from the group (empty slice means remove all). No
	// member-identity resolution is needed here: removing everyone needs no
	// GUID map, and passing nil for an empty add-list is a no-op regardless.
	err = membershipManager.SetGroupMembers(data.GroupID.ValueString(), []string{}, nil)
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
	// Import by various group identifier formats (DN, GUID, SID, UPN, SAM)
	importID := strings.TrimSpace(req.ID)

	tflog.Debug(ctx, "Importing AD group membership", map[string]any{
		"import_id": importID,
	})

	// Get base DN for identifier normalization
	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Getting Base DN",
			fmt.Sprintf("Could not get base DN for identifier normalization: %s", err.Error()),
		)
		return
	}

	// Normalize the import ID to a DN (supports DN, GUID, SID, UPN, SAM formats)
	normalizer := ldapclient.NewMemberNormalizer(r.client, baseDN, r.cacheManager)
	resolved, err := normalizer.Resolve(importID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Resolving Group Identifier",
			fmt.Sprintf("Could not resolve group identifier '%s' to DN. Supported formats: DN, GUID, SID, UPN, SAM Account Name. Error: %s", importID, err.Error()),
		)
		return
	}
	groupDN := resolved.DN

	tflog.Debug(ctx, "Resolved group identifier to DN", map[string]any{
		"import_id": importID,
		"group_dn":  groupDN,
	})

	// Get the group by DN to extract its GUID
	groupManager := ldapclient.NewGroupManager(ctx, r.client, baseDN, r.cacheManager)
	group, err := groupManager.GetGroupByDN(groupDN)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Group Membership",
			fmt.Sprintf("Could not find group at DN '%s': %s", groupDN, err.Error()),
		)
		return
	}

	groupGUID := group.ObjectGUID

	tflog.Debug(ctx, "Resolved group GUID from DN", map[string]any{
		"import_id":  importID,
		"group_dn":   groupDN,
		"group_guid": groupGUID,
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

	// Verify the group exists and get its current members
	currentMembers, err := membershipManager.GetGroupMembers(groupGUID)
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

	// For import, set Members to the plain DNs from AD (users can then
	// update their configuration to use their preferred identifier format)
	// and member_details to those same DNs paired with their resolved
	// GUIDs.
	if len(currentMembers) > 0 {
		membersSet, diags := types.SetValueFrom(ctx, types.StringType, currentMembers)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Members = membersSet

		memberDetailsSet, diags := r.resolveCurrentMemberDetails(ctx, currentMembers)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.MemberDetails = memberDetailsSet
	} else {
		// Empty membership
		data.Members = types.SetValueMust(types.StringType, []attr.Value{})
		data.MemberDetails = types.SetValueMust(memberDetailObjectType, []attr.Value{})
	}

	tflog.Info(ctx, "Successfully imported AD group membership", map[string]any{
		"import_id":    importID,
		"group_guid":   groupGUID,
		"group_dn":     groupDN,
		"member_count": len(currentMembers),
	})

	// Set the resource state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)

	// Set the ID for Terraform
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), groupGUID)...)
}

// resolveCurrentMemberDetails resolves each of the given (already-canonical)
// member DNs — as read live from AD's own `member` attribute — to its
// (dn, id) pair, for use outside of ModifyPlan (Read/refreshMembershipState
// and ImportState, which start from AD's actual current membership rather
// than from the user's verbatim `members` configuration).
//
// This deliberately performs a full live-or-cached resolution per DN (via
// MemberNormalizer.ResolveBatch, which checks the shared cache before
// falling back to LDAP) rather than a cache-only best-effort lookup: a
// cache-only lookup would only ever hit for a DN some earlier resolution in
// this same provider process already cached, which is not guaranteed for
// every real `terraform plan`/`apply` invocation (each is normally a fresh
// process with an empty cache). Resolving fully here ensures Read produces
// the exact same (dn, id) pairs ModifyPlan would independently compute for
// the same DN, so a steady-state refresh (no actual AD membership change)
// converges to zero plan diff instead of a spurious one from a mismatched
// `id` sub-field.
//
// A resolution failure for an individual member (e.g. it was deleted
// between the group-members read and this call) is non-fatal: it is logged
// and that member's GUID is left as the empty string, consistent with
// ResolvedIdentifier's "GUID empty when unavailable" contract.
func (r *GroupMembershipResource) resolveCurrentMemberDetails(ctx context.Context, memberDNs []string) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(memberDNs) == 0 {
		set, setDiags := types.SetValue(memberDetailObjectType, []attr.Value{})
		diags.Append(setDiags...)
		return set, diags
	}

	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		diags.AddError(
			"Error Getting Base DN",
			fmt.Sprintf("Could not get base DN from LDAP client for member GUID resolution: %s", err.Error()),
		)
		return types.SetNull(memberDetailObjectType), diags
	}

	normalizer := ldapclient.NewMemberNormalizer(r.client, baseDN, r.cacheManager)
	resolvedMap, failures := normalizer.ResolveBatch(memberDNs)
	for dn, resolveErr := range failures {
		tflog.Warn(ctx, "Could not resolve current member's GUID; member_details.id will be empty for this member", map[string]any{
			"dn":    dn,
			"error": resolveErr.Error(),
		})
	}

	details := make([]MemberDetailModel, 0, len(memberDNs))
	for _, dn := range memberDNs {
		guid := ""
		if resolved, ok := resolvedMap[dn]; ok {
			guid = resolved.GUID
		}
		details = append(details, MemberDetailModel{
			DN: types.StringValue(dn),
			ID: types.StringValue(guid),
		})
	}

	set, setDiags := types.SetValueFrom(ctx, memberDetailObjectType, details)
	diags.Append(setDiags...)
	return set, diags
}

// refreshMembershipState updates the model with current membership from Active Directory.
// This updates ONLY the MemberDetails attribute with current AD state,
// preserving the user's original configuration in the Members attribute.
func (r *GroupMembershipResource) refreshMembershipState(ctx context.Context, membershipManager *ldapclient.GroupMembershipManager, model *GroupMembershipResourceModel) error {
	// Get current members from AD (already normalized as DNs)
	currentMembers, err := membershipManager.GetGroupMembers(model.GroupID.ValueString())
	if err != nil {
		return fmt.Errorf("could not get current group members: %w", err)
	}

	// DO NOT touch model.Members - preserve user's original configuration!

	// Only update MemberDetails with current AD state
	memberDetailsSet, diags := r.resolveCurrentMemberDetails(ctx, currentMembers)
	if diags.HasError() {
		return fmt.Errorf("could not create member details set: %v", diags.Errors())
	}
	model.MemberDetails = memberDetailsSet

	tflog.Trace(ctx, "Refreshed membership state", map[string]any{
		"group_id":     model.GroupID.ValueString(),
		"member_count": len(currentMembers),
		"members":      currentMembers,
	})

	return nil
}
