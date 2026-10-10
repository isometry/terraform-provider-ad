package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
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
// are derived from the same identifier, in the same resolution pass, from
// whatever format was used in `members`. Planning and writes require every
// member's objectGUID (see resolveMembers); only a refresh of a member whose
// GUID could not be read (loadMembershipView) stores ID as the empty string,
// and such an element is replaced by the next plan. In a PLANNED value either
// field may be Unknown (see buildPlannedMemberDetails: case G has an unknown
// DN, case P both); in state both are always known.
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
			"Members are identified by `objectGUID`, which never changes for an object's lifetime (unlike its DN, which changes on rename), so membership writes are immune to members being renamed. " +
			"Members that are new to this resource, or that cannot be resolved yet (e.g. objects created in the same apply), are resolved again immediately before the write.\n\n" +
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
					"Members already in state are planned with full details. In the plan, a member new to this " +
					"resource shows `dn` as `(known after apply)` (its `id` is known), and a member that cannot " +
					"be resolved yet (e.g. an object created in the same apply) shows both `dn` and `id` as " +
					"`(known after apply)`. Writes use the GUID, so they are immune to the member being renamed " +
					"(the GUID never changes even when the DN does).",
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
// operations.
//
// Terraform calls PlanResourceChange again during apply for every changing
// resource, after that resource's dependencies have been applied, and
// requires that re-plan to be compatible with the original plan: every
// element of the re-planned set must correlate with a planned element (an
// unknown attribute matches anything), and the set may shrink but never
// grow. Resolution against live AD can legitimately differ between the two
// plans (a member created, or renamed, by another resource in the same
// apply), so member_details is planned PER ELEMENT, and an element is only
// planned as known when both plans are guaranteed to produce it identically.
// The only inputs guaranteed identical across both plans are the prior state
// and an object's objectGUID (immutable for the object's lifetime). See
// buildPlannedMemberDetails for the per-element cases K/G/P.
//
// This intentionally REVERSES the earlier invariant that member_details was
// only ever Unknown/Null as a whole: the planned Set may now contain
// individual unknown elements or attributes, and Create/Update (see
// resolveMemberDetailsForWrite) check whether it is FULLY known, not merely
// whether the Set as a whole is Unknown/Null.
//
// No-op exemption: when members, ignore_missing_members and group_id all
// equal prior state, and the known (case K) elements alone equal
// state.member_details with no case G element, member_details is planned as exactly
// state.member_details. Remaining placeholders in that situation can only be
// members that are permanently missing under ignore_missing_members; planning
// them would produce a diff on every plan. This is safe because Terraform
// never re-plans a no-op resource during apply.
//
// Residual risk (accepted): an identifier known at plan time that resolves to
// a DIFFERENT object during the apply-time re-plan (e.g. an object destroyed
// and recreated under the same DN/SAM/UPN in the same apply while referenced
// by that literal value) changes the GUID between the two plans and Terraform
// reports an inconsistent final plan. Eliminating this would require a wholly
// Unknown member_details on every change, losing all per-element detail.
// References Terraform itself marks unknown (e.g. `.id` of a replaced
// resource) are unaffected.
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
	current := r.readCurrentMembersBestEffort(ctx, baseDN, plan.GroupID.ValueString(), len(members))
	resolvedMap, failures, diags := r.resolveMembers(ctx, normalizer, members, current, effectiveIgnoreMissing)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Prior state anchors case K elements. It is null on Create (and on the
	// create half of a replacement).
	var state *GroupMembershipResourceModel
	var priorDetails []MemberDetailModel
	if !req.State.Raw.IsNull() {
		state = &GroupMembershipResourceModel{}
		resp.Diagnostics.Append(req.State.Get(ctx, state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if !state.MemberDetails.IsNull() && !state.MemberDetails.IsUnknown() {
			resp.Diagnostics.Append(state.MemberDetails.ElementsAs(ctx, &priorDetails, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}

	planned := buildPlannedMemberDetails(members, resolvedMap, failures, priorDetails)

	if state != nil &&
		plan.GroupID.Equal(state.GroupID) &&
		plan.Members.Equal(state.Members) &&
		plan.IgnoreMissingMembers.Equal(state.IgnoreMissingMembers) {
		noOp, diags := planned.isNoOpAgainst(ctx, state.MemberDetails)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		if noOp {
			tflog.Debug(ctx, "Membership unchanged vs prior state; planning member_details as prior state", map[string]any{
				"group_id":           plan.GroupID.ValueString(),
				"known_count":        len(planned.known),
				"unresolved_members": planned.unresolved,
			})
			plan.MemberDetails = state.MemberDetails
			resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
			return
		}
	}

	memberDetailsSet, diags := planned.toSet()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.MemberDetails = memberDetailsSet

	tflog.Debug(ctx, "Planned member_details per element", map[string]any{
		"group_id":           plan.GroupID.ValueString(),
		"members":            members,
		"known_count":        len(planned.known),
		"guid_only_count":    len(planned.guidOnly),
		"unresolved_count":   planned.unresolved,
		"member_details_len": len(memberDetailsSet.Elements()),
	})

	// Save the updated plan
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

// plannedMemberDetails is the per-element plan for `member_details`, as
// classified by buildPlannedMemberDetails.
type plannedMemberDetails struct {
	// known holds case K elements: prior-state elements (verbatim) matched
	// by a configured member, deduplicated.
	known []MemberDetailModel
	// guidOnly holds case G GUIDs: members resolved to a GUID that is not in
	// prior state, deduplicated (case-insensitively).
	guidOnly []string
	// unresolved counts case P placeholders for members that failed to
	// resolve (ignore-missing mode only; strict mode errors before this).
	unresolved int
}

// buildPlannedMemberDetails classifies every configured member into one
// planned `member_details` element:
//
//   - K (known, anchored): resolves to a GUID matching a prior-state element
//     -> that prior-state element verbatim, fully known. The state
//     DN is used rather than the freshly resolved DN so that the plan and the
//     apply-time re-plan (which receive the same prior state) produce the
//     same value even if the member is renamed in between.
//   - G (new, GUID known): resolves to a GUID not in prior state ->
//     {dn: unknown, id: GUID}. Such a member has no stable DN yet, but its
//     GUID can never change. This includes a member whose prior element has
//     an EMPTY id (transient GUID lookup failure in Read) but which now
//     resolves to a GUID: a one-time healing update. Anchoring it to the
//     state DN instead would break if the member were renamed before the
//     apply-time re-plan.
//   - P (placeholder): fails to resolve (ignore-missing mode) ->
//     {dn: unknown, id: unknown}, one per member, so the planned element
//     count is never smaller than the final count.
//
// Every resolved member has a GUID (resolveMembers errors otherwise).
// Identifiers that appear in neither resolved nor failures (empty or
// whitespace-only, skipped by ResolveBatch) produce no element.
func buildPlannedMemberDetails(
	members []string,
	resolved map[string]ldapclient.ResolvedIdentifier,
	failures map[string]error,
	priorDetails []MemberDetailModel,
) plannedMemberDetails {
	priorByGUID := make(map[string]int, len(priorDetails))
	for i, detail := range priorDetails {
		if guid := detail.ID.ValueString(); guid != "" {
			priorByGUID[strings.ToLower(guid)] = i
		}
	}

	var out plannedMemberDetails
	seen := make(map[string]bool)
	for _, member := range members {
		res, ok := resolved[member]
		if !ok {
			if _, failed := failures[member]; failed {
				out.unresolved++
			}
			continue
		}

		key := strings.ToLower(res.GUID)
		if seen[key] {
			continue
		}
		seen[key] = true
		if i, inPrior := priorByGUID[key]; inPrior {
			out.known = append(out.known, priorDetails[i])
		} else {
			out.guidOnly = append(out.guidOnly, res.GUID)
		}
	}

	return out
}

// isNoOpAgainst reports whether this plan qualifies for the no-op exemption
// against the given prior-state member_details (see ModifyPlan): no case G
// element, and the case K elements alone equal the prior state exactly.
// Unresolved case P placeholders are permitted: they can only be members that
// are permanently missing under ignore_missing_members.
func (p plannedMemberDetails) isNoOpAgainst(ctx context.Context, prior types.Set) (bool, diag.Diagnostics) {
	if prior.IsNull() || prior.IsUnknown() || len(p.guidOnly) > 0 {
		return false, nil
	}
	known, diags := plannedMemberDetails{known: p.known}.toSet()
	if diags.HasError() {
		return false, diags
	}
	tflog.Trace(ctx, "Comparing case K member_details elements to prior state", map[string]any{
		"known_count": len(p.known),
		"prior_count": len(prior.Elements()),
	})
	return known.Equal(prior), diags
}

// toSet renders the per-element plan as the planned `member_details` Set:
// K elements fully known, G elements with an unknown dn, and one fully
// unknown placeholder per P member.
func (p plannedMemberDetails) toSet() (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	elems := make([]attr.Value, 0, len(p.known)+len(p.guidOnly)+p.unresolved)
	appendElem := func(dn, id types.String) {
		obj, objDiags := types.ObjectValue(memberDetailAttrTypes, map[string]attr.Value{"dn": dn, "id": id})
		diags.Append(objDiags...)
		elems = append(elems, obj)
	}

	for _, detail := range p.known {
		appendElem(detail.DN, detail.ID)
	}
	for _, guid := range p.guidOnly {
		appendElem(types.StringUnknown(), types.StringValue(guid))
	}
	for range p.unresolved {
		appendElem(types.StringUnknown(), types.StringUnknown())
	}
	if diags.HasError() {
		return types.SetUnknown(memberDetailObjectType), diags
	}

	set, setDiags := types.SetValue(memberDetailObjectType, elems)
	diags.Append(setDiags...)
	return set, diags
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
// Used by ModifyPlan (plan time, classifying each member into a planned
// member_details element) and by resolveMembersForWriteFallback on behalf of
// Create/Update (apply time, immediately before the AD write, whenever the
// planned member_details is not fully known).
//
// current, when non-empty (see readCurrentMembersBestEffort), lets DN/GUID/SID
// identifiers naming a current member of the group resolve without LDAP
// lookups; it affects only how identity is resolved, never the result.
//
// A member that resolves without an objectGUID is always an error, even in
// ignore-missing mode.
//
// Returns the map of successfully resolved identifiers and the map of
// failures, both keyed by the caller's original, verbatim identifier string
// (mirrors MemberNormalizer.ResolveBatch). In strict mode
// (effectiveIgnoreMissing false), any resolution failure is fatal and the
// returned maps must not be trusted (the caller should stop on
// diags.HasError()). In ignore-missing mode, failures are reported as
// warnings and excluded from the resolved map; if every member fails to
// resolve, an error diagnostic is added as a safety net to prevent
// accidentally emptying group membership.
func (r *GroupMembershipResource) resolveMembers(
	ctx context.Context,
	normalizer *ldapclient.MemberNormalizer,
	members []string,
	current []ldapclient.CurrentMember,
	effectiveIgnoreMissing bool,
) (map[string]ldapclient.ResolvedIdentifier, map[string]error, diag.Diagnostics) {
	var diags diag.Diagnostics

	resolvedMap, failures := normalizer.ResolveBatchAgainst(members, current)

	// Members are identified by objectGUID throughout; an existing object whose
	// GUID cannot be read is not supported. This is an error even when
	// ignore_missing_members is set, which covers objects that do not exist,
	// not objects this account cannot fully read.
	for identifier, resolved := range resolvedMap {
		if resolved.GUID == "" {
			diags.AddError("Member objectGUID could not be read", fmt.Sprintf(
				"Member '%s' resolved to '%s', but its objectGUID could not be read. "+
					"Check that the provider's account is permitted to read objectGUID on this object.",
				identifier, resolved.DN))
		}
	}

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
			return resolvedMap, failures, diags
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

	return resolvedMap, failures, diags
}

// extractMemberDetailsForWrite unpacks a FULLY KNOWN data.MemberDetails —
// every element case K (anchored to prior state) as planned by ModifyPlan,
// e.g. when members were only removed or drift is being corrected — into
// the DN list and DN->GUID map consumed by SetGroupMembers/AddGroupMembers
// to prefer AD's rename-immune "<GUID=...>" alternative-DN form when
// writing newly-added members.
//
// This path performs ZERO LDAP calls to resolve member identity: the (dn, id)
// pairing is already correlated at the schema level, so this is pure
// in-memory unpacking. The DNs are state-anchored (case K) and may be stale
// if a member was renamed since the last refresh; the write trusts them and
// relies on the objectGUID, which never changes for an object's lifetime:
// SetGroupMembers diffs by GUID when memberGUIDs supplies one, and the
// GUID-alt-DN form is used for additions, so a stale DN string does not cause
// a spurious add/remove. A stale DN in state is corrected by the next
// refresh (Read).
//
// Callers must only invoke this when data.MemberDetails is fully known —
// see resolveMemberDetailsForWrite.
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
		memberGUIDs[dn] = detail.ID.ValueString()
	}

	return memberDNs, memberGUIDs, diags
}

// resolveMembersForWriteFallback re-resolves a resource's verbatim `members`
// configuration fresh (live/cached), immediately before an AD write in
// Create or Update. Used whenever data.MemberDetails is NOT fully known:
// wholly Unknown (members or group_id unknown when planned) or containing
// case G/P elements (members new to this resource, or not yet resolvable
// when planned, e.g. objects created in the very same apply). When
// member_details is fully known, Create/Update use
// extractMemberDetailsForWrite instead, which performs zero LDAP calls.
//
// The returned DNs are the members' CURRENT DNs, so the write's DN-based
// delta against AD's current membership is accurate even for a member
// renamed earlier in the same apply.
//
// The returned CurrentMember slice is the group snapshot used for resolution
// (see readCurrentMembersBestEffort), for SetGroupMembers to reuse; nil means none.
func (r *GroupMembershipResource) resolveMembersForWriteFallback(
	ctx context.Context, data *GroupMembershipResourceModel,
) ([]string, map[string]string, []ldapclient.CurrentMember, diag.Diagnostics) {
	var diags diag.Diagnostics

	if data.Members.IsNull() || data.Members.IsUnknown() {
		return nil, nil, nil, diags
	}

	var members []string
	diags.Append(data.Members.ElementsAs(ctx, &members, false)...)
	if diags.HasError() {
		return nil, nil, nil, diags
	}

	if len(members) == 0 {
		return []string{}, nil, nil, diags
	}

	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		diags.AddError(
			"Error Getting Base DN",
			fmt.Sprintf("Could not get base DN from LDAP client for member resolution: %s", err.Error()),
		)
		return nil, nil, nil, diags
	}

	normalizer := ldapclient.NewMemberNormalizer(r.client, baseDN, r.cacheManager)
	effectiveIgnoreMissing := r.effectiveIgnoreMissingMembers(ctx, data.IgnoreMissingMembers)

	current := r.readCurrentMembersBestEffort(ctx, baseDN, data.GroupID.ValueString(), len(members))
	resolvedMap, _, resolveDiags := r.resolveMembers(ctx, normalizer, members, current, effectiveIgnoreMissing)
	diags.Append(resolveDiags...)
	if diags.HasError() {
		return nil, nil, nil, diags
	}

	// Build the DN list (same order as configured members, deduplicated:
	// several identifiers may name the same object) and the DN->GUID map
	// used to prefer AD's rename-immune "<GUID=...>" alternative-DN form
	// when writing newly-added members.
	memberDNs := make([]string, 0, len(resolvedMap))
	memberGUIDs := make(map[string]string, len(resolvedMap))
	seenDNs := make(map[string]bool, len(resolvedMap))
	for _, member := range members {
		resolved, ok := resolvedMap[member]
		if !ok {
			continue // failed resolution, already reported above (ignore-missing mode)
		}
		if key := strings.ToLower(resolved.DN); !seenDNs[key] {
			seenDNs[key] = true
			memberDNs = append(memberDNs, resolved.DN)
		}
		memberGUIDs[resolved.DN] = resolved.GUID
	}

	return memberDNs, memberGUIDs, current, diags
}

// memberDetailsFullyKnown reports whether a planned member_details Set is
// known all the way down (not Null, not Unknown, and no element or
// attribute Unknown). ModifyPlan plans member_details per element, so a
// known Set may still contain case G/P elements with unknown attributes;
// checking IsUnknown()/IsNull() on the Set alone is not sufficient.
func memberDetailsFullyKnown(ctx context.Context, set types.Set) (bool, error) {
	if set.IsNull() || set.IsUnknown() {
		return false, nil
	}
	tfValue, err := set.ToTerraformValue(ctx)
	if err != nil {
		return false, fmt.Errorf("converting member_details to a Terraform value: %w", err)
	}
	return tfValue.IsFullyKnown(), nil
}

// reconcileMemberDetailsWithPlan builds the post-apply member_details
// elements from a fresh resolution (memberDNs/memberGUIDs, as returned by
// resolveMembersForWriteFallback) and the planned member_details. A fresh
// member matching a KNOWN planned element (case K) by GUID keeps that planned
// element verbatim (its DN is anchored to prior state); every other member
// uses its fresh (dn, id).
// Terraform requires every known planned element to appear unchanged in the
// apply result, and every result element to correlate with a planned element:
// case G elements correlate by GUID and case P placeholders with anything.
func reconcileMemberDetailsWithPlan(
	ctx context.Context, planned types.Set, memberDNs []string, memberGUIDs map[string]string,
) ([]MemberDetailModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	knownByGUID := make(map[string]MemberDetailModel)
	if !planned.IsNull() && !planned.IsUnknown() {
		for _, elem := range planned.Elements() {
			obj, ok := elem.(types.Object)
			if !ok || obj.IsUnknown() || obj.IsNull() {
				continue
			}
			var detail MemberDetailModel
			diags.Append(obj.As(ctx, &detail, basetypes.ObjectAsOptions{})...)
			if diags.HasError() {
				return nil, diags
			}
			if detail.DN.IsUnknown() || detail.ID.IsUnknown() {
				continue // case G / P: filled from the fresh resolution
			}
			knownByGUID[strings.ToLower(detail.ID.ValueString())] = detail
		}
	}

	details := make([]MemberDetailModel, 0, len(memberDNs))
	seen := make(map[string]bool, len(memberDNs))
	for _, dn := range memberDNs {
		guid := memberGUIDs[dn]
		detail := MemberDetailModel{DN: types.StringValue(dn), ID: types.StringValue(guid)}
		if anchored, ok := knownByGUID[strings.ToLower(guid)]; ok {
			detail = anchored
		}

		key := strings.ToLower(detail.ID.ValueString())
		if seen[key] {
			continue
		}
		seen[key] = true
		details = append(details, detail)
	}

	return details, diags
}

// resolveMemberDetailsForWrite is the single entry point Create/Update use
// to obtain the DN list and DN->GUID map for an AD membership write.
//
// When the planned data.MemberDetails is FULLY known (every element case K,
// e.g. members only removed or drift being corrected) it takes the
// zero-LDAP-call path, extractMemberDetailsForWrite. Otherwise — the Set is
// wholly Unknown/Null, or contains case G/P elements with unknown attributes
// (see ModifyPlan) — it resolves `members` fresh
// (resolveMembersForWriteFallback, cache-backed) and writes the members'
// current DNs/GUIDs. It also returns that path's group snapshot (nil on the
// fully-known path) for SetGroupMembers to reuse.
//
// In the fresh-resolution branch, data.MemberDetails is backfilled before
// returning: Terraform requires every computed attribute to be fully known
// once Create/Update completes, and the result must be compatible with the
// plan. reconcileMemberDetailsWithPlan keeps every known planned element
// verbatim (its prior-state-anchored DN, even if the member was renamed
// earlier in this apply; the next refresh corrects it) and fills case G/P
// elements from the fresh resolution. Members still unresolvable at apply
// time (ignore-missing mode) are excluded with a warning; a placeholder
// planned for them simply coalesces, which Terraform permits.
func (r *GroupMembershipResource) resolveMemberDetailsForWrite(
	ctx context.Context, data *GroupMembershipResourceModel,
) ([]string, map[string]string, []ldapclient.CurrentMember, diag.Diagnostics) {
	var diags diag.Diagnostics

	fullyKnown, err := memberDetailsFullyKnown(ctx, data.MemberDetails)
	if err != nil {
		diags.AddError(
			"Error Inspecting Planned Member Details",
			fmt.Sprintf("Could not inspect the planned member_details: %s", err.Error()),
		)
		return nil, nil, nil, diags
	}
	if fullyKnown {
		memberDNs, memberGUIDs, diags := r.extractMemberDetailsForWrite(ctx, data)
		return memberDNs, memberGUIDs, nil, diags
	}

	tflog.Debug(ctx, "member_details not fully known at apply time; resolving members fresh before the write", map[string]any{
		"group_id":                data.GroupID.ValueString(),
		"member_details_unknown":  data.MemberDetails.IsUnknown(),
		"member_details_null":     data.MemberDetails.IsNull(),
		"member_details_elements": len(data.MemberDetails.Elements()),
	})

	memberDNs, memberGUIDs, current, fallbackDiags := r.resolveMembersForWriteFallback(ctx, data)
	diags.Append(fallbackDiags...)
	if diags.HasError() {
		return nil, nil, nil, diags
	}

	details, reconcileDiags := reconcileMemberDetailsWithPlan(ctx, data.MemberDetails, memberDNs, memberGUIDs)
	diags.Append(reconcileDiags...)
	if diags.HasError() {
		return nil, nil, nil, diags
	}

	memberDetailsSet, setDiags := types.SetValueFrom(ctx, memberDetailObjectType, details)
	diags.Append(setDiags...)
	if diags.HasError() {
		return nil, nil, nil, diags
	}
	data.MemberDetails = memberDetailsSet

	return memberDNs, memberGUIDs, current, diags
}

// readCurrentMembersBestEffort reads the group's current members (DN, GUID,
// SID) in one extended-DN search so that DN/GUID/SID member identifiers can be
// resolved against them without per-identifier LDAP lookups (see
// MemberNormalizer.ResolveBatchAgainst).
//
// The result is the group's complete member list as read just now: non-nil
// means complete (an empty group is an empty non-nil slice), and nil means no
// usable view. GetCurrentMembers returns nil for a range-limited group, and
// every failure (no group yet, unavailableCriticalExtension, search failure,
// malformed value) is logged and yields nil, so a partial or failed read can
// never be taken for the real membership. Create/Update pass the snapshot on
// to SetGroupMembers, which then decides removals from it exactly as its own
// read would; nil makes SetGroupMembers read the group itself, and makes
// ResolveBatchAgainst behave exactly like ResolveBatch. It never produces a
// diagnostic. No LDAP call is made when there are no members or the group ID
// is not known.
func (r *GroupMembershipResource) readCurrentMembersBestEffort(
	ctx context.Context, baseDN, groupID string, memberCount int,
) []ldapclient.CurrentMember {
	if memberCount == 0 || groupID == "" {
		return nil
	}

	manager := ldapclient.NewGroupMembershipManager(ctx, r.client, baseDN, r.cacheManager)
	current, err := manager.GetCurrentMembers(groupID)
	if err != nil {
		tflog.Debug(ctx, "Could not read current group members for live member matching; resolving members normally", map[string]any{
			"group_id": groupID,
			"error":    err.Error(),
		})
		return nil
	}

	return current
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

	// Obtain the (dn, id) pairs to write: unpacked without resolving member
	// identity via LDAP when the planned member_details is fully known, otherwise resolved fresh
	// (see resolveMemberDetailsForWrite), in which case data.MemberDetails
	// is backfilled, plan-compatibly, so no unknown is left in
	// resp.State.Set below.
	memberDNs, memberGUIDs, current, diags := r.resolveMemberDetailsForWrite(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Setting group members", map[string]any{
		"group_id":     data.GroupID.ValueString(),
		"member_count": len(memberDNs),
		"member_dns":   memberDNs,
	})

	// Set the complete membership using the resolved DNs, preferring AD's
	// rename-immune "<GUID=...>" alternative-DN form for members whose
	// GUID is known.
	err = membershipManager.SetGroupMembers(data.GroupID.ValueString(), memberDNs, memberGUIDs, current)
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

	// Refresh member_details from AD (one snapshot; see refreshMembershipState).
	// `members` is deliberately left as configured.
	err = r.refreshMembershipState(ctx, membershipManager, &data)
	if err != nil {
		// The group was deleted out-of-band.
		if isGroupNotFoundError(err) {
			tflog.Debug(ctx, "Group not found, removing from state", map[string]any{
				"group_id": data.GroupID.ValueString(),
			})
			resp.State.RemoveResource(ctx)
			return
		}

		resp.Diagnostics.AddError(
			"Error Reading Group Membership",
			fmt.Sprintf("Could not read membership for group ID %s: %s", data.GroupID.ValueString(), err.Error()),
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

	// Obtain the (dn, id) pairs to write: unpacked without resolving member
	// identity via LDAP when the planned member_details is fully known, otherwise resolved fresh
	// (see resolveMemberDetailsForWrite), in which case data.MemberDetails
	// is backfilled, plan-compatibly, so no unknown is left in
	// resp.State.Set below.
	memberDNs, memberGUIDs, current, diags := r.resolveMemberDetailsForWrite(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating group members", map[string]any{
		"group_id":     data.GroupID.ValueString(),
		"member_count": len(memberDNs),
		"member_dns":   memberDNs,
	})

	// Set the complete membership using the resolved DNs, preferring AD's
	// rename-immune "<GUID=...>" alternative-DN form for members whose
	// GUID is known.
	err = membershipManager.SetGroupMembers(data.GroupID.ValueString(), memberDNs, memberGUIDs, current)
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
	err = membershipManager.SetGroupMembers(data.GroupID.ValueString(), []string{}, nil, nil)
	if err != nil {
		// If the group no longer exists, that's fine - the membership is effectively deleted
		if isGroupNotFoundError(err) {
			tflog.Debug(ctx, "Group not found during delete, membership already removed", map[string]any{
				"group_id": data.GroupID.ValueString(),
			})
			return
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

	// Verify the group exists and get its current members (one snapshot,
	// falling back to the per-member path; see loadMembershipView).
	view, err := r.loadMembershipView(ctx, membershipManager, groupGUID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Group Membership",
			fmt.Sprintf("Could not get members for group with GUID %s: %s", groupGUID, err.Error()),
		)
		return
	}
	currentMembers := view.dns

	// Create the resource model
	var data GroupMembershipResourceModel
	data.ID = types.StringValue(groupGUID)
	data.GroupID = types.StringValue(groupGUID)

	// For import, set Members to the plain DNs from AD (users can then
	// update their configuration to use their preferred identifier format)
	// and member_details to those same DNs paired with their GUIDs.
	if len(currentMembers) > 0 {
		membersSet, diags := types.SetValueFrom(ctx, types.StringType, currentMembers)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Members = membersSet
		data.MemberDetails = view.details
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

// isGroupNotFoundError reports whether err (possibly wrapped) means the group
// itself does not exist. It is deliberately narrow: only an *LDAPError whose
// message contains "not found", which is what GetCurrentMembers
// ("group with GUID %s not found", via NewNotFoundError) and GetGroupMembers
// (the same, from GroupManager.GetGroup) return for a missing group. It must
// NOT use ldapclient.IsNotFoundError: that pattern-matches generic text such
// as "no such object" / "does not exist", which a transient condition
// (replication lag, referral) can also produce, and a false positive here
// removes the resource from state.
func isGroupNotFoundError(err error) bool {
	var ldapErr *ldapclient.LDAPError
	return errors.As(err, &ldapErr) && strings.Contains(ldapErr.Error(), "not found")
}

// membershipView is a group's current membership as AD reports it: the
// normalised, sorted member DNs and the matching member_details set.
type membershipView struct {
	dns     []string
	details types.Set
}

// loadMembershipView reads the group's current membership for Read and
// ImportState. It is built from the SAME source ModifyPlan uses for member
// identity: a single GetCurrentMembers snapshot (extended-DN search), whose
// (DN, GUID) pairs are AD's own data. This matters for members outside the
// resolver's base DN (cross-domain users, FSPs, other naming contexts), which
// a base-DN-scoped per-member lookup cannot resolve: state would store an
// empty id that plan-time resolution then "heals", i.e. a perpetual update.
// It also costs one search instead of one lookup per member.
//
// Members whose snapshot GUID is empty keep id "". The fallback to
// GetGroupMembers plus per-member resolution happens ONLY when the snapshot
// fails with LDAP result code 12 (unavailableCriticalExtension, possibly
// wrapped), i.e. a server lacking the extended-DN control. Every other error
// (timeout, cancellation, access denied, disconnect, group not found, ...) is
// returned wrapped with %w, without a second read attempt, so Read and
// ImportState surface it. A missing group yields an error for which
// isGroupNotFoundError is true.
func (r *GroupMembershipResource) loadMembershipView(ctx context.Context, manager *ldapclient.GroupMembershipManager, groupID string) (*membershipView, error) {
	snapshot, err := manager.GetCurrentMembers(groupID)
	if err == nil {
		// GetCurrentMembers reports AD's order; sort by the normalised DN to
		// match GetGroupMembers.
		sort.SliceStable(snapshot, func(i, j int) bool { return snapshot[i].DN < snapshot[j].DN })

		dns := make([]string, 0, len(snapshot))
		details := make([]MemberDetailModel, 0, len(snapshot))
		for _, m := range snapshot {
			if m.GUID == "" {
				tflog.Warn(ctx, "Could not read current member's GUID; member_details.id will be empty for this member", map[string]any{"dn": m.DN})
			}
			dns = append(dns, m.DN)
			details = append(details, MemberDetailModel{
				DN: types.StringValue(m.DN),
				ID: types.StringValue(m.GUID),
			})
		}
		set, diags := types.SetValueFrom(ctx, memberDetailObjectType, details)
		if diags.HasError() {
			return nil, fmt.Errorf("could not create member details set: %v", diags.Errors())
		}
		return &membershipView{dns: dns, details: set}, nil
	}

	if !ldapclient.IsUnsupportedControlError(err) {
		return nil, fmt.Errorf("could not get current group members: %w", err)
	}

	tflog.Debug(ctx, "Server does not support the extended DN control; falling back to per-member resolution", map[string]any{
		"group_id": groupID,
		"error":    err.Error(),
	})

	dns, err := manager.GetGroupMembers(groupID)
	if err != nil {
		return nil, fmt.Errorf("could not get current group members: %w", err)
	}
	set, diags := r.resolveCurrentMemberDetails(ctx, dns)
	if diags.HasError() {
		return nil, fmt.Errorf("could not create member details set: %v", diags.Errors())
	}
	return &membershipView{dns: dns, details: set}, nil
}

// refreshMembershipState updates the model with current membership from Active Directory.
// This updates ONLY the MemberDetails attribute with current AD state,
// preserving the user's original configuration in the Members attribute.
func (r *GroupMembershipResource) refreshMembershipState(ctx context.Context, membershipManager *ldapclient.GroupMembershipManager, model *GroupMembershipResourceModel) error {
	view, err := r.loadMembershipView(ctx, membershipManager, model.GroupID.ValueString())
	if err != nil {
		return err
	}

	// DO NOT touch model.Members - preserve user's original configuration!
	model.MemberDetails = view.details

	tflog.Trace(ctx, "Refreshed membership state", map[string]any{
		"group_id":     model.GroupID.ValueString(),
		"member_count": len(view.dns),
		"members":      view.dns,
	})

	return nil
}
