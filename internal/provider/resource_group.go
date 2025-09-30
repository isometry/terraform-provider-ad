package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	"github.com/isometry/terraform-provider-ad/internal/provider/planmodifiers"
	customtypes "github.com/isometry/terraform-provider-ad/internal/provider/types"
	"github.com/isometry/terraform-provider-ad/internal/provider/validators"
	"github.com/isometry/terraform-provider-ad/internal/utils"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &GroupResource{}
var _ resource.ResourceWithImportState = &GroupResource{}

// NewGroupResource creates a new instance of the group resource.
func NewGroupResource() resource.Resource {
	return &GroupResource{}
}

// GroupResource defines the resource implementation.
type GroupResource struct {
	client       ldapclient.Client
	cacheManager *ldapclient.CacheManager
}

// GroupResourceModel describes the resource data model.
type GroupResourceModel struct {
	ID             types.String              `tfsdk:"id"`               // objectGUID (computed)
	Name           types.String              `tfsdk:"name"`             // Required - cn attribute
	SAMAccountName types.String              `tfsdk:"sam_account_name"` // Required - sAMAccountName
	Container      customtypes.DNStringValue `tfsdk:"container"`        // Required - parent container DN
	Scope          types.String              `tfsdk:"scope"`            // Optional+Computed+Default: "Global"
	Category       types.String              `tfsdk:"category"`         // Optional+Computed+Default: "Security"
	Description    types.String              `tfsdk:"description"`      // Optional
	ManagedBy      types.String              `tfsdk:"managed_by"`       // Optional+Computed - managedBy attribute
	// Computed attributes
	DistinguishedName customtypes.DNStringValue `tfsdk:"dn"`  // Computed
	SID               types.String              `tfsdk:"sid"` // Computed
}

func (r *GroupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *GroupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Manages an Active Directory group. Groups are used for organizing users and other groups for access control and email distribution.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the group. This is automatically assigned by Active Directory and used as the unique identifier.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the group (cn attribute). This is the display name visible in Active Directory.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 64),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[^"]+$`),
						"Group name cannot contain double quotes",
					),
				},
			},
			"sam_account_name": schema.StringAttribute{
				MarkdownDescription: "The SAM account name (pre-Windows 2000 group name). Must be unique within the domain. " +
					"If not specified, defaults to the value of 'name' if it's 64 characters or less " +
					"and contains only valid characters (letters, numbers, dots, underscores, hyphens).",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 64),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-zA-Z0-9._-]+$`),
						"SAM account name can only contain letters, numbers, dots, underscores, and hyphens",
					),
				},
				PlanModifiers: []planmodifier.String{
					planmodifiers.UseNameForSAMAccountName(false), // false = group (64 char limit)
				},
			},
			"container": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the container or organizational unit where the group will be created (e.g., `ou=Groups,dc=example,dc=com`).",
				Required:            true,
				CustomType:          customtypes.DNStringType{},
				Validators: []validator.String{
					validators.IsValidDN(),
				},
			},
			"scope": schema.StringAttribute{
				MarkdownDescription: "The scope of the group. Valid values are `Global`, `Universal`, or `DomainLocal`. Defaults to `Global`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("Global"),
				Validators: []validator.String{
					stringvalidator.OneOf("Global", "Universal", "DomainLocal"),
				},
			},
			"category": schema.StringAttribute{
				MarkdownDescription: "The category of the group. Valid values are `Security` or `Distribution`. Defaults to `Security`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("Security"),
				Validators: []validator.String{
					stringvalidator.OneOf("Security", "Distribution"),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description for the group. This is optional and can be used to provide additional context about the group's purpose.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(1024),
				},
			},
			"managed_by": schema.StringAttribute{
				MarkdownDescription: "Distinguished Name (DN) of the user or computer that manages this group. " +
					"Must be a valid DN format (e.g., `CN=User,OU=Users,DC=example,DC=com`).",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					validators.IsValidDN(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dn": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the group. This is automatically generated based on the name and container.",
				Computed:            true,
				CustomType:          customtypes.DNStringType{},
			},
			"sid": schema.StringAttribute{
				MarkdownDescription: "The Security Identifier (SID) of the group. This is automatically assigned by Active Directory.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *GroupResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *GroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GroupResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Set up entry/exit logging
	start := time.Now()
	tflog.Debug(ctx, "Starting resource operation", map[string]any{
		"operation": "create",
		"resource":  "ad_group",
		"name":      data.Name.ValueString(),
		"scope":     data.Scope.ValueString(),
		"category":  data.Category.ValueString(),
	})
	defer func() {
		duration := time.Since(start)
		if resp.Diagnostics.HasError() {
			tflog.Error(ctx, "Resource operation failed", map[string]any{
				"operation":   "create",
				"resource":    "ad_group",
				"duration_ms": duration.Milliseconds(),
			})
		} else {
			tflog.Info(ctx, "Resource operation completed", map[string]any{
				"operation":   "create",
				"resource":    "ad_group",
				"duration_ms": duration.Milliseconds(),
			})
		}
	}()

	tflog.Debug(ctx, "Creating AD group", map[string]any{
		"name":             data.Name.ValueString(),
		"sam_account_name": data.SAMAccountName.ValueString(),
		"container":        data.Container.ValueString(),
	})

	// Create GroupManager
	groupManager, err := r.getGroupManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Manager",
			err.Error(),
		)
		return
	}

	// Convert Terraform model to LDAP create request
	createReq := &ldapclient.CreateGroupRequest{
		Name:           data.Name.ValueString(),
		SAMAccountName: data.SAMAccountName.ValueString(),
		Container:      data.Container.ValueString(),
		Scope:          ldapclient.GroupScope(data.Scope.ValueString()),
		Category:       ldapclient.GroupCategory(data.Category.ValueString()),
	}

	// Add optional description
	if !data.Description.IsNull() && data.Description.ValueString() != "" {
		createReq.Description = data.Description.ValueString()
	}

	// Add optional managedBy
	if !data.ManagedBy.IsNull() && data.ManagedBy.ValueString() != "" {
		createReq.ManagedBy = data.ManagedBy.ValueString()
	}

	// Create the group
	group, err := groupManager.CreateGroup(createReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group",
			"Could not create group, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Created AD group", map[string]any{
		"guid": group.ObjectGUID,
		"dn":   group.DistinguishedName,
	})

	// Update the model with the created group data
	r.updateModelFromGroup(&data, group)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GroupResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading AD group", map[string]any{
		"guid": data.ID.ValueString(),
	})

	// Create GroupManager
	groupManager, err := r.getGroupManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Manager",
			err.Error(),
		)
		return
	}

	// Get the group by GUID
	group, err := groupManager.GetGroup(data.ID.ValueString())
	if err != nil {
		// Check if the group was not found
		if ldapErr, ok := err.(*ldapclient.LDAPError); ok {
			if strings.Contains(ldapErr.Error(), "not found") {
				resp.State.RemoveResource(ctx)
				return
			}
		}

		resp.Diagnostics.AddError(
			"Error Reading Group",
			fmt.Sprintf("Could not read group with ID %s: %s", data.ID.ValueString(), err.Error()),
		)
		return
	}

	// Update the model with the current group data
	r.updateModelFromGroup(&data, group)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data GroupResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating AD group", map[string]any{
		"guid": data.ID.ValueString(),
	})

	// Create GroupManager
	groupManager, err := r.getGroupManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Manager",
			err.Error(),
		)
		return
	}

	// Create update request
	updateReq := &ldapclient.UpdateGroupRequest{}
	hasChanges := false

	// Check for name changes
	var currentData GroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &currentData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !data.Name.Equal(currentData.Name) {
		name := data.Name.ValueString()
		updateReq.Name = &name
		hasChanges = true
	}

	// Check for SAM account name changes
	if !data.SAMAccountName.Equal(currentData.SAMAccountName) {
		samAccountName := data.SAMAccountName.ValueString()
		updateReq.SAMAccountName = &samAccountName
		hasChanges = true
	}

	// Check for description changes
	if !data.Description.Equal(currentData.Description) {
		description := data.Description.ValueString()
		updateReq.Description = &description
		hasChanges = true
	}

	// Check for scope changes
	if !data.Scope.Equal(currentData.Scope) {
		scope := ldapclient.GroupScope(data.Scope.ValueString())
		updateReq.Scope = &scope
		hasChanges = true
	}

	// Check for category changes
	if !data.Category.Equal(currentData.Category) {
		category := ldapclient.GroupCategory(data.Category.ValueString())
		updateReq.Category = &category
		hasChanges = true
	}

	// Check for container changes (triggers group move)
	if !data.Container.Equal(currentData.Container) {
		container := data.Container.ValueString()
		updateReq.Container = &container
		hasChanges = true
	}

	// Check for managedBy changes
	if !data.ManagedBy.Equal(currentData.ManagedBy) {
		if data.ManagedBy.IsNull() {
			// Clear the managedBy attribute
			emptyString := ""
			updateReq.ManagedBy = &emptyString
		} else {
			// Set new managedBy value
			managedByValue := data.ManagedBy.ValueString()
			updateReq.ManagedBy = &managedByValue
		}
		hasChanges = true
	}

	// If no changes at all, return current state
	if !hasChanges {
		tflog.Debug(ctx, "No changes detected for AD group")
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	// Update the group
	group, err := groupManager.UpdateGroup(data.ID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Group",
			"Could not update group, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Updated AD group", map[string]any{
		"guid": group.ObjectGUID,
	})

	// Update the model with the updated group data
	r.updateModelFromGroup(&data, group)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GroupResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting AD group", map[string]any{
		"guid": data.ID.ValueString(),
	})

	// Create GroupManager
	groupManager, err := r.getGroupManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Manager",
			err.Error(),
		)
		return
	}

	// Delete the group
	err = groupManager.DeleteGroup(data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Group",
			"Could not delete group, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Deleted AD group", map[string]any{
		"guid": data.ID.ValueString(),
	})
}

func (r *GroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Support import by GUID or DN
	importID := strings.TrimSpace(req.ID)

	tflog.Debug(ctx, "Importing AD group", map[string]any{
		"import_id": importID,
	})

	// Create GroupManager
	groupManager, err := r.getGroupManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Group Manager",
			err.Error(),
		)
		return
	}

	var group *ldapclient.Group

	// Check if the import ID looks like a GUID
	if r.isGUID(importID) {
		// Import by GUID
		group, err = groupManager.GetGroup(importID)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Importing Group by GUID",
				fmt.Sprintf("Could not import group with GUID %s: %s", importID, err.Error()),
			)
			return
		}
	} else {
		// Import by DN
		group, err = groupManager.GetGroupByDN(importID)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Importing Group by DN",
				fmt.Sprintf("Could not import group with DN %s: %s", importID, err.Error()),
			)
			return
		}
	}

	// Create model from the imported group
	var data GroupResourceModel
	r.updateModelFromGroup(&data, group)

	tflog.Debug(ctx, "Imported AD group", map[string]any{
		"guid": group.ObjectGUID,
		"dn":   group.DistinguishedName,
	})

	// Set the resource state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)

	// Set the ID for Terraform
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), group.ObjectGUID)...)
}

// updateModelFromGroup updates the Terraform model with data from an LDAP Group.
func (r *GroupResource) updateModelFromGroup(model *GroupResourceModel, group *ldapclient.Group) {
	model.ID = types.StringValue(group.ObjectGUID)
	model.Name = types.StringValue(group.Name)
	model.SAMAccountName = types.StringValue(group.SAMAccountName)
	model.Scope = types.StringValue(string(group.Scope))
	model.Category = types.StringValue(string(group.Category))
	model.SID = types.StringValue(group.ObjectSid)

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := ldapclient.NormalizeDNCase(group.DistinguishedName)
	if err != nil {
		// Log error but use original DN as fallback
		tflog.Warn(context.Background(), "Failed to normalize group DN case", map[string]any{
			"original_dn": group.DistinguishedName,
			"error":       err.Error(),
		})
		normalizedDN = group.DistinguishedName
	}
	model.DistinguishedName = customtypes.DNString(normalizedDN)

	// Normalize container DN case
	normalizedContainer, err := ldapclient.NormalizeDNCase(group.Container)
	if err != nil {
		// Log error but use original container as fallback
		tflog.Warn(context.Background(), "Failed to normalize container DN case", map[string]any{
			"original_container": group.Container,
			"error":              err.Error(),
		})
		normalizedContainer = group.Container
	}
	model.Container = customtypes.DNString(normalizedContainer)

	// Handle optional description
	if group.Description != "" {
		model.Description = types.StringValue(group.Description)
	} else {
		model.Description = types.StringNull()
	}

	// Handle optional managedBy
	if group.ManagedBy != "" {
		model.ManagedBy = types.StringValue(group.ManagedBy)
	} else {
		model.ManagedBy = types.StringNull()
	}
}

// getGroupManager creates a GroupManager instance with base DN lookup.
func (r *GroupResource) getGroupManager(ctx context.Context) (*ldapclient.GroupManager, error) {
	// Get base DN from client
	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get base DN from LDAP server: %w", err)
	}

	// Create GroupManager
	return ldapclient.NewGroupManager(ctx, r.client, baseDN, r.cacheManager), nil
}

// isGUID checks if a string looks like a GUID.
func (r *GroupResource) isGUID(s string) bool {
	// GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	guidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return guidRegex.MatchString(s)
}
