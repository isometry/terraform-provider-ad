package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	customtypes "github.com/isometry/terraform-provider-ad/internal/provider/types"
	"github.com/isometry/terraform-provider-ad/internal/provider/validators"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &OUResource{}
var _ resource.ResourceWithImportState = &OUResource{}

func NewOUResource() resource.Resource {
	return &OUResource{}
}

// OUResource defines the resource implementation.
type OUResource struct {
	client       ldapclient.Client
	cacheManager *ldapclient.CacheManager
}

// OUResourceModel describes the resource data model.
type OUResourceModel struct {
	ID          types.String              `tfsdk:"id"`          // objectGUID (computed)
	Name        types.String              `tfsdk:"name"`        // Required - OU name
	Path        customtypes.DNStringValue `tfsdk:"path"`        // Required - Parent container DN
	Description types.String              `tfsdk:"description"` // Optional - OU description
	Protected   types.Bool                `tfsdk:"protected"`   // Optional+Computed+Default: false
	// Computed attributes
	DN   customtypes.DNStringValue `tfsdk:"dn"`   // Computed - Full Distinguished Name
	GUID types.String              `tfsdk:"guid"` // Computed - GUID string (same as ID)
}

func (r *OUResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ou"
}

func (r *OUResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Manages an Active Directory organizational unit (OU). OUs are used to organize other Active Directory objects in a hierarchical structure for administrative purposes.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the OU. This is automatically assigned by Active Directory and used as the unique identifier.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the organizational unit. This becomes the CN component of the distinguished name.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 64),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[^"\\#+,;<=>\r\n/]+$`),
						"OU name cannot contain double quotes, backslashes, hash, plus, comma, semicolon, angle brackets, carriage return, newline, or forward slash",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"path": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the parent container where the OU will be created (e.g., `dc=example,dc=com` or `ou=Parent,dc=example,dc=com`).",
				Required:            true,
				CustomType:          customtypes.DNStringType{},
				Validators: []validator.String{
					validators.IsValidDN(),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description for the organizational unit. This is optional and can be used to provide additional context about the OU's purpose.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(1024),
				},
			},
			"protected": schema.BoolAttribute{
				MarkdownDescription: "Whether the OU is protected from accidental deletion. When true, the OU cannot be deleted until protection is disabled. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"dn": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the OU. This is automatically generated based on the name and path.",
				Computed:            true,
				CustomType:          customtypes.DNStringType{},
			},
			"guid": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the OU in string format. This is the same value as the `id` attribute.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *OUResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *OUResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data OUResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = initializeLogging(ctx)

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating AD OU", map[string]any{
		"name": data.Name.ValueString(),
		"path": data.Path.ValueString(),
	})

	// Create OUManager
	ouManager, err := r.getOUManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating OU Manager",
			err.Error(),
		)
		return
	}

	// Normalize parent DN case before creating
	normalizedParentDN, err := ldapclient.NormalizeDNCase(data.Path.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Parent DN",
			fmt.Sprintf("Could not normalize parent DN case: %s", err.Error()),
		)
		return
	}

	// Convert Terraform model to LDAP create request
	createReq := &ldapclient.CreateOURequest{
		Name:      data.Name.ValueString(),
		ParentDN:  normalizedParentDN,
		Protected: data.Protected.ValueBool(),
	}

	// Add optional description
	if !data.Description.IsNull() && data.Description.ValueString() != "" {
		createReq.Description = data.Description.ValueString()
	}

	// Create the OU
	ou, err := ouManager.CreateOU(createReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating OU",
			"Could not create organizational unit, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Created AD OU", map[string]any{
		"guid": ou.ObjectGUID,
		"dn":   ou.DistinguishedName,
	})

	// Update the model with the created OU data
	r.updateModelFromOU(&data, ou)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OUResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data OUResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = initializeLogging(ctx)

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading AD OU", map[string]any{
		"guid": data.ID.ValueString(),
	})

	// Create OUManager
	ouManager, err := r.getOUManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating OU Manager",
			err.Error(),
		)
		return
	}

	// Get the OU by GUID
	ou, err := ouManager.GetOU(data.ID.ValueString())
	if err != nil {
		// Check if the OU was not found
		if ldapErr, ok := err.(*ldapclient.LDAPError); ok {
			if strings.Contains(ldapErr.Error(), "not found") {
				resp.State.RemoveResource(ctx)
				return
			}
		}

		resp.Diagnostics.AddError(
			"Error Reading OU",
			fmt.Sprintf("Could not read organizational unit with ID %s: %s", data.ID.ValueString(), err.Error()),
		)
		return
	}

	// Update the model with the current OU data
	r.updateModelFromOU(&data, ou)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OUResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data OUResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = initializeLogging(ctx)

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating AD OU", map[string]any{
		"guid": data.ID.ValueString(),
	})

	// Create OUManager
	ouManager, err := r.getOUManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating OU Manager",
			err.Error(),
		)
		return
	}

	// Create update request
	updateReq := &ldapclient.UpdateOURequest{}
	hasChanges := false

	// Check for changes by comparing with current state
	var currentData OUResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &currentData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check for description changes
	if !data.Description.Equal(currentData.Description) {
		description := data.Description.ValueString()
		updateReq.Description = &description
		hasChanges = true
	}

	// Check for protection changes
	if !data.Protected.Equal(currentData.Protected) {
		protected := data.Protected.ValueBool()
		updateReq.Protected = &protected
		hasChanges = true
	}

	if !hasChanges {
		tflog.Debug(ctx, "No changes detected for AD OU")
		// No changes needed, just return current state
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	// Update the OU
	ou, err := ouManager.UpdateOU(data.ID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating OU",
			"Could not update organizational unit, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Updated AD OU", map[string]any{
		"guid": ou.ObjectGUID,
	})

	// Update the model with the updated OU data
	r.updateModelFromOU(&data, ou)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OUResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data OUResourceModel

	// Initialize logging subsystem for consistent logging
	ctx = initializeLogging(ctx)

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting AD OU", map[string]any{
		"guid": data.ID.ValueString(),
	})

	// Create OUManager
	ouManager, err := r.getOUManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating OU Manager",
			err.Error(),
		)
		return
	}

	// Delete the OU
	err = ouManager.DeleteOU(data.ID.ValueString())
	if err != nil {
		// Provide more helpful error messages for common scenarios
		if strings.Contains(err.Error(), "protected") {
			resp.Diagnostics.AddError(
				"Error Deleting Protected OU",
				fmt.Sprintf("Cannot delete OU %s because it is protected from accidental deletion. "+
					"Set the 'protected' attribute to false and apply the configuration before deleting.", data.Name.ValueString()),
			)
		} else {
			resp.Diagnostics.AddError(
				"Error Deleting OU",
				"Could not delete organizational unit, unexpected error: "+err.Error(),
			)
		}
		return
	}

	tflog.Debug(ctx, "Deleted AD OU", map[string]any{
		"guid": data.ID.ValueString(),
	})
}

func (r *OUResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Support import by GUID or DN
	importID := strings.TrimSpace(req.ID)

	tflog.Debug(ctx, "Importing AD OU", map[string]any{
		"import_id": importID,
	})

	// Create OUManager
	ouManager, err := r.getOUManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating OU Manager",
			err.Error(),
		)
		return
	}

	var ou *ldapclient.OU

	// Check if the import ID looks like a GUID
	if r.isGUID(importID) {
		// Import by GUID
		ou, err = ouManager.GetOU(importID)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Importing OU by GUID",
				fmt.Sprintf("Could not import organizational unit with GUID %s: %s", importID, err.Error()),
			)
			return
		}
	} else {
		// Import by DN
		ou, err = ouManager.GetOUByDN(importID)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Importing OU by DN",
				fmt.Sprintf("Could not import organizational unit with DN %s: %s", importID, err.Error()),
			)
			return
		}
	}

	// Create model from the imported OU
	var data OUResourceModel
	r.updateModelFromOU(&data, ou)

	tflog.Debug(ctx, "Imported AD OU", map[string]any{
		"guid": ou.ObjectGUID,
		"dn":   ou.DistinguishedName,
	})

	// Set the resource state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)

	// Set the ID for Terraform
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), ou.ObjectGUID)...)
}

// updateModelFromOU updates the Terraform model with data from an LDAP OU.
func (r *OUResource) updateModelFromOU(model *OUResourceModel, ou *ldapclient.OU) {
	model.ID = types.StringValue(ou.ObjectGUID)
	model.Name = types.StringValue(ou.Name)
	model.GUID = types.StringValue(ou.ObjectGUID) // Same as ID
	model.Protected = types.BoolValue(ou.Protected)

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := ldapclient.NormalizeDNCase(ou.DistinguishedName)
	if err != nil {
		// Log error but use original DN as fallback
		tflog.Warn(context.Background(), "Failed to normalize OU DN case", map[string]any{
			"original_dn": ou.DistinguishedName,
			"error":       err.Error(),
		})
		normalizedDN = ou.DistinguishedName
	}
	model.DN = customtypes.DNString(normalizedDN)

	// Normalize parent path DN case
	normalizedParent, err := ldapclient.NormalizeDNCase(ou.Parent)
	if err != nil {
		// Log error but use original parent as fallback
		tflog.Warn(context.Background(), "Failed to normalize parent DN case", map[string]any{
			"original_parent": ou.Parent,
			"error":           err.Error(),
		})
		normalizedParent = ou.Parent
	}
	model.Path = customtypes.DNString(normalizedParent)

	// Handle optional description
	if ou.Description != "" {
		model.Description = types.StringValue(ou.Description)
	} else {
		model.Description = types.StringNull()
	}
}

// getOUManager creates an OUManager instance with base DN lookup.
func (r *OUResource) getOUManager(ctx context.Context) (*ldapclient.OUManager, error) {
	// Get base DN from client
	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get base DN from LDAP server: %w", err)
	}

	// Create OUManager
	return ldapclient.NewOUManager(ctx, r.client, baseDN), nil
}

// isGUID checks if a string looks like a GUID.
func (r *OUResource) isGUID(s string) bool {
	// GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	guidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return guidRegex.MatchString(s)
}
