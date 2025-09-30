# Important Patterns and Best Practices

## LDAP-Specific Patterns

### 1. Logging Context
Always pass context through for proper logging subsystem integration:
```go
ctx = utils.InitializeLogging(ctx)
tflog.Debug(ctx, "operation message", map[string]any{
    "key": "value",
})
```

### 2. Error Wrapping
Use error chains for proper error context:
```go
return fmt.Errorf("description: %w", err)
```

### 3. GUID Handling
GUIDs in LDAP are binary, must be converted for Terraform state:
```go
guid, err := ldap.ParseGUID(binaryGUID)
stringGUID := ldap.FormatGUID(guid)
```

### 4. DN Validation
Use custom validators from internal/provider/validators/:
```go
Validators: []validator.String{
    validators.IsValidDN(),
}
```

### 5. Member Normalization
Use NormalizeMember() for identifier conversion:
```go
dn, err := ldap.NormalizeMember(identifier, client)
```

## Terraform Framework Patterns

### 1. Resource ID
All resources use objectGUID as Terraform resource ID:
```go
model.ID = types.StringValue(group.ObjectGUID)
```

### 2. Schema Definition
Use terraform-plugin-framework schema with validators and plan modifiers:
```go
"sam_account_name": schema.StringAttribute{
    Optional: true,
    Computed: true,
    PlanModifiers: []planmodifier.String{
        planmodifiers.UseNameForSAMAccountName(false),
    },
}
```

### 3. CRUD Operations
Full Create, Read, Update, Delete with error handling:
```go
func (r *GroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
    // Read plan
    // Initialize logging
    // Create resource
    // Update state
}
```

## Common Pitfalls

1. **GUID Encoding**: GUIDs in LDAP are binary, must be converted for Terraform state
2. **DN Case Sensitivity**: LDAP DNs are case-insensitive but Terraform is case-sensitive (use NormalizeDNCase)
3. **Group Type**: AD stores groupType as integer combining scope and category bits
4. **Authentication**: Different username formats (DN/UPN/SAM) require different bind methods
5. **Kerberos SPN**: IP-based connections need explicit SPN when using Kerberos

## Expert Coordination

### Main Agent Role
- Coordinator and arbiter, NOT implementer
- Maintains PROGRESS.md with current status
- Delegates ALL development work to expert agents
- Never implements code directly

### Expert Boundaries
- **active-directory-ldap-expert**: All LDAP/AD code (internal/ldap/)
- **terraform-provider-expert**: All Terraform provider code (internal/provider/)
- Main agent coordinates integration between domains