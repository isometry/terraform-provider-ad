package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

const (
	gmGroupGUID  = "11111111-2222-3333-4444-555555555555"
	gmMemberGUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	gmMemberDN   = "CN=Member,OU=Test,DC=example,DC=com"
)

// groupMemberStubClient answers the base-scope membership check made on the
// group's "<GUID=...>" DN, the member's GUID lookup, and the member-removal
// modify. Every other method panics via the nil embedded interface.
type groupMemberStubClient struct {
	ldapclient.Client
	memberCheckErr error  // error of the membership check
	isMember       bool   // result of the membership check
	memberDN       string // current DN of the member; "" makes the GUID lookup fail
	modifyErr      error
}

func (c *groupMemberStubClient) GetBaseDN(context.Context) (string, error) {
	return "DC=example,DC=com", nil
}

func (c *groupMemberStubClient) Search(_ context.Context, req *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
	if strings.HasPrefix(req.BaseDN, "<GUID=") {
		if c.memberCheckErr != nil {
			return nil, c.memberCheckErr
		}
		if !c.isMember {
			return &ldapclient.SearchResult{}, nil
		}
		return &ldapclient.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(req.BaseDN, nil)}}, nil
	}
	if c.memberDN == "" {
		return nil, errors.New("lookup failed")
	}
	raw, err := ldapclient.NewGUIDHandler().StringToGUIDBytes(gmMemberGUID)
	if err != nil {
		return nil, err
	}
	entry := ldap.NewEntry(c.memberDN, nil)
	entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: "objectGUID", ByteValues: [][]byte{raw}})
	return &ldapclient.SearchResult{Entries: []*ldap.Entry{entry}}, nil
}

func (c *groupMemberStubClient) Modify(context.Context, *ldapclient.ModifyRequest) error {
	return c.modifyErr
}

func groupMemberState(t *testing.T, ctx context.Context, r *GroupMemberResource) tfsdk.State {
	t.Helper()
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	st := tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}
	data := GroupMemberResourceModel{
		ID:            types.StringValue(gmGroupGUID + "/" + gmMemberGUID),
		GroupID:       types.StringValue(gmGroupGUID),
		Member:        types.StringValue("member@example.com"),
		MemberDetails: newMemberDetailsObject(gmMemberDN, gmMemberGUID),
	}
	if d := st.Set(ctx, &data); d.HasError() {
		t.Fatalf("building state: %v", d.Errors())
	}
	return st
}

func TestGroupMemberResource_Schema(t *testing.T) {
	resp := &resource.SchemaResponse{}
	(&GroupMemberResource{}).Schema(t.Context(), resource.SchemaRequest{}, resp)
	attrs := resp.Schema.Attributes

	for _, name := range []string{"group_id", "member"} {
		a, ok := attrs[name].(schema.StringAttribute)
		if !ok || !a.Required || len(a.PlanModifiers) != 1 {
			t.Errorf("%s: want a required string attribute with RequiresReplace, got %#v", name, attrs[name])
		}
	}
	if a, ok := attrs["id"].(schema.StringAttribute); !ok || !a.Computed || a.Optional || a.Required {
		t.Errorf("id: want computed-only string, got %#v", attrs["id"])
	}
	details, ok := attrs["member_details"].(schema.SingleNestedAttribute)
	if !ok || !details.Computed || details.Optional || details.Required {
		t.Fatalf("member_details: want computed-only single nested attribute, got %#v", attrs["member_details"])
	}
	if len(details.Attributes) != 2 || details.Attributes["dn"] == nil || details.Attributes["id"] == nil {
		t.Errorf("member_details: want attributes dn and id, got %v", details.Attributes)
	}
	if _, ok := attrs["ignore_missing_members"]; ok {
		t.Error("ignore_missing_members must not exist on ad_group_member")
	}
}

func TestParseGroupMemberImportID(t *testing.T) {
	group, member, err := parseGroupMemberImportID(" 11111111-2222-3333-4444-555555555555/AAAAAAAABBBBCCCCDDDDEEEEEEEEEEEE ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if group != gmGroupGUID || member != gmMemberGUID {
		t.Errorf("got (%s, %s), want canonical (%s, %s)", group, member, gmGroupGUID, gmMemberGUID)
	}

	for _, id := range []string{
		gmGroupGUID,
		gmGroupGUID + "/",
		gmGroupGUID + "/" + gmMemberGUID + "/" + gmMemberGUID,
		gmGroupGUID + "/" + gmMemberDN,
		"group/" + gmMemberGUID,
	} {
		if _, _, err := parseGroupMemberImportID(id); err == nil {
			t.Errorf("%q: expected an error", id)
		}
	}
}

func TestGroupMemberResource_Read(t *testing.T) {
	tests := map[string]struct {
		client      groupMemberStubClient
		wantRemoved bool
		wantError   bool
		wantDN      string
	}{
		"member renamed": {
			client: groupMemberStubClient{isMember: true, memberDN: "CN=Renamed,OU=Test,DC=example,DC=com"},
			wantDN: "CN=Renamed,OU=Test,DC=example,DC=com",
		},
		"member DN lookup fails": {
			client: groupMemberStubClient{isMember: true},
			wantDN: gmMemberDN,
		},
		"not a member": {
			client:      groupMemberStubClient{memberDN: gmMemberDN},
			wantRemoved: true,
		},
		"group not found": {
			client:      groupMemberStubClient{memberCheckErr: ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))},
			wantRemoved: true,
		},
		"membership check fails": {
			client:    groupMemberStubClient{memberCheckErr: ldap.NewError(ldap.LDAPResultBusy, errors.New("busy"))},
			wantError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			r := &GroupMemberResource{client: &tc.client, cacheManager: ldapclient.NewCacheManager()}
			st := groupMemberState(t, ctx, r)
			resp := &resource.ReadResponse{State: st}
			r.Read(ctx, resource.ReadRequest{State: st}, resp)

			if resp.Diagnostics.HasError() != tc.wantError {
				t.Fatalf("diagnostics: %v", resp.Diagnostics)
			}
			if tc.wantError {
				return
			}
			if removed := resp.State.Raw.IsNull(); removed != tc.wantRemoved {
				t.Fatalf("removed = %v, want %v", removed, tc.wantRemoved)
			}
			if tc.wantRemoved {
				return
			}
			var out GroupMemberResourceModel
			if d := resp.State.Get(ctx, &out); d.HasError() {
				t.Fatalf("reading state: %v", d.Errors())
			}
			want := newMemberDetailsObject(tc.wantDN, gmMemberGUID)
			if !out.MemberDetails.Equal(want) {
				t.Errorf("member_details = %v, want %v", out.MemberDetails, want)
			}
		})
	}
}

func TestGroupMemberResource_DeleteMissingGroupSucceeds(t *testing.T) {
	ctx := t.Context()
	client := &groupMemberStubClient{modifyErr: ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))}
	r := &GroupMemberResource{client: client, cacheManager: ldapclient.NewCacheManager()}
	st := groupMemberState(t, ctx, r)
	resp := &resource.DeleteResponse{State: st}
	r.Delete(ctx, resource.DeleteRequest{State: st}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
}
