package provider_test

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

func daclSDFlags() *ldap.ControlMicrosoftSDFlags {
	return &ldap.ControlMicrosoftSDFlags{
		Criticality:  true,
		ControlValue: int32(ldapclient.SDFlagsDACLSecurityInformation),
	}
}

// readDACL reads and parses the DACL of the object at dn.
func readDACL(ctx context.Context, client ldapclient.Client, dn string) (*ldapclient.SecurityDescriptor, error) {
	res, err := client.Search(ctx, &ldapclient.SearchRequest{
		BaseDN:     dn,
		Scope:      ldapclient.ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"nTSecurityDescriptor"},
		SizeLimit:  1,
		Controls:   []ldap.Control{daclSDFlags()},
	})
	if err != nil {
		return nil, fmt.Errorf("reading nTSecurityDescriptor of %s: %w", dn, err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("object not found: %s", dn)
	}
	raw := res.Entries[0].GetEqualFoldRawAttributeValue("nTSecurityDescriptor")
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s has no nTSecurityDescriptor", dn)
	}
	return ldapclient.UnmarshalSecurityDescriptor(raw)
}

// plantLegacyInheritableACE adds the deny-DELETE|DELETE_TREE ACE for Everyone
// WITH ContainerInherit, as written by provider versions up to v0.5.0.
func plantLegacyInheritableACE(ctx context.Context, client ldapclient.Client, dn string) error {
	sd, err := readDACL(ctx, client, dn)
	if err != nil {
		return err
	}
	everyone, err := ldapclient.ParseSID("S-1-1-0")
	if err != nil {
		return err
	}
	ace := ldapclient.ACE{
		AceType:    ldapclient.AccessDeniedACEType,
		AceFlags:   ldapclient.ContainerInheritACE,
		AccessMask: ldapclient.AccessMaskDelete | ldapclient.AccessMaskDeleteTree,
		SID:        everyone,
	}
	if sd.DACL == nil {
		sd.DACL = &ldapclient.ACL{AclRevision: 2, ACEs: []ldapclient.ACE{ace}}
		sd.Control |= ldapclient.SEDACLPresent
	} else {
		sd.DACL.ACEs = append([]ldapclient.ACE{ace}, sd.DACL.ACEs...) // deny ACEs first
	}
	raw, err := sd.Marshal()
	if err != nil {
		return fmt.Errorf("marshalling security descriptor: %w", err)
	}
	return client.Modify(ctx, &ldapclient.ModifyRequest{
		DN:                dn,
		ReplaceAttributes: map[string][]string{"nTSecurityDescriptor": {string(raw)}},
		Controls:          []ldap.Control{daclSDFlags()},
	})
}

// countDenyDeleteACEs counts deny DELETE|DELETE_TREE ACEs for Everyone (S-1-1-0):
// plain (non-inheritable explicit), legacy (explicit but inheritable by
// children) and inherited (copied from a parent).
func countDenyDeleteACEs(sd *ldapclient.SecurityDescriptor) (plain, legacy, inherited int) {
	if sd == nil || sd.DACL == nil {
		return
	}
	const inheritFlags = ldapclient.ContainerInheritACE | ldapclient.ObjectInheritACE
	const both = ldapclient.AccessMaskDelete | ldapclient.AccessMaskDeleteTree
	for _, ace := range sd.DACL.ACEs {
		if ace.RawBody != nil || ace.AceType != ldapclient.AccessDeniedACEType ||
			ace.AccessMask&both != both || ace.SID.String() != "S-1-1-0" {
			continue
		}
		switch {
		case ace.AceFlags&ldapclient.InheritedACE != 0:
			inherited++
		case ace.AceFlags&inheritFlags != 0:
			legacy++
		default:
			plain++
		}
	}
	return
}
