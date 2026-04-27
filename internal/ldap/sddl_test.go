package ldap

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// accessAllowedObjectACEType is 0x05 — ACCESS_ALLOWED_OBJECT_ACE (MS-DTYP
// 2.4.4.3). Kept as a test-local constant so the production code isn't
// polluted with a constant it never uses.
const accessAllowedObjectACEType uint8 = 0x05

// buildObjectACEBody constructs a plausible ACCESS_ALLOWED_OBJECT_ACE body
// (everything after the 4-byte generic ACE header):
//
//	Mask (4)       : access mask
//	Flags (4)      : ACE_OBJECT_TYPE_PRESENT (0x01)
//	ObjectType(16) : GUID
//	(InheritedObjectType omitted because that flag bit is not set)
//	Sid            : variable length SID
//
// It returns the body bytes. The caller is responsible for computing total
// ACE size and writing the header.
func buildObjectACEBody(t *testing.T, mask uint32, objectGUID [16]byte, sid SID) []byte {
	t.Helper()
	sidBytes, err := sid.Bytes()
	require.NoError(t, err)
	body := make([]byte, 0, 4+4+16+len(sidBytes))
	// Access mask
	mbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(mbuf, mask)
	body = append(body, mbuf...)
	// Object flags: ACE_OBJECT_TYPE_PRESENT
	fbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(fbuf, 0x00000001)
	body = append(body, fbuf...)
	// ObjectType GUID (16 bytes)
	body = append(body, objectGUID[:]...)
	// SID
	body = append(body, sidBytes...)
	return body
}

// buildSD is a tiny helper used across sddl tests.
func buildSD(protected bool) *SecurityDescriptor {
	sd := &SecurityDescriptor{
		Revision: 1,
		Control:  SESelfRelative | SEDACLPresent,
		Owner: &SID{
			RevisionLevel:  1,
			Authority:      5,
			SubAuthorities: []uint32{32, 544}, // BUILTIN\Administrators
		},
		Group: &SID{
			RevisionLevel:  1,
			Authority:      5,
			SubAuthorities: []uint32{18}, // Local System
		},
		DACL: &ACL{
			AclRevision: 2,
			ACEs: []ACE{
				{
					AceType:    AccessAllowedACEType,
					AceFlags:   ContainerInheritACE,
					AccessMask: 0x000F01FF,
					SID: SID{
						RevisionLevel:  1,
						Authority:      5,
						SubAuthorities: []uint32{18},
					},
				},
			},
		},
	}
	if protected {
		sd.AddDenyDeleteEveryoneACE()
	}
	return sd
}

func TestSecurityDescriptor_RoundTrip_Unprotected(t *testing.T) {
	original := buildSD(false)
	raw, err := original.Marshal()
	require.NoError(t, err)

	parsed, err := UnmarshalSecurityDescriptor(raw)
	require.NoError(t, err)

	assert.Equal(t, original.Revision, parsed.Revision)
	assert.True(t, parsed.Control&SESelfRelative != 0)
	assert.True(t, parsed.Control&SEDACLPresent != 0)
	require.NotNil(t, parsed.DACL)
	require.Len(t, parsed.DACL.ACEs, 1)
	assert.Equal(t, original.DACL.ACEs[0].AceType, parsed.DACL.ACEs[0].AceType)
	assert.Equal(t, original.DACL.ACEs[0].AccessMask, parsed.DACL.ACEs[0].AccessMask)
	assert.Equal(t, original.DACL.ACEs[0].SID.String(), parsed.DACL.ACEs[0].SID.String())

	require.NotNil(t, parsed.Owner)
	assert.Equal(t, original.Owner.String(), parsed.Owner.String())
	require.NotNil(t, parsed.Group)
	assert.Equal(t, original.Group.String(), parsed.Group.String())

	// Re-marshal must be byte-identical after a round-trip.
	again, err := parsed.Marshal()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(raw, again), "round-trip marshal should be stable")
}

func TestSecurityDescriptor_RoundTrip_Protected(t *testing.T) {
	original := buildSD(true)
	raw, err := original.Marshal()
	require.NoError(t, err)

	parsed, err := UnmarshalSecurityDescriptor(raw)
	require.NoError(t, err)

	assert.True(t, parsed.HasDenyDeleteEveryoneACE())
	// The deny ACE must come first (canonical order).
	require.NotNil(t, parsed.DACL)
	require.GreaterOrEqual(t, len(parsed.DACL.ACEs), 1)
	assert.Equal(t, AccessDeniedACEType, parsed.DACL.ACEs[0].AceType)
	assert.Equal(t, everyoneSIDValue.String(), parsed.DACL.ACEs[0].SID.String())
	assert.Equal(t,
		AccessMaskDelete|AccessMaskDeleteChild,
		parsed.DACL.ACEs[0].AccessMask&(AccessMaskDelete|AccessMaskDeleteChild))
}

func TestSecurityDescriptor_HasDenyDeleteEveryoneACE_Negative(t *testing.T) {
	cases := []struct {
		name string
		sd   *SecurityDescriptor
	}{
		{
			name: "nil descriptor",
			sd:   nil,
		},
		{
			name: "no DACL",
			sd:   &SecurityDescriptor{Revision: 1, Control: SESelfRelative},
		},
		{
			name: "DACL with only allow ACE",
			sd:   buildSD(false),
		},
		{
			name: "deny ACE but wrong SID",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SESelfRelative | SEDACLPresent,
				DACL: &ACL{
					AclRevision: 2,
					ACEs: []ACE{{
						AceType:    AccessDeniedACEType,
						AccessMask: AccessMaskDelete | AccessMaskDeleteChild,
						SID: SID{
							RevisionLevel:  1,
							Authority:      5,
							SubAuthorities: []uint32{18},
						},
					}},
				},
			},
		},
		{
			name: "deny ACE to Everyone but only DELETE (no DELETE_CHILD)",
			sd: &SecurityDescriptor{
				Revision: 1,
				Control:  SESelfRelative | SEDACLPresent,
				DACL: &ACL{
					AclRevision: 2,
					ACEs: []ACE{{
						AceType:    AccessDeniedACEType,
						AccessMask: AccessMaskDelete,
						SID:        everyoneSIDValue,
					}},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, tc.sd.HasDenyDeleteEveryoneACE())
		})
	}
}

func TestSecurityDescriptor_AddAndRemoveDenyDeleteACE(t *testing.T) {
	sd := buildSD(false)
	assert.False(t, sd.HasDenyDeleteEveryoneACE())

	sd.AddDenyDeleteEveryoneACE()
	assert.True(t, sd.HasDenyDeleteEveryoneACE())
	// Deny must precede any allow.
	assert.Equal(t, AccessDeniedACEType, sd.DACL.ACEs[0].AceType)

	removed := sd.RemoveDenyDeleteEveryoneACE()
	assert.True(t, removed)
	assert.False(t, sd.HasDenyDeleteEveryoneACE())

	// Removing again is a no-op.
	removed = sd.RemoveDenyDeleteEveryoneACE()
	assert.False(t, removed)
}

func TestSecurityDescriptor_AddDenyDeleteACE_NoDACL(t *testing.T) {
	sd := &SecurityDescriptor{Revision: 1, Control: SESelfRelative}
	assert.False(t, sd.HasDenyDeleteEveryoneACE())

	sd.AddDenyDeleteEveryoneACE()
	require.NotNil(t, sd.DACL)
	assert.True(t, sd.Control&SEDACLPresent != 0)
	assert.True(t, sd.HasDenyDeleteEveryoneACE())
}

func TestUnmarshalSecurityDescriptor_Errors(t *testing.T) {
	// Too short.
	_, err := UnmarshalSecurityDescriptor([]byte{0x01, 0x00, 0x00, 0x80})
	assert.Error(t, err)

	// Absolute (non-self-relative) rejected.
	absolute := make([]byte, 20)
	absolute[0] = 1
	// No SESelfRelative bit set.
	_, err = UnmarshalSecurityDescriptor(absolute)
	assert.Error(t, err)
}

func TestRoundTrip_DACLOnly(t *testing.T) {
	// Minimal DACL-only descriptor matching what LDAP_SERVER_SD_FLAGS_OID
	// with DACL_SECURITY_INFORMATION returns on read.
	sd := &SecurityDescriptor{
		Revision: 1,
		Control:  SESelfRelative | SEDACLPresent,
		DACL: &ACL{
			AclRevision: 2,
			ACEs: []ACE{{
				AceType:    AccessDeniedACEType,
				AceFlags:   ContainerInheritACE,
				AccessMask: AccessMaskDelete | AccessMaskDeleteChild,
				SID:        everyoneSIDValue,
			}},
		},
	}
	raw, err := sd.Marshal()
	require.NoError(t, err)
	parsed, err := UnmarshalSecurityDescriptor(raw)
	require.NoError(t, err)
	assert.Nil(t, parsed.Owner)
	assert.Nil(t, parsed.Group)
	assert.Nil(t, parsed.SACL)
	assert.True(t, parsed.HasDenyDeleteEveryoneACE())
}

// TestSecurityDescriptor_ObjectACE_RoundTrip verifies that a DACL containing
// both a simple deny ACE and an ACCESS_ALLOWED_OBJECT_ACE (type 0x05) round
// trips bit-identically through Unmarshal/Marshal even though we don't parse
// the object ACE semantically.
func TestSecurityDescriptor_ObjectACE_RoundTrip(t *testing.T) {
	objectGUID := [16]byte{
		0xbf, 0x96, 0x79, 0xbb, 0x0d, 0xe6, 0x11, 0xd0,
		0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2,
	}
	objectBody := buildObjectACEBody(t, 0x00000030, objectGUID, SID{
		RevisionLevel:  1,
		Authority:      5,
		SubAuthorities: []uint32{32, 544}, // BUILTIN\Administrators
	})

	sd := &SecurityDescriptor{
		Revision: 1,
		Control:  SESelfRelative | SEDACLPresent,
		DACL: &ACL{
			AclRevision: 4, // ACL_REVISION_DS when object ACEs are present
			ACEs: []ACE{
				{
					AceType:    AccessDeniedACEType,
					AceFlags:   ContainerInheritACE,
					AccessMask: AccessMaskDelete | AccessMaskDeleteChild,
					SID:        everyoneSIDValue,
				},
				{
					AceType:  accessAllowedObjectACEType,
					AceFlags: ContainerInheritACE | InheritedACE,
					RawBody:  objectBody,
				},
			},
		},
	}

	raw, err := sd.Marshal()
	require.NoError(t, err)

	parsed, err := UnmarshalSecurityDescriptor(raw)
	require.NoError(t, err)
	require.NotNil(t, parsed.DACL)
	require.Len(t, parsed.DACL.ACEs, 2)

	// Simple deny ACE parsed structurally.
	assert.Equal(t, AccessDeniedACEType, parsed.DACL.ACEs[0].AceType)
	assert.Nil(t, parsed.DACL.ACEs[0].RawBody)
	assert.Equal(t,
		AccessMaskDelete|AccessMaskDeleteChild,
		parsed.DACL.ACEs[0].AccessMask)
	assert.Equal(t, everyoneSIDValue.String(), parsed.DACL.ACEs[0].SID.String())

	// Object ACE preserved opaquely.
	assert.Equal(t, accessAllowedObjectACEType, parsed.DACL.ACEs[1].AceType)
	require.NotNil(t, parsed.DACL.ACEs[1].RawBody)
	assert.True(t, bytes.Equal(objectBody, parsed.DACL.ACEs[1].RawBody),
		"object ACE body must round-trip verbatim")

	// Re-marshal must be byte-identical.
	again, err := parsed.Marshal()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(raw, again),
		"round-trip marshal must be stable even with opaque object ACEs")
}

// TestSecurityDescriptor_ObjectACE_ProtectionHelpers verifies the protection
// helpers treat opaque object-type ACEs as uninteresting. In particular:
//   - HasDenyDeleteEveryoneACE is false when the DACL only contains object ACEs.
//   - AddDenyDeleteEveryoneACE prepends the deny ACE leaving object ACEs intact.
//   - RemoveDenyDeleteEveryoneACE removes only the deny ACE, keeping object ACEs.
func TestSecurityDescriptor_ObjectACE_ProtectionHelpers(t *testing.T) {
	objectGUID := [16]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	objSID := SID{
		RevisionLevel:  1,
		Authority:      5,
		SubAuthorities: []uint32{11}, // Authenticated Users
	}
	objectBody := buildObjectACEBody(t, 0x00020094, objectGUID, objSID)

	sd := &SecurityDescriptor{
		Revision: 1,
		Control:  SESelfRelative | SEDACLPresent,
		DACL: &ACL{
			AclRevision: 4,
			ACEs: []ACE{
				{
					AceType:  accessAllowedObjectACEType,
					AceFlags: ContainerInheritACE,
					RawBody:  append([]byte(nil), objectBody...),
				},
			},
		},
	}

	// Sanity: round-trip, then assert helpers from the parsed form.
	raw, err := sd.Marshal()
	require.NoError(t, err)
	parsed, err := UnmarshalSecurityDescriptor(raw)
	require.NoError(t, err)

	assert.False(t, parsed.HasDenyDeleteEveryoneACE(),
		"object-only DACL has no deny-delete ACE")

	// Add prepends without touching the object ACE.
	parsed.AddDenyDeleteEveryoneACE()
	require.Len(t, parsed.DACL.ACEs, 2)
	assert.Equal(t, AccessDeniedACEType, parsed.DACL.ACEs[0].AceType)
	assert.Equal(t, everyoneSIDValue.String(), parsed.DACL.ACEs[0].SID.String())
	assert.Equal(t, accessAllowedObjectACEType, parsed.DACL.ACEs[1].AceType)
	require.NotNil(t, parsed.DACL.ACEs[1].RawBody)
	assert.True(t, bytes.Equal(objectBody, parsed.DACL.ACEs[1].RawBody),
		"object ACE body must be untouched after Add")
	assert.True(t, parsed.HasDenyDeleteEveryoneACE())

	// Round-trip after adding the deny ACE must still be stable.
	rawAfterAdd, err := parsed.Marshal()
	require.NoError(t, err)
	reparsed, err := UnmarshalSecurityDescriptor(rawAfterAdd)
	require.NoError(t, err)
	assert.True(t, reparsed.HasDenyDeleteEveryoneACE())
	require.Len(t, reparsed.DACL.ACEs, 2)
	assert.Equal(t, accessAllowedObjectACEType, reparsed.DACL.ACEs[1].AceType)
	assert.True(t, bytes.Equal(objectBody, reparsed.DACL.ACEs[1].RawBody))

	// Remove drops only the deny ACE and leaves the object ACE intact.
	removed := reparsed.RemoveDenyDeleteEveryoneACE()
	assert.True(t, removed)
	require.Len(t, reparsed.DACL.ACEs, 1)
	assert.Equal(t, accessAllowedObjectACEType, reparsed.DACL.ACEs[0].AceType)
	require.NotNil(t, reparsed.DACL.ACEs[0].RawBody)
	assert.True(t, bytes.Equal(objectBody, reparsed.DACL.ACEs[0].RawBody),
		"object ACE body must survive Remove")
	assert.False(t, reparsed.HasDenyDeleteEveryoneACE())
}

// TestSecurityDescriptor_RandomDACL_EmptyAces verifies that an otherwise
// garbage DACL with AceCount=0 parses successfully as an empty ACL: the
// parser must only care about the declared ACE count, not the trailing
// bytes inside the ACL region.
func TestSecurityDescriptor_RandomDACL_EmptyAces(t *testing.T) {
	// 512 random bytes, appended after a valid 20-byte SD header pointing at
	// an ACL whose AceCount is 0 but whose size spans the whole trailer.
	const aclPayload = 512
	aclSize := 8 + aclPayload

	sd := make([]byte, 20+aclSize)
	sd[0] = 0x01 // Revision
	binary.LittleEndian.PutUint16(sd[2:4], SESelfRelative|SEDACLPresent)
	// Owner/Group/SACL offsets stay zero.
	binary.LittleEndian.PutUint32(sd[16:20], 20) // DACL at offset 20

	// ACL header: rev=4, size=aclSize, AceCount=0.
	sd[20] = 0x04
	binary.LittleEndian.PutUint16(sd[22:24], uint16(aclSize))
	binary.LittleEndian.PutUint16(sd[24:26], 0) // AceCount=0

	// Fill the remainder with random garbage; an empty-ACE parser must not
	// attempt to read into it.
	_, err := rand.Read(sd[28:])
	require.NoError(t, err)

	parsed, err := UnmarshalSecurityDescriptor(sd)
	require.NoError(t, err)
	require.NotNil(t, parsed.DACL)
	assert.Empty(t, parsed.DACL.ACEs)
}

// TestUnmarshalACL_CorruptAceSize_NoPanic ensures the parser returns a clear
// error rather than panicking when an ACE declares a size that runs past the
// enclosing ACL boundary.
func TestUnmarshalACL_CorruptAceSize_NoPanic(t *testing.T) {
	// Build a self-relative SD whose DACL claims AceCount=1 but whose single
	// ACE declares an AceSize larger than the ACL body.
	// ACL body carries only a 4-byte truncated ACE header.
	const aclSize = 8 + 4
	sd := make([]byte, 20+aclSize)
	sd[0] = 0x01 // Revision
	binary.LittleEndian.PutUint16(sd[2:4], SESelfRelative|SEDACLPresent)
	binary.LittleEndian.PutUint32(sd[16:20], 20)

	// ACL header
	sd[20] = 0x02
	binary.LittleEndian.PutUint16(sd[22:24], uint16(aclSize))
	binary.LittleEndian.PutUint16(sd[24:26], 1) // AceCount=1

	// Truncated ACE header: type=0x00, flags=0, size=0xFFFF (absurd)
	sd[28] = AccessAllowedACEType
	sd[29] = 0x00
	binary.LittleEndian.PutUint16(sd[30:32], 0xFFFF)

	assert.NotPanics(t, func() {
		_, err := UnmarshalSecurityDescriptor(sd)
		assert.Error(t, err)
	})
}

// TestUnmarshalACL_TinyAceSize ensures an AceSize below the 4-byte ACE header
// is rejected cleanly.
func TestUnmarshalACL_TinyAceSize(t *testing.T) {
	const aclSize = 8 + 4
	sd := make([]byte, 20+aclSize)
	sd[0] = 0x01
	binary.LittleEndian.PutUint16(sd[2:4], SESelfRelative|SEDACLPresent)
	binary.LittleEndian.PutUint32(sd[16:20], 20)

	sd[20] = 0x02
	binary.LittleEndian.PutUint16(sd[22:24], uint16(aclSize))
	binary.LittleEndian.PutUint16(sd[24:26], 1)

	// ACE with size=3 (less than the 4-byte header)
	sd[28] = AccessAllowedACEType
	sd[29] = 0x00
	binary.LittleEndian.PutUint16(sd[30:32], 3)

	_, err := UnmarshalSecurityDescriptor(sd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "impossibly small")
}
