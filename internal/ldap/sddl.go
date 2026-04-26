package ldap

import (
	"encoding/binary"
	"fmt"
)

// Windows SECURITY_DESCRIPTOR self-relative binary format.
// Reference: MS-DTYP section 2.4.6 (SECURITY_DESCRIPTOR) and 2.4.5 (ACL).
// All multi-byte integers are little-endian; SIDs use their own mixed encoding
// (see sid.go).

// SECURITY_DESCRIPTOR_CONTROL flag bits (MS-DTYP 2.4.6).
const (
	SEOwnerDefaulted     uint16 = 0x0001
	SEGroupDefaulted     uint16 = 0x0002
	SEDACLPresent        uint16 = 0x0004
	SEDACLDefaulted      uint16 = 0x0008
	SESACLPresent        uint16 = 0x0010
	SESACLDefaulted      uint16 = 0x0020
	SEDACLAutoInheritReq uint16 = 0x0100
	SESACLAutoInheritReq uint16 = 0x0200
	SEDACLAutoInherited  uint16 = 0x0400
	SESACLAutoInherited  uint16 = 0x0800
	SEDACLProtected      uint16 = 0x1000
	SESACLProtected      uint16 = 0x2000
	SERMControlValid     uint16 = 0x4000
	SESelfRelative       uint16 = 0x8000
)

// ACE types (MS-DTYP 2.4.4.1).
const (
	AccessAllowedACEType uint8 = 0x00
	AccessDeniedACEType  uint8 = 0x01
	SystemAuditACEType   uint8 = 0x02
)

// ACE flags (MS-DTYP 2.4.4.1).
const (
	ObjectInheritACE        uint8 = 0x01
	ContainerInheritACE     uint8 = 0x02
	NoPropagateInheritACE   uint8 = 0x04
	InheritOnlyACE          uint8 = 0x08
	InheritedACE            uint8 = 0x10
	SuccessfulAccessACEFlag uint8 = 0x40
	FailedAccessACEFlag     uint8 = 0x80
)

// Access mask bits relevant to OU delete protection.
// Standard rights: MS-DTYP 2.4.3; AD-specific in MS-ADTS.
const (
	AccessMaskDelete      uint32 = 0x00010000
	AccessMaskDeleteChild uint32 = 0x00000040
)

// LDAP_SERVER_SD_FLAGS_OID control value bits. Only DACL is requested/written
// when toggling OU protection so owner/group/SACL are left untouched.
const (
	SDFlagsOwnerSecurityInformation uint32 = 0x00000001
	SDFlagsGroupSecurityInformation uint32 = 0x00000002
	SDFlagsDACLSecurityInformation  uint32 = 0x00000004
	SDFlagsSACLSecurityInformation  uint32 = 0x00000008
)

// SecurityDescriptor is the self-relative form of a Windows security descriptor.
type SecurityDescriptor struct {
	Revision uint8
	Sbz1     uint8
	Control  uint16
	Owner    *SID
	Group    *SID
	SACL     *ACL
	DACL     *ACL
}

// ACL holds a discretionary or system access control list.
type ACL struct {
	AclRevision uint8
	Sbz1        uint8
	Sbz2        uint16
	ACEs        []ACE
}

// ACE is a single access control entry.
//
// For the simple ACE types this package actively reasons about
// (AccessAllowedACEType, AccessDeniedACEType, SystemAuditACEType), the parsed
// AccessMask and SID fields are populated and RawBody is nil.
//
// For every other ACE type (object-type ACEs 0x05/0x06/0x07, mandatory label
// ACEs 0x11, callback/resource ACEs, future types AD may introduce, etc.) the
// body is preserved verbatim in RawBody so that Marshal reproduces the exact
// bytes observed during Unmarshal. The high-level helpers
// (HasDenyDeleteEveryoneACE / AddDenyDeleteEveryoneACE /
// RemoveDenyDeleteEveryoneACE) ignore these opaque ACEs because the
// protect-from-deletion ACE we care about is always a simple deny (type 0x01).
type ACE struct {
	AceType  uint8
	AceFlags uint8
	// AccessMask is only meaningful when RawBody is nil.
	AccessMask uint32
	// SID is only meaningful when RawBody is nil.
	SID SID
	// RawBody, when non-nil, holds the AceSize-4 bytes that follow the 4-byte
	// ACE header (type, flags, size). It is used for ACE types we don't parse
	// semantically so that round-tripping preserves them bit-identically.
	RawBody []byte
}

// UnmarshalSecurityDescriptor decodes a self-relative binary security
// descriptor.
func UnmarshalSecurityDescriptor(b []byte) (*SecurityDescriptor, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("security descriptor too short: %d bytes (minimum 20)", len(b))
	}

	sd := &SecurityDescriptor{
		Revision: b[0],
		Sbz1:     b[1],
		Control:  binary.LittleEndian.Uint16(b[2:4]),
	}

	if sd.Control&SESelfRelative == 0 {
		return nil, fmt.Errorf("absolute security descriptors are not supported")
	}

	ownerOff := binary.LittleEndian.Uint32(b[4:8])
	groupOff := binary.LittleEndian.Uint32(b[8:12])
	saclOff := binary.LittleEndian.Uint32(b[12:16])
	daclOff := binary.LittleEndian.Uint32(b[16:20])

	if ownerOff != 0 {
		sid, err := decodeSIDAt(b, ownerOff)
		if err != nil {
			return nil, fmt.Errorf("owner SID: %w", err)
		}
		sd.Owner = &sid
	}
	if groupOff != 0 {
		sid, err := decodeSIDAt(b, groupOff)
		if err != nil {
			return nil, fmt.Errorf("group SID: %w", err)
		}
		sd.Group = &sid
	}
	if saclOff != 0 && sd.Control&SESACLPresent != 0 {
		acl, err := unmarshalACL(b, saclOff)
		if err != nil {
			return nil, fmt.Errorf("SACL: %w", err)
		}
		sd.SACL = acl
	}
	if daclOff != 0 && sd.Control&SEDACLPresent != 0 {
		acl, err := unmarshalACL(b, daclOff)
		if err != nil {
			return nil, fmt.Errorf("DACL: %w", err)
		}
		sd.DACL = acl
	}

	return sd, nil
}

// decodeSIDAt decodes a SID embedded at offset in the buffer.
// Bounds are checked against the SubAuthorityCount byte.
func decodeSIDAt(buf []byte, offset uint32) (SID, error) {
	if int(offset)+8 > len(buf) {
		return SID{}, fmt.Errorf("SID offset %d exceeds buffer length %d", offset, len(buf))
	}
	count := int(buf[offset+1])
	end := int(offset) + 8 + 4*count
	if end > len(buf) {
		return SID{}, fmt.Errorf("SID at offset %d truncated (need %d bytes, have %d)", offset, end, len(buf))
	}
	return DecodeSID(buf[offset:end])
}

// unmarshalACL decodes an ACL and all its ACEs at offset.
func unmarshalACL(buf []byte, offset uint32) (*ACL, error) {
	if int(offset)+8 > len(buf) {
		return nil, fmt.Errorf("ACL header offset %d exceeds buffer length %d", offset, len(buf))
	}
	hdr := buf[offset : offset+8]
	acl := &ACL{
		AclRevision: hdr[0],
		Sbz1:        hdr[1],
		Sbz2:        binary.LittleEndian.Uint16(hdr[6:8]),
	}
	aclSize := binary.LittleEndian.Uint16(hdr[2:4])
	aceCount := binary.LittleEndian.Uint16(hdr[4:6])

	if int(offset)+int(aclSize) > len(buf) {
		return nil, fmt.Errorf("ACL size %d at offset %d exceeds buffer length %d", aclSize, offset, len(buf))
	}

	cursor := offset + 8
	end := offset + uint32(aclSize)
	acl.ACEs = make([]ACE, 0, aceCount)
	for i := uint16(0); i < aceCount; i++ {
		if cursor+4 > end {
			return nil, fmt.Errorf("ACE %d header runs past ACL boundary", i)
		}
		ace := ACE{
			AceType:  buf[cursor],
			AceFlags: buf[cursor+1],
		}
		aceSize := binary.LittleEndian.Uint16(buf[cursor+2 : cursor+4])
		if aceSize < 4 {
			return nil, fmt.Errorf("ACE %d size %d is impossibly small", i, aceSize)
		}
		if cursor+uint32(aceSize) > end {
			return nil, fmt.Errorf("ACE %d size %d runs past ACL boundary", i, aceSize)
		}

		bodyStart := cursor + 4
		bodyEnd := cursor + uint32(aceSize)

		switch ace.AceType {
		case AccessAllowedACEType, AccessDeniedACEType, SystemAuditACEType:
			// Simple ACE: 4-byte access mask followed by a SID.
			if aceSize < 12 {
				return nil, fmt.Errorf("ACE %d (type %d) too small for access mask + SID", i, ace.AceType)
			}
			ace.AccessMask = binary.LittleEndian.Uint32(buf[bodyStart : bodyStart+4])
			sid, err := DecodeSID(buf[bodyStart+4 : bodyEnd])
			if err != nil {
				return nil, fmt.Errorf("ACE %d SID: %w", i, err)
			}
			ace.SID = sid
		default:
			// Every other ACE type (object ACEs, mandatory label ACEs,
			// callback/resource ACEs, future additions) is preserved
			// verbatim so Marshal round-trips the original bytes. The
			// protection helpers only care about the simple deny-delete
			// ACE above, so opaque preservation is sufficient.
			body := make([]byte, int(aceSize)-4)
			copy(body, buf[bodyStart:bodyEnd])
			ace.RawBody = body
		}

		acl.ACEs = append(acl.ACEs, ace)
		cursor += uint32(aceSize)
	}

	return acl, nil
}

// Marshal encodes the security descriptor back to its self-relative binary
// form. Any non-self-relative Control bits in sd.Control are preserved except
// SE_SELF_RELATIVE, which is always set on output.
func (sd *SecurityDescriptor) Marshal() ([]byte, error) {
	rev := sd.Revision
	if rev == 0 {
		rev = 1
	}

	// Compute body layout: header (20 bytes) + SACL + DACL + Owner + Group.
	// Windows emits in this order when present; we match to stay canonical.
	header := make([]byte, 20)
	header[0] = rev
	header[1] = sd.Sbz1

	control := sd.Control | SESelfRelative
	if sd.DACL != nil {
		control |= SEDACLPresent
	}
	if sd.SACL != nil {
		control |= SESACLPresent
	}

	offset := uint32(20)
	var saclBytes, daclBytes, ownerBytes, groupBytes []byte
	var saclOff, daclOff, ownerOff, groupOff uint32

	if sd.SACL != nil {
		b, err := marshalACL(sd.SACL)
		if err != nil {
			return nil, fmt.Errorf("SACL: %w", err)
		}
		saclBytes = b
		saclOff = offset
		offset += uint32(len(b))
	}
	if sd.DACL != nil {
		b, err := marshalACL(sd.DACL)
		if err != nil {
			return nil, fmt.Errorf("DACL: %w", err)
		}
		daclBytes = b
		daclOff = offset
		offset += uint32(len(b))
	}
	if sd.Owner != nil {
		b, err := sd.Owner.Bytes()
		if err != nil {
			return nil, fmt.Errorf("owner SID: %w", err)
		}
		ownerBytes = b
		ownerOff = offset
		offset += uint32(len(b))
	}
	if sd.Group != nil {
		b, err := sd.Group.Bytes()
		if err != nil {
			return nil, fmt.Errorf("group SID: %w", err)
		}
		groupBytes = b
		groupOff = offset
		offset += uint32(len(b))
	}

	binary.LittleEndian.PutUint16(header[2:4], control)
	binary.LittleEndian.PutUint32(header[4:8], ownerOff)
	binary.LittleEndian.PutUint32(header[8:12], groupOff)
	binary.LittleEndian.PutUint32(header[12:16], saclOff)
	binary.LittleEndian.PutUint32(header[16:20], daclOff)

	out := make([]byte, 0, offset)
	out = append(out, header...)
	out = append(out, saclBytes...)
	out = append(out, daclBytes...)
	out = append(out, ownerBytes...)
	out = append(out, groupBytes...)
	return out, nil
}

// marshalACL encodes an ACL with its ACEs.
func marshalACL(acl *ACL) ([]byte, error) {
	rev := acl.AclRevision
	if rev == 0 {
		rev = 2 // ACL_REVISION
	}

	aceBlobs := make([][]byte, 0, len(acl.ACEs))
	totalACEBytes := 0
	for i, ace := range acl.ACEs {
		b, err := marshalACE(&ace)
		if err != nil {
			return nil, fmt.Errorf("ACE %d: %w", i, err)
		}
		aceBlobs = append(aceBlobs, b)
		totalACEBytes += len(b)
	}

	size := 8 + totalACEBytes
	if size > 0xFFFF {
		return nil, fmt.Errorf("ACL size %d exceeds uint16 max", size)
	}

	out := make([]byte, 0, size)
	hdr := make([]byte, 8)
	hdr[0] = rev
	hdr[1] = acl.Sbz1
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(size))
	binary.LittleEndian.PutUint16(hdr[4:6], uint16(len(acl.ACEs)))
	binary.LittleEndian.PutUint16(hdr[6:8], acl.Sbz2)
	out = append(out, hdr...)
	for _, b := range aceBlobs {
		out = append(out, b...)
	}
	return out, nil
}

// marshalACE encodes a single ACE. Simple ACEs (allow/deny/audit) are built
// from AccessMask + SID; any ACE with a non-nil RawBody is emitted as the
// 4-byte header followed by the opaque body exactly as captured by Unmarshal.
func marshalACE(ace *ACE) ([]byte, error) {
	if ace.RawBody != nil {
		size := 4 + len(ace.RawBody)
		if size > 0xFFFF {
			return nil, fmt.Errorf("ACE size %d exceeds uint16 max", size)
		}
		out := make([]byte, 4, size)
		out[0] = ace.AceType
		out[1] = ace.AceFlags
		binary.LittleEndian.PutUint16(out[2:4], uint16(size))
		out = append(out, ace.RawBody...)
		return out, nil
	}

	sidBytes, err := ace.SID.Bytes()
	if err != nil {
		return nil, fmt.Errorf("SID: %w", err)
	}
	size := 8 + len(sidBytes)
	if size > 0xFFFF {
		return nil, fmt.Errorf("ACE size %d exceeds uint16 max", size)
	}
	out := make([]byte, 8, size)
	out[0] = ace.AceType
	out[1] = ace.AceFlags
	binary.LittleEndian.PutUint16(out[2:4], uint16(size))
	binary.LittleEndian.PutUint32(out[4:8], ace.AccessMask)
	out = append(out, sidBytes...)
	return out, nil
}

// everyoneSID returns the well-known S-1-1-0 (World) SID.
func everyoneSID() SID {
	return SID{
		RevisionLevel:  1,
		Authority:      1,
		SubAuthorities: []uint32{0},
	}
}

// HasDenyDeleteEveryoneACE reports whether the DACL contains the specific deny
// ACE used by Windows "protect from accidental deletion". The match requires
// both DELETE and DELETE_CHILD in the access mask and SID == S-1-1-0.
func (sd *SecurityDescriptor) HasDenyDeleteEveryoneACE() bool {
	if sd == nil || sd.DACL == nil {
		return false
	}
	want := everyoneSID().String()
	for _, ace := range sd.DACL.ACEs {
		if ace.RawBody != nil {
			// Opaque (non-simple) ACE: not our deny-delete ACE by definition.
			continue
		}
		if ace.AceType != AccessDeniedACEType {
			continue
		}
		if ace.AccessMask&AccessMaskDelete == 0 {
			continue
		}
		if ace.AccessMask&AccessMaskDeleteChild == 0 {
			continue
		}
		if ace.SID.String() == want {
			return true
		}
	}
	return false
}

// AddDenyDeleteEveryoneACE inserts the deny-delete ACE at the front of the
// DACL so it precedes any allow ACEs (Windows canonical order). A new DACL is
// created if none exists.
func (sd *SecurityDescriptor) AddDenyDeleteEveryoneACE() {
	ace := ACE{
		AceType:    AccessDeniedACEType,
		AceFlags:   ContainerInheritACE,
		AccessMask: AccessMaskDelete | AccessMaskDeleteChild,
		SID:        everyoneSID(),
	}
	if sd.DACL == nil {
		sd.DACL = &ACL{AclRevision: 2, ACEs: []ACE{ace}}
		sd.Control |= SEDACLPresent
		return
	}
	sd.DACL.ACEs = append([]ACE{ace}, sd.DACL.ACEs...)
}

// RemoveDenyDeleteEveryoneACE drops all deny-delete-everyone ACEs from the
// DACL. Returns true if any ACE was removed.
func (sd *SecurityDescriptor) RemoveDenyDeleteEveryoneACE() bool {
	if sd == nil || sd.DACL == nil {
		return false
	}
	want := everyoneSID().String()
	filtered := sd.DACL.ACEs[:0]
	removed := false
	for _, ace := range sd.DACL.ACEs {
		if ace.RawBody == nil &&
			ace.AceType == AccessDeniedACEType &&
			ace.AccessMask&AccessMaskDelete != 0 &&
			ace.AccessMask&AccessMaskDeleteChild != 0 &&
			ace.SID.String() == want {
			removed = true
			continue
		}
		filtered = append(filtered, ace)
	}
	sd.DACL.ACEs = filtered
	return removed
}
