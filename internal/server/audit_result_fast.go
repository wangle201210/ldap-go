package server

// Recognize only the short LDAPResult form emitted without diagnostic text,
// matched DN, referrals, controls or extension fields. All other BER shapes
// retain the general decoder, including its permissive/error behavior.
func simpleAuditResultCode(encoded []byte) (int, bool) {
	if len(encoded) < 14 || len(encoded) > 21 || encoded[0] != 0x30 ||
		int(encoded[1]) != len(encoded)-2 || encoded[2] != 0x02 {
		return 0, false
	}
	idLength := int(encoded[3])
	if idLength < 1 || idLength > 8 || len(encoded) != idLength+13 {
		return 0, false
	}
	result := encoded[4+idLength:]
	switch result[0] {
	case 0x61, 0x65, 0x67, 0x69, 0x6b, 0x6d, 0x6f, 0x78:
	default:
		return 0, false
	}
	if result[1] != 7 || result[2] != 0x0a || result[3] != 1 || result[4] >= 0x80 ||
		result[5] != 0x04 || result[6] != 0 || result[7] != 0x04 || result[8] != 0 {
		return 0, false
	}
	return int(result[4]), true
}
