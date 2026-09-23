package directory

import "strings"

// SimpleLegacyDisplayRelation compares the displayed DN forms using legacy
// case folding, as if both String results had been parsed without a schema.
// Only simple single-AVA ASCII forms qualify; callers retain their original
// parser when ok is false. No identity/matching-rule semantics are substituted.
func (dn DN) SimpleLegacyDisplayRelation(other DN) (equal, ancestor, ok bool) {
	if dn.parsed == nil || other.parsed == nil ||
		len(dn.displayRDNs) != len(dn.parsed.RDNs) || len(other.displayRDNs) != len(other.parsed.RDNs) {
		return false, false, false
	}
	for _, components := range [][]string{dn.displayRDNs, other.displayRDNs} {
		for _, rdn := range components {
			if depth, simple := simpleDNDepth(rdn); !simple || depth != 1 {
				return false, false, false
			}
		}
	}
	if len(dn.displayRDNs) > len(other.displayRDNs) {
		return false, false, true
	}
	offset := len(other.displayRDNs) - len(dn.displayRDNs)
	for i, rdn := range dn.displayRDNs {
		if !strings.EqualFold(rdn, other.displayRDNs[offset+i]) {
			return false, false, true
		}
	}
	return offset == 0, offset > 0, true
}
