package directory

import (
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ParentKey returns the same key as Parent without building its display and
// attribute slices. Empty DNs, including the zero value, have no parent.
func (dn DN) ParentKey() (string, bool) {
	if dn.parsed == nil || len(dn.parsed.RDNs) == 0 {
		return "", false
	}
	if dn.hasSchemaAwareIdentity() {
		return encodeDNIdentity(dn.identityRDNs[1:]), true
	}
	parent := ldap.DN{RDNs: dn.parsed.RDNs[1:]}
	return strings.ToLower(parent.String()), true
}
