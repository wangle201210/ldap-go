package schema

import (
	"bytes"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// WithDNAttributes returns an evaluation-only entry containing the AVAs from
// every RDN in its DN. RFC 4511 extensible filters use this view when their
// dnAttributes flag is true; stored entry content is never changed.
func (registry *Registry) WithDNAttributes(
	entry directory.Entry,
) (directory.Entry, error) {
	dn, err := registry.NormalizeDN(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	result := entry.Clone()
	for dn.Depth() > 0 {
		for _, value := range dn.RDNValues() {
			result.Attributes = append(result.Attributes, directory.Attribute{
				Description: value.Type,
				Values:      [][]byte{bytes.Clone(value.Value)},
			})
		}
		parent, ok := dn.Parent()
		if !ok {
			break
		}
		dn = parent
	}
	return result, nil
}
