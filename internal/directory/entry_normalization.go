package directory

// ReplaceRawNormalizedValues records OpenLDAP-generated values whose a_nvals
// shares a_vals. This storage hint is not an LDAP attribute or equality input.
func (e *Entry) ReplaceRawNormalizedValues(description string, values [][]byte) {
	e.ReplaceValues(description, values)
	if index := e.attributeIndex(description); index >= 0 {
		e.Attributes[index].RawNormalized = true
	}
}
