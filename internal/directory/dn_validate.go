package directory

// SimpleDNDepthBytes recognizes single-AVA DNs whose values contain only ASCII
// letters, digits, '.', '_' and '-'. False requires the full parser and does not
// mean the DN is invalid. It neither modifies nor retains input.
func SimpleDNDepthBytes(value []byte) (int, bool) {
	return simpleDNDepthBytes(value)
}

// ValidateDN has the acceptance and errors of ParseDN without constructing
// display or identity strings. Complex inputs retain the authoritative parser.
func ValidateDN(value []byte) error {
	if _, simple := simpleDNDepthBytes(value); simple {
		return nil
	}
	_, err := parseDN(string(value))
	return err
}
