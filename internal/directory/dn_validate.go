package directory

// ValidateDN has the acceptance and errors of ParseDN without constructing
// display or identity strings. Complex inputs retain the authoritative parser.
func ValidateDN(value []byte) error {
	if _, simple := simpleDNDepthBytes(value); simple {
		return nil
	}
	_, err := parseDN(string(value))
	return err
}
