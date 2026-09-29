package directory

import "bytes"

// ParseSimpleRDNBytes recognizes exactly one RDN in SimpleDNDepthBytes' strict
// ASCII subset. The returned attribute and assertion borrow value, which is
// neither modified nor retained. A false result requires the full DN parser;
// it does not imply that the RDN is invalid.
func ParseSimpleRDNBytes(value []byte) (attribute, assertion []byte, simple bool) {
	attribute, assertion, found := bytes.Cut(value, []byte("="))
	if !found || !validDNAttributeTypeBytes(attribute) || len(assertion) == 0 {
		return nil, nil, false
	}
	// Validating both fields also rejects commas, so no separate RDN split is
	// needed. Keep the value alphabet identical to simpleDNDepthBytes.
	for _, c := range assertion {
		if !asciiDNAttributeLetter(c) && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return nil, nil, false
		}
	}
	return attribute, assertion, true
}
