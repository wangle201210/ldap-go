package directory

import "bytes"

// Initialized once and only read by the strict RDN helpers below.
var simpleRDNValueByteClass = func() [256]bool {
	var allowed [256]bool
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._"
	for i := range len(alphabet) {
		allowed[alphabet[i]] = true
	}
	return allowed
}()

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
		if !simpleRDNValueByteClass[c] {
			return nil, nil, false
		}
	}
	return attribute, assertion, true
}

// MatchSimpleRDNValueBytes validates actual in ParseSimpleRDNBytes' strict value
// subset while comparing it with expected. The caller must validate the RDN name
// separately. Expected must be nonempty, in the same subset, and normalized for
// DN caseIgnore[IA5]Match (fold=true) or caseExact[IA5]Match (fold=false); no other
// matching rules are supported. Neither input is modified or retained. A false
// simple result requires full DN normalization, even after a value mismatch.
func MatchSimpleRDNValueBytes(actual, expected []byte, fold bool) (matched, simple bool) {
	if len(actual) == 0 {
		return false, false
	}
	matched = len(actual) == len(expected)
	for i, c := range actual {
		if !simpleRDNValueByteClass[c] {
			return false, false
		}
		// A mismatch skips comparison, but never validation of the remaining bytes.
		if matched {
			if fold && c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			matched = c == expected[i]
		}
	}
	return matched, true
}
