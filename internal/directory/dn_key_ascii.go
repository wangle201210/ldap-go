package directory

import "strings"

// Base64's strict decoder still accepts line breaks. Single-byte searches use
// the optimized byte-search path for the overwhelmingly common valid keys.
func hasDNKeyLineBreak(encoded string) bool {
	return strings.IndexByte(encoded, '\r') >= 0 || strings.IndexByte(encoded, '\n') >= 0
}
