package directory

import (
	"errors"
	"strings"
)

// ValidateDNIdentityInScope is equivalent to ValidateDNWithIdentityKey
// followed, only on success, by IdentityKeyInScope. Matching v2 cardinalities
// share one decode; legacy keys and cardinality mismatches use the original
// validation paths.
//
// Callers must handle validationErr first. scopeErr is separate so it can be
// handled later, such as after a callback's deadline check. On validation failure,
// inScope is false and scopeErr is nil.
func ValidateDNIdentityInScope(value, key string, base DN, scope Scope) (inScope bool, scopeErr error, validationErr error) {
	if !strings.HasPrefix(key, schemaAwareDNKeyPrefix) {
		if err := ValidateDNWithIdentityKey(value, key); err != nil {
			return false, nil, err
		}
		inScope, scopeErr = IdentityKeyInScope(base, key, scope)
		return inScope, scopeErr, nil
	}
	var scratch [1024]byte
	rdns, err := validatedDNIdentityRDNs(value, key, scratch[:])
	if err != nil {
		return false, nil, err
	}
	if !base.hasSchemaAwareIdentity() {
		return false, errors.New("scope base has no schema-aware identity"), nil
	}
	return dnIdentityRDNsInScope(base, rdns, scope), nil, nil
}
