package directory

import (
	"reflect"
	"testing"
)

func referenceValidateDNIdentityInScope(value, key string, base DN, scope Scope) (bool, error, error) {
	if err := ValidateDNWithIdentityKey(value, key); err != nil {
		return false, nil, err
	}
	inScope, err := IdentityKeyInScope(base, key, scope)
	return inScope, err, nil
}

func checkDNIdentityScope(t *testing.T, value, key string, base DN, scope Scope) {
	t.Helper()
	got, scopeErr, validationErr := ValidateDNIdentityInScope(value, key, base, scope)
	want, wantScopeErr, wantValidationErr := referenceValidateDNIdentityInScope(value, key, base, scope)
	if got != want || !reflect.DeepEqual(scopeErr, wantScopeErr) || !reflect.DeepEqual(validationErr, wantValidationErr) {
		t.Fatalf("combined %q / %q, base %q, scope %d: got (%t, %v, %v); two calls (%t, %v, %v)",
			value, key, base.Key(), scope, got, scopeErr, validationErr, want, wantScopeErr, wantValidationErr)
	}
	checkDNIdentityScopeBytes(t, []byte(value), []byte(key), base, scope)
	// Keep an independent oracle because both public operations share helpers
	// with the combined implementation. Compare wrapped errors and their types.
	_, frozenValidationErr := referenceParseDNWithIdentityKey(value, key)
	var frozenScope bool
	var frozenScopeErr error
	if frozenValidationErr == nil {
		frozenScope, frozenScopeErr = referenceIdentityKeyInScope(base, key, scope)
	}
	if got != frozenScope || !reflect.DeepEqual(scopeErr, frozenScopeErr) || !reflect.DeepEqual(validationErr, frozenValidationErr) {
		t.Fatalf("combined %q / %q, base %q, scope %d: got (%t, %v, %v); frozen (%t, %v, %v)",
			value, key, base.Key(), scope, got, scopeErr, validationErr, frozenScope, frozenScopeErr, frozenValidationErr)
	}
}

func checkDNIdentityScopeBytes(t *testing.T, value, key []byte, base DN, scope Scope) {
	t.Helper()
	got, scopeErr, validationErr := ValidateDNIdentityInScopeBytes(value, key, base, scope)
	want, wantScopeErr, wantValidationErr := referenceValidateDNIdentityInScope(string(value), string(key), base, scope)
	if got != want || !reflect.DeepEqual(scopeErr, wantScopeErr) || !reflect.DeepEqual(validationErr, wantValidationErr) {
		t.Fatalf("bytes %q / %q, base %q, scope %d: got (%t, %v, %v); two calls (%t, %v, %v)",
			value, key, base.Key(), scope, got, scopeErr, validationErr, want, wantScopeErr, wantValidationErr)
	}
}
