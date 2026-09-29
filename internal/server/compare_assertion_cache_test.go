package server

import (
	"bytes"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestCompareAssertionCacheKeepsValidationLive(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("CN=Alice,DC=example,DC=com")
	request := ldapwire.CompareRequest{Attribute: "member", Assertion: raw}
	for range 2 {
		got, failure := validateCompareRequest(registry, request)
		want, err := registry.NormalizeEqualityAssertion(request.Attribute, raw)
		if failure != nil || err != nil || !bytes.Equal(got.Assertion, want) {
			t.Fatalf("validated assertion=%q, failure=%v, reference=%q/%v", got.Assertion, failure, want, err)
		}
		clear(got.Assertion)
		if !bytes.Equal(raw, []byte("CN=Alice,DC=example,DC=com")) {
			t.Fatal("normalized assertion aliases request input")
		}
	}
	attribute, _ := registry.AttributeType("member")
	attribute.SyntaxLength = len(raw) - 1
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	if _, failure := validateCompareRequest(registry, request); failure == nil || failure.Code != ldapwire.ResultInvalidAttributeSyntax {
		t.Fatalf("warm normalization bypassed updated syntax length: %v", failure)
	}
	attribute.SyntaxLength = 0
	attribute.Equality = ""
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	if _, failure := validateCompareRequest(registry, request); failure == nil || failure.Code != ldapwire.ResultInappropriateMatching {
		t.Fatalf("warm normalization bypassed equality-rule removal: %v", failure)
	}
}
