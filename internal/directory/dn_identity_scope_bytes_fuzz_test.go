package directory

import (
	"encoding/base64"
	"strings"
	"testing"
)

func FuzzValidateDNIdentityInScopeBytes(f *testing.F) {
	for _, value := range []string{
		"", "cn=", "CN-1=a_b.c-12", "2.5.4.3=Alice,dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
		"exactAlias=Case+commonName=ALICE,dc=example,dc=com",
		`cn=Smith\, Alice,dc=example,dc=com`,
		"uid=" + strings.Repeat("a", 1010),
		"uid=" + strings.Repeat("a", 1011),
		"uid=" + strings.Repeat("a", 1012),
	} {
		dn, err := ParseDNWithNormalizer(value, aliasIdentityNormalizer{})
		if err != nil {
			f.Fatal(err)
		}
		for _, key := range []string{dn.Key(), dn.LegacyKey(), dn.Key() + "\r\n", "dn:v2:!"} {
			f.Add([]byte(value), []byte(key), "dc=example,dc=com", int8(ScopeWholeSubtree))
		}
	}
	for _, payload := range identityPayloadCorpus()[:40] {
		f.Add([]byte("cn=a"), []byte(schemaAwareDNKeyPrefix+base64.RawURLEncoding.EncodeToString(payload)), "cn=a", int8(ScopeBase))
	}
	for _, payload := range malformedSimpleDNIdentityOuterPayloads(f) {
		key := []byte(schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(payload))
		for _, scope := range []Scope{ScopeWholeSubtree, ScopeBase, -1} {
			f.Add([]byte("cn=a,dc=example,dc=com"), key, "dc=other,dc=com", int8(scope))
		}
	}
	f.Add([]byte("cn"), []byte("dn:v2:!"), "invalid", int8(-1))
	f.Fuzz(func(t *testing.T, value, key []byte, baseValue string, scope int8) {
		depth, simple := simpleDNDepthBytes(value)
		if wantDepth, wantSimple := simpleDNDepth(string(value)); depth != wantDepth || simple != wantSimple {
			t.Fatalf("recognize %q: bytes %d/%t, string %d/%t", value, depth, simple, wantDepth, wantSimple)
		}
		base, err := ParseDNWithNormalizer(baseValue, aliasIdentityNormalizer{})
		if err != nil {
			base, err = ParseDNWithNormalizer("", aliasIdentityNormalizer{})
			if err != nil {
				t.Fatal(err)
			}
		}
		bases := []DN{base, {}}
		if legacy, err := ParseDN(baseValue); err == nil {
			bases = append(bases, legacy)
		}
		payloadKey := []byte(schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(key))
		avaKey := []byte(encodeDNIdentity([][]byte{encodeDNIdentityParts(key)}))
		validKey := []byte(encodeDNIdentity([][]byte{encodeDNIdentityParts(encodeDNIdentityParts([]byte("cn"), key))}))
		for _, scopeBase := range bases {
			checkDNIdentityScopeBytes(t, value, key, scopeBase, Scope(scope))
			checkDNIdentityScopeBytes(t, value, payloadKey, scopeBase, Scope(scope))
			checkDNIdentityScopeBytes(t, []byte("cn=a"), avaKey, scopeBase, Scope(scope))
			checkDNIdentityScopeBytes(t, []byte("cn=a"), validKey, scopeBase, Scope(scope))
		}
	})
}
