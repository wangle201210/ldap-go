package directory

import (
	"encoding/base64"
	"testing"
)

func FuzzValidateDNIdentityInScope(f *testing.F) {
	for _, value := range []string{
		"", "cn=", "cn=a", "dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
		"exactAlias=Case+commonName=ALICE,dc=example,dc=com",
		`cn=Smith\, Alice,dc=example,dc=com`,
	} {
		dn, err := ParseDNWithNormalizer(value, aliasIdentityNormalizer{})
		if err != nil {
			f.Fatal(err)
		}
		for _, key := range []string{dn.Key(), dn.LegacyKey(), dn.Key() + "\n", "dn:v2:!"} {
			f.Add(value, key, "dc=example,dc=com", int8(ScopeWholeSubtree))
		}
	}
	for _, payload := range identityPayloadCorpus()[:40] {
		f.Add("cn=a", schemaAwareDNKeyPrefix+base64.RawURLEncoding.EncodeToString(payload), "cn=a", int8(ScopeBase))
	}
	f.Add("cn", "dn:v2:!", "invalid", int8(-1))
	f.Fuzz(func(t *testing.T, value, key, baseValue string, scope int8) {
		// Always exercise both the invalid-base guard and a schema-aware base.
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
		for _, scopeBase := range bases {
			checkDNIdentityScope(t, value, key, scopeBase, Scope(scope))
			// Preserve canonical base64 while mutating nested structures and
			// keep one fully structured path to exercise successful validation.
			payloadKey := schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte(key))
			checkDNIdentityScope(t, "cn=a", payloadKey, scopeBase, Scope(scope))
			avaKey := encodeDNIdentity([][]byte{encodeDNIdentityParts([]byte(key))})
			checkDNIdentityScope(t, "cn=a", avaKey, scopeBase, Scope(scope))
			validKey := encodeDNIdentity([][]byte{encodeDNIdentityParts(encodeDNIdentityParts([]byte("cn"), []byte(key)))})
			checkDNIdentityScope(t, "cn=a", validKey, scopeBase, Scope(scope))
		}
	})
}
