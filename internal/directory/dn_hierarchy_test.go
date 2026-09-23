package directory

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDNHierarchyPathAncestry(t *testing.T) {
	var dns []DN
	for _, raw := range []string{
		"", "dc=com", "dc=example,dc=com", "dc=examplex,dc=com",
		"uid=parent,dc=example,dc=com",
		"uid=orphan,uid=missing,uid=parent,dc=example,dc=com",
		`uid=Comma\,Value+cn=Root,dc=example,dc=com`,
		`CN=ROOT+UID=comma\,value,DC=EXAMPLE,DC=COM`,
		"uid=" + strings.Repeat("x", 150) + ",dc=example,dc=com",
		`uid=a\00b,dc=example,dc=com`,
	} {
		dn, err := ParseDNWithNormalizer(raw, scopeIdentityNormalizer{})
		if err != nil {
			t.Fatal(err)
		}
		dns = append(dns, dn)
	}
	for _, base := range dns {
		prefix, err := DNHierarchyPath(base.Key())
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range dns {
			path, err := DNHierarchyPath(candidate.Key())
			if err != nil {
				t.Fatal(err)
			}
			if got, want := bytes.HasPrefix(path, prefix), base.Equal(candidate) || base.AncestorOf(candidate); got != want {
				t.Fatalf("%q -> %q: prefix=%v, ancestry=%v", base, candidate, got, want)
			}
		}
	}
}

func TestDNHierarchyPathRejectsMalformedIdentity(t *testing.T) {
	ava := encodeDNIdentityParts([]byte("cn"), []byte("a"))
	valid := encodeDNIdentity([][]byte{encodeDNIdentityParts(ava)})
	encode := func(payload []byte) string {
		return schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(payload)
	}
	for _, key := range []string{
		"cn=a", "dn:v2:!", valid + "=", valid + "\n",
		encode([]byte{0x80, 0}), encode([]byte{1, 10}), encode([]byte{0, 1}),
		encodeDNIdentity([][]byte{encodeDNIdentityParts()}),
		encodeDNIdentity([][]byte{encodeDNIdentityParts(encodeDNIdentityParts(nil, []byte("a")))}),
		encodeDNIdentity([][]byte{encodeDNIdentityParts(ava, ava)}),
		encodeDNIdentity([][]byte{encodeDNIdentityParts(append([]byte{0x82, 0}, ava[1:]...))}),
	} {
		if _, err := DNHierarchyPath(key); err == nil {
			t.Fatalf("accepted invalid key %q", key)
		}
	}
	first, err := DNHierarchyPath(valid)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DNHierarchyPath(valid)
	if err != nil {
		t.Fatal(err)
	}
	clear(first)
	if bytes.Equal(first, second) {
		t.Fatal("paths share mutable storage")
	}
}
