package directory

import (
	"bytes"
	"testing"
)

func checkSimpleRDNBytes(t testing.TB, value []byte) {
	t.Helper()
	before := bytes.Clone(value)
	attribute, assertion, simple := ParseSimpleRDNBytes(value)
	depth, wantSimple := simpleDNDepth(string(value))
	byteDepth, byteSimple := SimpleDNDepthBytes(value)
	if simple != (wantSimple && depth == 1) || simple != (byteSimple && byteDepth == 1) {
		t.Fatalf("%q: simple=%v, string depth/simple=(%d,%v), bytes=(%d,%v)",
			value, simple, depth, wantSimple, byteDepth, byteSimple)
	}
	if !bytes.Equal(value, before) {
		t.Fatal("RDN parser modified input")
	}
	if !simple {
		if attribute != nil || assertion != nil {
			t.Fatal("failed recognition returned partial fields")
		}
		return
	}
	// Use the authoritative parser for the accepted fields, independently of
	// the simple grammar recognizers that constrain fast-path eligibility.
	dn, err := ParseDN(string(value))
	if err != nil {
		t.Fatalf("accepted %q rejected by parser: %v", value, err)
	}
	if len(dn.parsed.RDNs) != 1 || len(dn.parsed.RDNs[0].Attributes) != 1 {
		t.Fatalf("accepted %q is not a single-AVA RDN", value)
	}
	ava := dn.parsed.RDNs[0].Attributes[0]
	if string(attribute) != ava.Type || string(assertion) != ava.Value {
		t.Fatalf("%q: fields=(%q,%q), parser=(%q,%q)", value, attribute, assertion, ava.Type, ava.Value)
	}
}

func TestParseSimpleRDNBytesOracle(t *testing.T) {
	checkSimpleRDNBytes(t, nil)
	for _, value := range []string{
		"", "=a", "cn", "cn=", "cn=a", "CN-1=a_b.c-12", "2.5.4.3=ALICE", "0=a", "0.0=a",
		"cn=a,", "cn=a,dc=x", "cn=a,,dc=x", "cn,uid=a", "cn=a+uid=b", "cn=a=b",
		`cn=a\,b`, `cn=\61lice`, `cn=\`, "cn= Alice", "cn=a ", "cn=#6162", "cn=a;b",
		"cn=\x00", "cn=\xff", "cn=\u00e9", "cn;lang-en=a", "_cn=a", "-cn=a", "cn_1=a",
		"01.2=a", "1.02.3=a", "1..2=a", "1.=a", ".1=a",
	} {
		checkSimpleRDNBytes(t, []byte(value))
	}
	for _, original := range []string{"uid=Alice-9_x.y", "2.5.4.3=ALICE", "CN-1=a"} {
		value := []byte(original)
		for position := range value {
			for replacement := range 256 {
				value[position] = byte(replacement)
				checkSimpleRDNBytes(t, value)
			}
			value[position] = original[position]
			checkSimpleRDNBytes(t, value[:position])
		}
		for suffix := range 256 {
			checkSimpleRDNBytes(t, append(bytes.Clone(value), byte(suffix)))
		}
	}
}

func TestParseSimpleRDNBytesBorrowsFields(t *testing.T) {
	backing := []byte("prefix|uid=Alice|suffix")
	before := bytes.Clone(backing)
	value := backing[7:16]
	attribute, assertion, simple := ParseSimpleRDNBytes(value)
	if !simple || string(attribute) != "uid" || string(assertion) != "Alice" {
		t.Fatalf("parse=(%q,%q,%v)", attribute, assertion, simple)
	}
	if !bytes.Equal(backing, before) || &attribute[0] != &value[0] || &assertion[0] != &value[4] {
		t.Fatal("RDN parser must borrow fields without modifying backing storage")
	}
}

func FuzzParseSimpleRDNBytes(f *testing.F) {
	for _, value := range []string{"uid=Alice-9_x.y", "2.5.4.3=ALICE", "1.02.3=a", "cn=", "cn=a,dc=x", "cn=a+uid=b", `cn=a\,b`} {
		f.Add([]byte(value))
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > 4096 {
			t.Skip()
		}
		checkSimpleRDNBytes(t, value)
	})
}
