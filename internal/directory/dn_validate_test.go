package directory

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func assertDNValidationParity(t testing.TB, value []byte) {
	t.Helper()
	before := bytes.Clone(value)
	_, want := ParseDN(string(value))
	got := ValidateDN(value)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ValidateDN(%q) = %v; ParseDN = %v", value, got, want)
	}
	if !bytes.Equal(value, before) {
		t.Fatal("validation changed input")
	}
}

func TestValidateDNParity(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"", " ", "cn=", "CN=Alice", "1=one", "2.5.4.3=a_b.c-12", "01.2=x",
		"uid=alice,ou=people,dc=example,dc=com", "cn;lang-en=Alice",
		"cn=Alice+CN=Bob", "cn;lang-en=Alice+cn;lang-fr=Bob", "cn=a+uid=b",
		`cn=Smith\, Alice,dc=example`, `cn=\ leading\ `, `cn=#04024142`,
		`cn=\c3\a9\00\ff`, "cn=\xc3\xa9", "cn=\xff", "cn=a=b",
		" cn = Alice , dc = example ", "cn=a,", "cn=a,,dc=x", "cn=a;dc=x",
		"=a", ",", "cn", "cn=bad\\", "cn=bad\\zz", "cn=#nothex",
		"cn=" + strings.Repeat("a", 4096), strings.Repeat("ou=x,", 130) + "dc=example",
	} {
		assertDNValidationParity(t, []byte(raw))
	}
	const seed = "uid=alice,ou=people,dc=example,dc=com"
	for index := range len(seed) {
		for replacement := range 256 {
			value := []byte(seed)
			value[index] = byte(replacement)
			assertDNValidationParity(t, value)
		}
	}
}

func FuzzValidateDNParity(f *testing.F) {
	for _, value := range []string{"", "uid=alice,ou=people,dc=example,dc=com", "cn=a+uid=b", "CN=a+cn=b", `cn=Smith\, Alice`, "cn=#04024142", "cn=\xff", "cn=a,"} {
		f.Add([]byte(value))
	}
	f.Fuzz(func(t *testing.T, value []byte) { assertDNValidationParity(t, value) })
}

func BenchmarkValidateDN(b *testing.B) {
	for _, tc := range []struct{ name, raw string }{
		{"simple", "uid=alice,ou=people,dc=example,dc=com"},
		{"escaped", `cn=Smith\, Alice,ou=people,dc=example,dc=com`},
		{"multiAVA", "cn=Alice+uid=alice,ou=people,dc=example,dc=com"},
		{"invalid", "cn=Alice+CN=Bob,dc=example,dc=com"},
	} {
		value := []byte(tc.raw)
		_, wantErr := ParseDN(tc.raw)
		b.Run(tc.name+"/parse", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := ParseDN(string(value)); (err == nil) != (wantErr == nil) {
					b.Fatal(err)
				}
			}
		})
		b.Run(tc.name+"/validate", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := ValidateDN(value); (err == nil) != (wantErr == nil) {
					b.Fatal(err)
				}
			}
		})
	}
}
