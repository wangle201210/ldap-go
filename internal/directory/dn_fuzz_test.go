package directory

import "testing"

func FuzzParseDNRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"",
		"dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
		"cn=Smith\\, John+uid=jsmith,ou=People,dc=example,dc=com",
		"cn=leading\\ space,dc=example,dc=com",
		"cn=hash\\23value,dc=example,dc=com",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		dn, err := ParseDN(value)
		if err != nil {
			return
		}
		roundTripped, err := ParseDN(dn.String())
		if err != nil {
			t.Fatalf("parse formatted DN %q: %v", dn.String(), err)
		}
		if !dn.Equal(roundTripped) || dn.Key() != roundTripped.Key() {
			t.Fatalf(
				"DN round trip mismatch: %q (%q) != %q (%q)",
				dn.String(),
				dn.Key(),
				roundTripped.String(),
				roundTripped.Key(),
			)
		}

		current := dn
		for depth := dn.Depth(); depth > 0; depth-- {
			parent, ok := current.Parent()
			if !ok || parent.Depth() != depth-1 {
				t.Fatalf("parent depth from %q = %d, %t", current.String(), parent.Depth(), ok)
			}
			if parent.Depth() > 0 && !parent.AncestorOf(dn) {
				t.Fatalf("parent %q is not an ancestor of %q", parent.String(), dn.String())
			}
			current = parent
		}
	})
}
