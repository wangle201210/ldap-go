package directory

import (
	"errors"
	"testing"
)

func TestEntryMutationsAreAtomicBuildingBlocks(t *testing.T) {
	t.Parallel()

	entry := Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []Attribute{
			{Description: "mail", Values: [][]byte{[]byte("alice@example.com")}},
			{Description: "loginCount", Values: [][]byte{[]byte("4")}},
		},
	}

	if err := entry.AddValues("mail", [][]byte{[]byte("other@example.com")}); err != nil {
		t.Fatalf("AddValues(): %v", err)
	}
	if err := entry.AddValues("mail", [][]byte{[]byte("ALICE@example.com")}); !errors.Is(err, ErrAttributeValueExists) {
		t.Fatalf("duplicate AddValues() error = %v", err)
	}
	if err := entry.DeleteValues("mail", [][]byte{[]byte("missing@example.com")}); !errors.Is(err, ErrNoSuchAttribute) {
		t.Fatalf("missing DeleteValues() error = %v", err)
	}
	entry.ReplaceValues("description", [][]byte{[]byte("updated")})
	if err := entry.Increment("loginCount", []byte("3")); err != nil {
		t.Fatalf("Increment(): %v", err)
	}

	if !entry.HasValue("mail", []byte("other@example.com")) {
		t.Fatal("added mail value is missing")
	}
	if !entry.HasValue("description", []byte("updated")) {
		t.Fatal("replacement attribute is missing")
	}
	if !entry.HasValue("loginCount", []byte("7")) {
		t.Fatal("incremented value is missing")
	}
}

func TestReplaceAncestorAndRDNValues(t *testing.T) {
	t.Parallel()

	oldBase := mustDN(t, "ou=people,dc=example,dc=com")
	newSuperior := mustDN(t, "ou=archive,dc=example,dc=com")
	newBase, err := ComposeDN("ou=users", newSuperior)
	if err != nil {
		t.Fatalf("ComposeDN(): %v", err)
	}
	child := mustDN(t, "uid=alice,ou=people,dc=example,dc=com")
	replaced, err := child.ReplaceAncestor(oldBase, newBase)
	if err != nil {
		t.Fatalf("ReplaceAncestor(): %v", err)
	}
	want := mustDN(t, "uid=alice,ou=users,ou=archive,dc=example,dc=com")
	if !replaced.Equal(want) {
		t.Fatalf("replaced DN = %q, want %q", replaced.String(), want.String())
	}
}
