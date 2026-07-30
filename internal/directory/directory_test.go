package directory

import (
	"testing"
)

func TestDNScopes(t *testing.T) {
	t.Parallel()

	base := mustDN(t, "dc=Example,dc=COM")
	child := mustDN(t, "ou=People,dc=example,dc=com")
	grandchild := mustDN(t, "uid=alice,ou=people,dc=example,dc=com")

	if !InScope(base, base, ScopeBase) {
		t.Fatal("base DN must be in base scope")
	}
	if !InScope(base, child, ScopeSingleLevel) {
		t.Fatal("child DN must be in one-level scope")
	}
	if InScope(base, grandchild, ScopeSingleLevel) {
		t.Fatal("grandchild DN must not be in one-level scope")
	}
	if !InScope(base, grandchild, ScopeWholeSubtree) {
		t.Fatal("grandchild DN must be in subtree scope")
	}
}

func TestFilterMatch(t *testing.T) {
	t.Parallel()

	entry := Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
			{Description: "cn", Values: [][]byte{[]byte("Alice Example")}},
			{Description: "mail", Values: [][]byte{[]byte("alice@example.com")}},
		},
	}

	tests := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{
			name: "and equality and presence",
			filter: Filter{
				Kind: FilterAnd,
				Children: []Filter{
					{Kind: FilterEquality, Attribute: "objectclass", Assertion: []byte("INETORGPERSON")},
					{Kind: FilterPresent, Attribute: "mail"},
				},
			},
			want: true,
		},
		{
			name: "ordered substring",
			filter: Filter{
				Kind:      FilterSubstrings,
				Attribute: "cn",
				Substring: Substring{
					Initial: []byte("ali"),
					Any:     [][]byte{[]byte("ce ex")},
					Final:   []byte("ample"),
				},
			},
			want: true,
		},
		{
			name: "not",
			filter: Filter{
				Kind:     FilterNot,
				Children: []Filter{{Kind: FilterEquality, Attribute: "cn", Assertion: []byte("Bob")}},
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := test.filter.Match(entry)
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("Match() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestEntrySelectsUserAndOperationalAttributes(t *testing.T) {
	t.Parallel()

	entry := Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []Attribute{
			{Description: "uid", Values: [][]byte{[]byte("alice")}},
			{Description: "modifyTimestamp", Values: [][]byte{[]byte("20260730000000Z")}},
		},
	}
	isOperational := func(description string) bool {
		return description == "modifyTimestamp"
	}

	user := entry.SelectWith([]string{"*"}, false, isOperational)
	if !user.HasAttribute("uid") || user.HasAttribute("modifyTimestamp") {
		t.Fatalf("user selection = %#v", user.Attributes)
	}
	operational := entry.SelectWith([]string{"+"}, false, isOperational)
	if operational.HasAttribute("uid") || !operational.HasAttribute("modifyTimestamp") {
		t.Fatalf("operational selection = %#v", operational.Attributes)
	}
	all := entry.SelectWith([]string{"*", "+"}, false, isOperational)
	if !all.HasAttribute("uid") || !all.HasAttribute("modifyTimestamp") {
		t.Fatalf("combined selection = %#v", all.Attributes)
	}
	explicit := entry.SelectWith([]string{"modifyTimestamp"}, true, isOperational)
	if len(explicit.Attributes) != 1 || len(explicit.Attributes[0].Values) != 0 {
		t.Fatalf("typesOnly explicit selection = %#v", explicit.Attributes)
	}
}

func mustDN(t *testing.T, value string) DN {
	t.Helper()
	dn, err := ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
