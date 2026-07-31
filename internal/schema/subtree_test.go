package schema

import (
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestParseSubtreeSpecification(t *testing.T) {
	t.Parallel()

	value := `{ base "ou=People\, West", ` +
		`specificExclusions { chopBefore:"ou=Contractors", chopAfter:"ou=Archive" }, ` +
		`minimum 1, maximum 3, ` +
		`specificationFilter and:{ item:person, not:item:alias } }`
	specification, err := ParseSubtreeSpecification(value)
	if err != nil {
		t.Fatalf("ParseSubtreeSpecification(): %v", err)
	}
	base := subtreeMustDN(t, `ou=People\, West`)
	if !specification.Base.Equal(base) {
		t.Fatalf("base = %q, want %q", specification.Base.String(), base.String())
	}
	if len(specification.SpecificExclusions) != 2 ||
		!specification.SpecificExclusions[0].ChopBefore ||
		specification.SpecificExclusions[1].ChopBefore {
		t.Fatalf("specific exclusions = %#v", specification.SpecificExclusions)
	}
	if specification.Minimum != 1 ||
		specification.Maximum == nil ||
		*specification.Maximum != 3 {
		t.Fatalf(
			"distance bounds = %d..%v",
			specification.Minimum,
			specification.Maximum,
		)
	}
	if specification.SpecificationFilter == nil ||
		specification.SpecificationFilter.Kind != SubtreeRefinementAnd ||
		len(specification.SpecificationFilter.Children) != 2 ||
		specification.SpecificationFilter.Children[1].Kind != SubtreeRefinementNot {
		t.Fatalf(
			"specification filter = %#v",
			specification.SpecificationFilter,
		)
	}
}

func TestParseSubtreeSpecificationRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	values := []string{
		"",
		"{",
		"{ } trailing",
		"{base\"\"}",
		"{ Base \"\" }",
		"{ unknown 1 }",
		"{ minimum -1 }",
		"{ minimum 01 }",
		"{ maximum 1, minimum 0 }",
		"{ minimum 0, minimum 1 }",
		"{ minimum 1, }",
		"{ base \"ou\" }",
		"{ specificExclusions { chopBefore: \"ou=People\" } }",
		"{ specificExclusions { before:\"ou=People\" } }",
		"{ specificExclusions { chopBefore:\"ou=People\", } }",
		"{ specificationFilter item:1 }",
		"{ specificationFilter item:1.02 }",
		"{ specificationFilter item:not_an_oid }",
		"{ specificationFilter every:{ item:person } }",
		"{ specificationFilter and:{ item:person, } }",
		"{\tminimum 1 }",
	}
	deepRefinement := "{ specificationFilter " +
		strings.Repeat("not:", maxSubtreeRefinementDepth+1) +
		"item:person }"
	values = append(values, deepRefinement)

	for _, value := range values {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseSubtreeSpecification(value); err == nil {
				t.Fatalf("ParseSubtreeSpecification(%q) succeeded", value)
			}
		})
	}
}

func TestSubtreeSpecificationMatches(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	specification, err := ParseSubtreeSpecification(
		`{ base "ou=People", ` +
			`specificExclusions { chopBefore:"ou=Contractors", chopAfter:"ou=Archive" }, ` +
			`minimum 1, maximum 2, ` +
			`specificationFilter and:{ item:2.5.6.6, not:item:alias } }`,
	)
	if err != nil {
		t.Fatalf("ParseSubtreeSpecification(): %v", err)
	}
	administrativePoint := subtreeMustDN(t, "dc=example,dc=com")

	tests := []struct {
		name          string
		dn            string
		objectClasses []string
		want          bool
	}{
		{
			name:          "matching subclass",
			dn:            "uid=alice,ou=People,dc=example,dc=com",
			objectClasses: []string{"inetOrgPerson"},
			want:          true,
		},
		{
			name:          "minimum excludes base",
			dn:            "ou=People,dc=example,dc=com",
			objectClasses: []string{"person"},
		},
		{
			name:          "chop before excludes named entry",
			dn:            "ou=Contractors,ou=People,dc=example,dc=com",
			objectClasses: []string{"person"},
		},
		{
			name:          "chop before excludes descendants",
			dn:            "uid=alice,ou=Contractors,ou=People,dc=example,dc=com",
			objectClasses: []string{"person"},
		},
		{
			name:          "chop after keeps named entry",
			dn:            "ou=Archive,ou=People,dc=example,dc=com",
			objectClasses: []string{"person"},
			want:          true,
		},
		{
			name:          "chop after excludes descendants",
			dn:            "uid=alice,ou=Archive,ou=People,dc=example,dc=com",
			objectClasses: []string{"person"},
		},
		{
			name:          "maximum excludes deep entry",
			dn:            "uid=alice,cn=deep,ou=Team,ou=People,dc=example,dc=com",
			objectClasses: []string{"person"},
		},
		{
			name:          "refinement excludes another class",
			dn:            "ou=Team,ou=People,dc=example,dc=com",
			objectClasses: []string{"organizationalUnit"},
		},
		{
			name:          "refinement excludes alias",
			dn:            "cn=alice,ou=People,dc=example,dc=com",
			objectClasses: []string{"alias", "person"},
		},
		{
			name:          "outside base",
			dn:            "uid=alice,ou=Other,dc=example,dc=com",
			objectClasses: []string{"person"},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidateDN := subtreeMustDN(t, test.dn)
			entry := directory.Entry{
				DN: test.dn,
				Attributes: []directory.Attribute{{
					Description: "objectClass",
					Values:      subtreeByteValues(test.objectClasses...),
				}},
			}
			matches, err := registry.SubtreeSpecificationMatches(
				specification,
				administrativePoint,
				candidateDN,
				entry,
			)
			if err != nil {
				t.Fatalf("SubtreeSpecificationMatches(): %v", err)
			}
			if matches != test.want {
				t.Fatalf("matches = %t, want %t", matches, test.want)
			}
		})
	}
}

func TestSubtreeSpecificationEmptyRefinementSets(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	administrativePoint := subtreeMustDN(t, "dc=example,dc=com")
	entryDN := subtreeMustDN(t, "uid=alice,dc=example,dc=com")
	entry := directory.Entry{
		DN: entryDN.String(),
		Attributes: []directory.Attribute{{
			Description: "objectClass",
			Values:      subtreeByteValues("inetOrgPerson"),
		}},
	}
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "empty and", value: "{ specificationFilter and:{} }", want: true},
		{name: "empty or", value: "{ specificationFilter or:{} }"},
	} {
		specification, err := ParseSubtreeSpecification(test.value)
		if err != nil {
			t.Fatalf("ParseSubtreeSpecification(%s): %v", test.name, err)
		}
		matches, err := registry.SubtreeSpecificationMatches(
			specification,
			administrativePoint,
			entryDN,
			entry,
		)
		if err != nil {
			t.Fatalf("SubtreeSpecificationMatches(%s): %v", test.name, err)
		}
		if matches != test.want {
			t.Fatalf("%s matches = %t, want %t", test.name, matches, test.want)
		}
	}
}

func subtreeMustDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}

func subtreeByteValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}
