package schema_test

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestAbsentAttributeFiltersPreserveUndefined(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		filter string
		valid  bool
	}{
		{"(unknownFilterAttribute=value)", false},
		{"(unknownFilterAttribute=*)", false},
		{"(cn>=A)", false},
		{"(jpegPhoto=value)", false},
		{"(userPassword=*secret*)", false},
		{"(createTimestamp=not-a-time)", false},
		{"(cn:1.2.3:=value)", false},
		{"(cn;unknownOption=value)", false},
		{"(cn=Absent)", true},
		{"(cn=*)", true},
		{"(cn~=Absent)", true},
		{"(cn;lang-en=Absent)", true},
		{"(cn;lang-=Absent)", true},
		{"(cn:caseIgnoreMatch:=Absent)", true},
		{"(createTimestamp=20260920000000Z)", true},
		{"(attributeTypes=cn)", true},
		{"(objectClasses=person)", true},
		{"(matchingRules=caseIgnoreMatch)", true},
		{"(dITStructureRules=1)", true},
		{"(certificateRevocationList=*)", true},
		{"(certificateRevocationList;binary=*)", true},
	} {
		t.Run(test.filter, func(t *testing.T) {
			filter, err := ldapwire.CompileFilter(test.filter)
			if err != nil {
				t.Fatal(err)
			}
			want := directory.FilterUndefinedResult
			if test.valid {
				want = directory.FilterFalseResult
			}
			if got, err := filter.EvaluateWith(directory.Entry{}, registry); err != nil || got != want {
				t.Fatalf("direct = %v, %v; want %v", got, err, want)
			}
			negated := directory.Filter{Kind: directory.FilterNot, Children: []directory.Filter{filter}}
			if test.valid {
				want = directory.FilterTrueResult
			}
			if got, err := negated.EvaluateWith(directory.Entry{}, registry); err != nil || got != want {
				t.Fatalf("NOT = %v, %v; want %v", got, err, want)
			}
		})
	}
}
