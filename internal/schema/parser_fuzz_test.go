package schema

import (
	"reflect"
	"testing"
)

func FuzzSchemaDescriptionRoundTrip(f *testing.F) {
	seeds := []struct {
		kind        uint8
		description string
	}{
		{0, "( 1.2.3 NAME 'appID' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"},
		{1, "( 1.2.4 NAME 'appUser' SUP top AUXILIARY MUST appID MAY description )"},
		{2, "( 2.5.6.6 NAME 'personRule' AUX appUser MUST mail NOT description )"},
		{3, "( 1.2.5 NAME 'personForm' OC inetOrgPerson MUST uid MAY cn )"},
		{4, "( 100 NAME 'personStructure' FORM personForm SUP ( 1 2 ) )"},
	}
	for _, seed := range seeds {
		f.Add(seed.kind, seed.description)
	}
	f.Add(uint8(0), "")

	f.Fuzz(func(t *testing.T, kind uint8, description string) {
		switch kind % 5 {
		case 0:
			first, err := ParseAttributeType(description)
			if err != nil {
				return
			}
			second, err := ParseAttributeType(FormatAttributeType(first))
			assertSchemaFuzzRoundTrip(t, first, second, err)
		case 1:
			first, err := ParseObjectClass(description)
			if err != nil {
				return
			}
			second, err := ParseObjectClass(FormatObjectClass(first))
			assertSchemaFuzzRoundTrip(t, first, second, err)
		case 2:
			first, err := ParseDITContentRule(description)
			if err != nil {
				return
			}
			second, err := ParseDITContentRule(FormatDITContentRule(first))
			assertSchemaFuzzRoundTrip(t, first, second, err)
		case 3:
			first, err := ParseNameForm(description)
			if err != nil {
				return
			}
			second, err := ParseNameForm(FormatNameForm(first))
			assertSchemaFuzzRoundTrip(t, first, second, err)
		case 4:
			first, err := ParseDITStructureRule(description)
			if err != nil {
				return
			}
			second, err := ParseDITStructureRule(FormatDITStructureRule(first))
			assertSchemaFuzzRoundTrip(t, first, second, err)
		}
	})
}

func assertSchemaFuzzRoundTrip(t *testing.T, first, second any, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("parse formatted schema description: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("schema round trip mismatch\nfirst:  %#v\nsecond: %#v", first, second)
	}
}
