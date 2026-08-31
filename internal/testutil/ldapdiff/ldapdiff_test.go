package ldapdiff

import (
	"errors"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestSearchOutcomeCanonicalizesEntryAttributeAndValueOrder(t *testing.T) {
	t.Parallel()
	left := &ldap.SearchResult{Entries: []*ldap.Entry{
		ldap.NewEntry("uid=bob,dc=example,dc=com", map[string][]string{
			"description": {"second", "first"},
			"uid":         {"bob"},
		}),
		ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
			"uid": {"alice"},
		}),
	}}
	right := &ldap.SearchResult{Entries: []*ldap.Entry{
		ldap.NewEntry("UID=alice,DC=example,DC=com", map[string][]string{
			"UID": {"alice"},
		}),
		ldap.NewEntry("uid=bob,DC=example,DC=com", map[string][]string{
			"UID":         {"bob"},
			"DESCRIPTION": {"first", "second"},
		}),
	}}
	if err := CompareOutcomes(
		SearchOutcome(left, nil, Options{}),
		SearchOutcome(right, nil, Options{}),
		Options{},
	); err != nil {
		t.Fatal(err)
	}
}

func TestSearchOutcomeDoesNotFoldDNValuesWithoutSchema(t *testing.T) {
	t.Parallel()
	left := &ldap.SearchResult{Entries: []*ldap.Entry{
		ldap.NewEntry("uid=Alice,dc=example,dc=com", nil),
	}}
	right := &ldap.SearchResult{Entries: []*ldap.Entry{
		ldap.NewEntry("uid=alice,dc=example,dc=com", nil),
	}}
	if err := CompareOutcomes(
		SearchOutcome(left, nil, Options{}),
		SearchOutcome(right, nil, Options{}),
		Options{},
	); err == nil {
		t.Fatal("schema-neutral DN comparison folded case-exact values")
	}
	options := Options{NormalizeDN: func(value string) (string, error) {
		return strings.ToLower(value), nil
	}}
	if err := CompareOutcomes(
		SearchOutcome(left, nil, options),
		SearchOutcome(right, nil, options),
		options,
	); err != nil {
		t.Fatal(err)
	}
}

func TestSearchOutcomeIgnoresConfiguredAttributesAndOpaqueControls(t *testing.T) {
	t.Parallel()
	leftControl := ldap.NewControlPaging(10)
	leftControl.SetCookie([]byte("left"))
	rightControl := ldap.NewControlPaging(10)
	rightControl.SetCookie([]byte("right"))
	options := Options{
		IgnoreAttributes: map[string]struct{}{"entryuuid": {}},
		OpaqueControlValues: map[string]struct{}{
			PagingControlOID: {},
		},
	}
	left := &ldap.SearchResult{
		Entries: []*ldap.Entry{ldap.NewEntry("dc=example,dc=com", map[string][]string{
			"dc":        {"example"},
			"entryUUID": {"left"},
		})},
		Controls: []ldap.Control{leftControl},
	}
	right := &ldap.SearchResult{
		Entries: []*ldap.Entry{ldap.NewEntry("dc=example,dc=com", map[string][]string{
			"dc":        {"example"},
			"entryUUID": {"right"},
		})},
		Controls: []ldap.Control{rightControl},
	}
	if err := CompareOutcomes(
		SearchOutcome(left, nil, options),
		SearchOutcome(right, nil, options),
		options,
	); err != nil {
		t.Fatal(err)
	}
}

func TestCompareOutcomesCanIgnoreOnlyDiagnosticText(t *testing.T) {
	t.Parallel()
	reference := Outcome{Code: ldap.LDAPResultNoSuchObject, Diagnostic: "reference"}
	candidate := Outcome{Code: ldap.LDAPResultNoSuchObject, Diagnostic: "candidate"}
	if err := CompareOutcomes(reference, candidate, Options{IgnoreDiagnostic: true}); err != nil {
		t.Fatal(err)
	}
	candidate.Code = ldap.LDAPResultOther
	if err := CompareOutcomes(reference, candidate, Options{IgnoreDiagnostic: true}); err == nil {
		t.Fatal("result-code mismatch was ignored")
	}
}

func TestSearchCountOutcomeIgnoresUnspecifiedTruncatedSubset(t *testing.T) {
	t.Parallel()
	left := &ldap.SearchResult{Entries: []*ldap.Entry{
		ldap.NewEntry("uid=alice,dc=example,dc=com", nil),
		ldap.NewEntry("uid=bob,dc=example,dc=com", nil),
	}}
	right := &ldap.SearchResult{Entries: []*ldap.Entry{
		ldap.NewEntry("uid=alice,dc=example,dc=com", nil),
		ldap.NewEntry("uid=carol,dc=example,dc=com", nil),
	}}
	if err := CompareOutcomes(
		SearchCountOutcome(left, nil, Options{}),
		SearchCountOutcome(right, nil, Options{}),
		Options{},
	); err != nil {
		t.Fatal(err)
	}
}

func TestResultOutcomePreservesLDAPErrorContract(t *testing.T) {
	t.Parallel()
	outcome := ResultOutcome(ldap.NewError(
		ldap.LDAPResultConstraintViolation,
		errors.New("constraint detail"),
	))
	if outcome.Code != ldap.LDAPResultConstraintViolation ||
		outcome.Diagnostic != "constraint detail" {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestCompareOutcomesBoundsMismatchDiagnostics(t *testing.T) {
	t.Parallel()
	reference := Outcome{Diagnostic: strings.Repeat("r", 40<<10)}
	candidate := Outcome{
		Code:       ldap.LDAPResultOther,
		Diagnostic: strings.Repeat("c", 40<<10),
	}
	err := CompareOutcomes(reference, candidate, Options{})
	if err == nil || !strings.Contains(err.Error(), "bytes omitted") ||
		len(err.Error()) > 66<<10 {
		t.Fatalf("bounded mismatch error length = %d, error = %v", len(err.Error()), err)
	}
}
