package server

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestCollectiveAdministrativeAreaBoundaries(t *testing.T) {
	t.Parallel()

	registry := collectiveServerRegistry(t)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })

	const (
		baseDN       = "dc=example,dc=com"
		outerDN      = "ou=people," + baseDN
		innerDN      = "ou=team," + outerDN
		deepInnerDN  = "ou=deep," + innerDN
		isolatedDN   = "ou=isolated," + innerDN
		autonomousDN = "ou=autonomous," + baseDN
		wrongRoleDN  = "ou=wrong," + baseDN
		orphanDN     = "ou=orphan," + baseDN
	)
	entries := []directory.Entry{
		collectiveAdministrativePointEntry(
			outerDN,
			"collectiveAttributeSpecificArea",
		),
		collectiveAdministrativePointEntry(
			innerDN,
			collectiveAttributeInnerAreaOID,
		),
		collectiveAdministrativePointEntry(
			deepInnerDN,
			"collectiveAttributeInnerArea",
		),
		collectiveAdministrativePointEntry(
			isolatedDN,
			collectiveAttributeSpecificAreaOID,
		),
		collectiveAdministrativePointEntry(
			autonomousDN,
			"autonomousArea",
		),
		collectiveAdministrativePointEntry(
			wrongRoleDN,
			"accessControlSpecificArea",
		),
		collectiveAdministrativePointEntry(
			orphanDN,
			"collectiveAttributeInnerArea",
		),
		collectiveAdministrativeSource("cn=outer-a,"+outerDN, "outer-a"),
		collectiveAdministrativeSource("cn=outer-b,"+outerDN, "outer-b"),
		collectiveAdministrativeSource("cn=inner-a,"+innerDN, "inner-a"),
		collectiveAdministrativeSource("cn=inner-b,"+innerDN, "inner-b"),
		collectiveAdministrativeSource("cn=deep,"+deepInnerDN, "deep"),
		collectiveAdministrativeSource("cn=isolated,"+isolatedDN, "isolated"),
		collectiveAdministrativeSource("cn=autonomous,"+autonomousDN, "autonomous"),
		collectiveAdministrativeSource("cn=wrong,"+wrongRoleDN, "wrong"),
		collectiveAdministrativeSource("cn=orphan,"+orphanDN, "orphan"),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed collective administrative areas: %v", err)
	}

	if err := store.View(context.Background(), func(reader storage.Reader) error {
		plan, err := buildCollectiveAttributePlan(registry, reader)
		if err != nil {
			return err
		}
		if len(plan.specificAreas) != 3 {
			t.Fatalf("specific areas = %#v, want outer, isolated, and autonomous", plan.specificAreas)
		}
		if len(plan.sources) != 7 {
			t.Fatalf("eligible collective sources = %d, want 7", len(plan.sources))
		}

		tests := []struct {
			name       string
			dn         string
			values     []string
			references []string
		}{
			{
				name:   "specific area",
				dn:     "uid=outer," + outerDN,
				values: []string{"outer-a", "outer-b"},
				references: []string{
					"cn=outer-a," + outerDN,
					"cn=outer-b," + outerDN,
				},
			},
			{
				name:   "inner area overlaps specific",
				dn:     "uid=inner," + innerDN,
				values: []string{"inner-a", "inner-b", "outer-a", "outer-b"},
				references: []string{
					"cn=inner-a," + innerDN,
					"cn=inner-b," + innerDN,
					"cn=outer-a," + outerDN,
					"cn=outer-b," + outerDN,
				},
			},
			{
				name:   "nested inner areas accumulate",
				dn:     "uid=deep," + deepInnerDN,
				values: []string{"deep", "inner-a", "inner-b", "outer-a", "outer-b"},
				references: []string{
					"cn=deep," + deepInnerDN,
					"cn=inner-a," + innerDN,
					"cn=inner-b," + innerDN,
					"cn=outer-a," + outerDN,
					"cn=outer-b," + outerDN,
				},
			},
			{
				name:       "nested specific area cuts outer and inner",
				dn:         "uid=isolated," + isolatedDN,
				values:     []string{"isolated"},
				references: []string{"cn=isolated," + isolatedDN},
			},
			{
				name:       "autonomous point is implicit specific area",
				dn:         "uid=autonomous," + autonomousDN,
				values:     []string{"autonomous"},
				references: []string{"cn=autonomous," + autonomousDN},
			},
			{
				name: "unrelated role cannot host collective subentry",
				dn:   "uid=wrong," + wrongRoleDN,
			},
			{
				name: "inner area requires containing specific area",
				dn:   "uid=orphan," + orphanDN,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				entry := collectiveServerPerson(test.dn, nil)
				derived, applyErr := plan.apply(entry)
				if applyErr != nil {
					t.Fatalf("apply(%q): %v", test.dn, applyErr)
				}
				assertCollectiveSet(
					t,
					derived.Values("c-description"),
					test.values,
				)
				assertCollectiveSet(
					t,
					derived.Values("collectiveAttributeSubentries"),
					test.references,
				)
			})
		}
		return nil
	}); err != nil {
		t.Fatalf("evaluate collective administrative areas: %v", err)
	}
}

func collectiveAdministrativeSource(dn, value string) directory.Entry {
	return collectiveServerSource(
		dn,
		"{}",
		directory.Attribute{
			Description: "c-description",
			Values:      stringValues(value),
		},
	)
}

func assertCollectiveSet(t *testing.T, values [][]byte, want []string) {
	t.Helper()
	if len(values) == 0 && len(want) == 0 {
		return
	}
	got := make([]string, len(values))
	for index := range values {
		got[index] = string(values[index])
	}
	sort.Strings(got)
	want = append([]string(nil), want...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collective values = %q, want %q", got, want)
	}
}
