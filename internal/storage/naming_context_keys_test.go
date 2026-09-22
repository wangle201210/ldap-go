package storage

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func inferNamingContextsReference(forEach func(func(directory.Entry, directory.DN) error) error) ([]string, error) {
	type namedDN struct {
		dn  directory.DN
		raw string
	}
	entries := make(map[string]namedDN)
	if err := forEach(func(entry directory.Entry, dn directory.DN) error {
		if dn.Depth() != 0 {
			entries[dn.Key()] = namedDN{dn: dn, raw: entry.DN}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("scan directory entries: %w", err)
	}
	contexts := make([]namedDN, 0)
	for _, entry := range entries {
		parent, exists := entry.dn.Parent()
		if !exists || parent.Depth() == 0 {
			contexts = append(contexts, entry)
			continue
		}
		if _, exists := entries[parent.Key()]; !exists {
			contexts = append(contexts, entry)
		}
	}
	sort.Slice(contexts, func(i, j int) bool { return contexts[i].dn.Key() < contexts[j].dn.Key() })
	result := make([]string, len(contexts))
	for i := range contexts {
		result[i] = contexts[i].raw
	}
	return result, nil
}

type namingContextKeyNormalizer struct{ testDNNormalizer }

func (normalizer namingContextKeyNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	switch strings.ToLower(attribute) {
	case "cn", "2.5.4.3":
		return "2.5.4.3", []byte(strings.ToLower(string(value))), nil
	case "ou", "2.5.4.11":
		return "2.5.4.11", []byte(strings.ToLower(string(value))), nil
	default:
		return normalizer.testDNNormalizer.NormalizeDNAttribute(attribute, value)
	}
}

func namingContextKeyRows(rows []string, failure error) func(func(directory.Entry, directory.DN) error) error {
	return func(visit func(directory.Entry, directory.DN) error) error {
		for _, raw := range rows {
			dn, err := directory.ParseDNWithNormalizer(raw, namingContextKeyNormalizer{})
			if err != nil {
				return err
			}
			if err := visit(directory.Entry{DN: raw}, dn); err != nil {
				return err
			}
		}
		return failure
	}
}

func TestNamingContextKeysMatchParsedDNReference(t *testing.T) {
	for _, rows := range [][]string{
		nil, {""}, {"cn=config", "cn=schema,cn=config"},
		{"uid=child,dc=missing", "dc=present", "uid=one,dc=present"},
		{"uid=child,dc=missing", "dc=missing"},
		{"CN=duplicate", "cn=DUPLICATE", "uid=child,cn=duplicate"},
		{"exactName=Root", "exactName=root", "uid=one,exactName=Root"},
		{`cn=a\,b+uid=alpha,dc=example`, `uid=alpha+cn=a\,b,dc=example`, "dc=example"},
		{"dc=example", "invalid-DN"},
	} {
		for _, failure := range []error{nil, errors.New("iteration failed")} {
			visit := namingContextKeyRows(rows, failure)
			got, gotErr := inferNamingContexts(visit)
			want, wantErr := inferNamingContextsReference(visit)
			if failure == nil && (len(rows) == 0 || rows[len(rows)-1] != "invalid-DN") && gotErr != nil {
				t.Fatalf("valid rows %q unexpectedly failed: %v", rows, gotErr)
			}
			if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || errors.Is(gotErr, failure) != errors.Is(wantErr, failure) {
				t.Fatalf("rows %q: got %v/%v, want %v/%v", rows, got, gotErr, want, wantErr)
			}
		}
	}
}

func BenchmarkNamingContextKeys(b *testing.B) {
	rows := []string{"dc=example", "ou=people,dc=example"}
	for i := 0; i < 10000; i++ {
		rows = append(rows, fmt.Sprintf("uid=user-%06d,ou=people,dc=example", i))
	}
	visit := namingContextKeyRows(rows, nil)
	for _, implementation := range []struct {
		name  string
		infer func(func(func(directory.Entry, directory.DN) error) error) ([]string, error)
	}{
		{"reference", inferNamingContextsReference}, {"compact", inferNamingContexts},
	} {
		b.Run(implementation.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				got, err := implementation.infer(visit)
				if err != nil || len(got) != 1 || got[0] != "dc=example" {
					b.Fatalf("got %v/%v", got, err)
				}
			}
		})
	}
}
