package server

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestDatabaseEqualityIndexAssertionCachedDN(t *testing.T) {
	t.Parallel()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	normalizer := &databaseEqualityIndexNormalizer{registry: registry}
	for _, equality := range []string{"caseIgnoreMatch", "caseExactMatch", "caseIgnoreMatch"} {
		attribute, _ := registry.AttributeType("uid")
		attribute.Equality = equality
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct{ attribute, value string }{
			{"member", "userid=ALICE,dc=EXAMPLE"},
			{"2.5.4.31;binary", "uid=Alice+cn=Team,dc=example"},
			{"member", "cn=broken,"},
			{"member", "unknownName=x"},
			{"uniqueMember", "uid=ALICE#'01'B"},
			{"uidNumber", "123"},
			{"dITStructureRules", "17"},
		} {
			want, wantErr := registry.NormalizeEqualityAssertion(test.attribute, []byte(test.value))
			for range 2 {
				got, gotErr := normalizer.NormalizeEqualityIndexAssertion(test.attribute, []byte(test.value))
				if !reflect.DeepEqual(got, want) || reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
					t.Fatalf("%s=%q (%s): got %q/%v, want %q/%v", test.attribute, test.value, equality, got, gotErr, want, wantErr)
				}
				clear(got)
			}
		}
	}
}

type equalityAssertionCallbackRegistry struct {
	*schema.Registry
	callback    func(string, []byte) ([]byte, error)
	cachedCalls int
}

func (registry *equalityAssertionCallbackRegistry) NormalizeEqualityAssertion(description string, value []byte) ([]byte, error) {
	return registry.callback(description, value)
}

func (registry *equalityAssertionCallbackRegistry) NormalizeEqualityAssertionCachedDN(string, []byte) ([]byte, error) {
	registry.cachedCalls++
	return nil, errors.New("custom registry must not opt into caching")
}

func TestDatabaseEqualityIndexAssertionCustomCallbacks(t *testing.T) {
	t.Parallel()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	custom := &equalityAssertionCallbackRegistry{Registry: registry}
	normalizer := &databaseEqualityIndexNormalizer{registry: custom}
	input := []byte("{0}CN=Alice")
	wantErr := errors.New("changed callback error")
	calls := 0
	for _, result := range []struct {
		value []byte
		err   error
	}{
		{input, nil}, {[]byte("different normalization"), nil}, {nil, wantErr}, {input, nil},
	} {
		custom.callback = func(description string, value []byte) ([]byte, error) {
			calls++
			if description != "MEMBER;binary" || !bytes.Equal(value, input) || &value[0] != &input[0] {
				t.Fatal("custom callback input changed")
			}
			return result.value, result.err
		}
		before := calls
		got, err := normalizer.NormalizeEqualityIndexAssertion("MEMBER;binary", input)
		if calls != before+1 || custom.cachedCalls != 0 || !reflect.DeepEqual(got, result.value) || !errors.Is(err, result.err) {
			t.Fatalf("callback result %q/%v, calls=%d, cached calls=%d", got, err, calls, custom.cachedCalls)
		}
		if len(got) > 0 && &got[0] != &result.value[0] {
			t.Fatal("custom callback result was copied")
		}
	}
}
