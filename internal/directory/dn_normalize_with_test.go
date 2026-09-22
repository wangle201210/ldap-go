package directory

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

type parsedDNRecordingNormalizer struct {
	aliasIdentityNormalizer
	calls  []string
	failAt int
	err    error
}

func (n *parsedDNRecordingNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	n.calls = append(n.calls, "normalize:"+attribute+"="+string(value))
	if len(n.calls) == n.failAt {
		return "", nil, n.err
	}
	return n.aliasIdentityNormalizer.NormalizeDNAttribute(attribute, value)
}

func (n *parsedDNRecordingNormalizer) CanonicalDNAttributeName(attribute string) (string, error) {
	n.calls = append(n.calls, "canonical:"+attribute)
	if len(n.calls) == n.failAt {
		return "", n.err
	}
	return n.aliasIdentityNormalizer.CanonicalDNAttributeName(attribute)
}

func TestDNNormalizeWithPreservesCallsAndErrors(t *testing.T) {
	const raw = "uid=ALICE+commonName=Example,dc=COM"
	legacy, err := ParseDN(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{
		"normalize:uid=ALICE", "canonical:uid",
		"normalize:commonName=Example", "canonical:commonName",
		"normalize:dc=COM", "canonical:dc",
	}
	injected := errors.New("normalizer failure")
	for failAt := 0; failAt <= len(wantCalls); failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			n := &parsedDNRecordingNormalizer{failAt: failAt, err: injected}
			got, gotErr := legacy.NormalizeWith(n)
			reference := &parsedDNRecordingNormalizer{failAt: failAt, err: injected}
			want, wantErr := ParseDNWithNormalizer(raw, reference)
			if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) ||
				reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) {
				t.Fatalf("got %#v, %v; want %#v, %v", got, gotErr, want, wantErr)
			}
			calls := wantCalls
			if failAt != 0 {
				calls = calls[:failAt]
				if !errors.Is(gotErr, injected) {
					t.Fatalf("lost normalizer error: %v", gotErr)
				}
			}
			if !reflect.DeepEqual(n.calls, calls) || !reflect.DeepEqual(n.calls, reference.calls) {
				t.Fatalf("calls = %q, want %q", n.calls, calls)
			}
		})
	}
	if _, err := legacy.NormalizeWith(nil); err == nil || err.Error() != "DN attribute normalizer is required" {
		t.Fatalf("nil normalizer error = %v", err)
	}
	// The existing parser must still reject a nil normalizer before parsing.
	if _, err := ParseDNWithNormalizer("invalid DN", nil); err == nil || err.Error() != "DN attribute normalizer is required" {
		t.Fatalf("parser error precedence changed: %v", err)
	}
}

func TestDNNormalizeWithImmutableSharing(t *testing.T) {
	for _, raw := range []string{
		"", "dc=COM", "exactAlias=Root,dc=COM",
		"uid=ALICE+commonName=Example,dc=COM",
		`cn=\ leading\ +uid=Smith\, Alice,dc=COM`,
		`cn=\00\ff\c3\a9\+\"\;\<\>\\,dc=COM`,
	} {
		t.Run(raw, func(t *testing.T) {
			legacy, err := ParseDN(raw)
			if err != nil {
				t.Fatal(err)
			}
			untouched, _ := ParseDN(raw)
			parent, hasParent := legacy.Parent()
			wantParent, _ := untouched.Parent()
			normalized, err := legacy.NormalizeWith(aliasIdentityNormalizer{})
			if err != nil {
				t.Fatal(err)
			}
			want, err := ParseDNWithNormalizer(raw, aliasIdentityNormalizer{})
			if err != nil || !reflect.DeepEqual(normalized, want) {
				t.Fatalf("normalized DN differs: %v", err)
			}
			if !reflect.DeepEqual(legacy, untouched) || hasParent && !reflect.DeepEqual(parent, wantParent) {
				t.Fatal("normalization mutated the legacy DN or its parent")
			}
			// A second schema uses original AVAs, not the first schema's pretty DN.
			recomputed, err := normalized.NormalizeWith(scopeIdentityNormalizer{})
			wantRecomputed, wantErr := ParseDNWithNormalizer(raw, scopeIdentityNormalizer{})
			if err != nil || wantErr != nil || !reflect.DeepEqual(recomputed, wantRecomputed) || !reflect.DeepEqual(normalized, want) {
				t.Fatalf("renormalization changed shared state: %v / %v", err, wantErr)
			}
		})
	}
	got, err := (DN{}).NormalizeWith(aliasIdentityNormalizer{})
	want, wantErr := ParseDNWithNormalizer("", aliasIdentityNormalizer{})
	if err != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("zero DN differs from empty DN: %v / %v", err, wantErr)
	}
}

func TestDNNormalizeWithCanonicalAliasCollision(t *testing.T) {
	legacy, err := ParseDN("cn=Alice+commonName=Bob,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	n := &parsedDNRecordingNormalizer{}
	_, err = legacy.NormalizeWith(n)
	if err == nil || err.Error() != `normalize DN RDN 0: canonical attribute type "2.5.4.3" appears more than once` {
		t.Fatalf("alias collision error = %v", err)
	}
	if want := []string{"normalize:cn=Alice", "canonical:cn", "normalize:commonName=Bob"}; !reflect.DeepEqual(n.calls, want) {
		t.Fatalf("calls = %q, want %q", n.calls, want)
	}
}
