package directory

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func FuzzDNNormalizeWithReference(f *testing.F) {
	for _, raw := range []string{"", "uid=alice,dc=example,dc=com", "cn=a+uid=b,dc=com", "cn=a+commonName=b,dc=com", `cn=\00\ff\,x,dc=com`} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		dn, err := ParseDN(raw)
		if err != nil {
			return
		}
		for _, normalizer := range []DNAttributeNormalizer{scopeIdentityNormalizer{}, aliasIdentityNormalizer{}} {
			got, gotErr := dn.NormalizeWith(normalizer)
			want, wantErr := referenceNormalizeDNWith(dn, normalizer)
			if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) {
				t.Fatalf("normalizer %T: got %#v/%v, want %#v/%v", normalizer, got, gotErr, want, wantErr)
			}
		}
	})
}

func TestDNNormalizeWithSingleAVAReference(t *testing.T) {
	for _, raw := range []string{
		"", "DC=COM", "uid=ALICE,dc=Example,dc=COM",
		"commonName=Alice,exactAlias=Root,dc=COM",
		"cn=,dc=COM", "2.5.4.3=ALICE,dc=COM",
		`cn=\ leading\ ,dc=COM`,
		`cn=\00\ff\c3\a9\+\"\;\<\>\\,dc=COM`,
		"uid=ALICE+commonName=Example,exactAlias=Root,dc=COM",
		"cn=Alice,uid=ALICE+exactAlias=Root,dc=COM",
		"cn=" + strings.Repeat("a", 4096) + ",dc=COM",
		strings.Repeat("ou=People,", 130) + "dc=COM",
	} {
		t.Run(raw, func(t *testing.T) {
			original := mustDN(t, raw)
			for _, normalizer := range []DNAttributeNormalizer{scopeIdentityNormalizer{}, aliasIdentityNormalizer{}} {
				got, err := original.NormalizeWith(normalizer)
				want, wantErr := referenceNormalizeDNWith(original, normalizer)
				if err != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("normalizer %T: got %#v, %v; want %#v, %v", normalizer, got, err, want, wantErr)
				}
			}
		})
	}
}

type singleAVARecordingNormalizer struct {
	parsedDNRecordingNormalizer
	emptyAt int
}

func (n *singleAVARecordingNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	canonical, normalized, err := n.parsedDNRecordingNormalizer.NormalizeDNAttribute(attribute, value)
	if err == nil && len(n.calls) == n.emptyAt {
		return " \t ", normalized, nil
	}
	return canonical, normalized, err
}

func TestDNNormalizeWithSingleAVACallbackErrors(t *testing.T) {
	injected := errors.New("single AVA normalizer failure")
	for _, raw := range []string{
		"uid=ALICE,commonName=Example,dc=COM",
		"uid=ALICE+commonName=Example,dc=COM",
		"uid=ALICE,cn=Alice+commonName=Bob,dc=COM",
	} {
		original := mustDN(t, raw)
		callbackCount := 0
		for _, rdn := range original.parsed.RDNs {
			callbackCount += 2 * len(rdn.Attributes)
		}
		for _, emptyType := range []bool{false, true} {
			for at := 0; at <= callbackCount; at++ {
				t.Run(fmt.Sprintf("%s/empty=%t/at=%d", raw, emptyType, at), func(t *testing.T) {
					current := &singleAVARecordingNormalizer{}
					if emptyType {
						current.emptyAt = at
					} else {
						current.failAt, current.err = at, injected
					}
					reference := *current
					got, err := original.NormalizeWith(current)
					want, wantErr := referenceNormalizeDNWith(original, &reference)
					if !reflect.DeepEqual(got, want) || fmt.Sprint(err) != fmt.Sprint(wantErr) ||
						reflect.TypeOf(err) != reflect.TypeOf(wantErr) ||
						errors.Is(err, injected) != errors.Is(wantErr, injected) ||
						!reflect.DeepEqual(current.calls, reference.calls) {
						t.Fatalf("got %#v, %v, %q; want %#v, %v, %q", got, err, current.calls, want, wantErr, reference.calls)
					}
				})
			}
		}
	}
}

type singleAVABufferNormalizer struct {
	buffer [64]byte
	inputs [][]byte
}

func (n *singleAVABufferNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	n.inputs = append(n.inputs, value)
	length := copy(n.buffer[:], strings.ToLower(string(value)))
	if len(value) != 0 {
		value[0] = '!'
	}
	return " " + strings.ToUpper(attribute) + " ", n.buffer[:length], nil
}

func (n *singleAVABufferNormalizer) CanonicalDNAttributeName(attribute string) (string, error) {
	// Identity must already own its bytes; normalized display observes this mutation.
	n.buffer[0] = '?'
	return strings.ToLower(attribute), nil
}

func TestDNNormalizeWithSingleAVAOwnedResults(t *testing.T) {
	for _, raw := range []string{
		"CN=Alice,DC=Example,DC=COM",
		"CN=Alice+UID=ALICE,DC=Example,DC=COM",
	} {
		t.Run(raw, func(t *testing.T) {
			original := mustDN(t, raw)
			untouched := mustDN(t, raw)
			originalParent, _ := original.Parent()
			wantOriginalParent, _ := untouched.Parent()
			normalizer := &singleAVABufferNormalizer{}
			got, err := original.NormalizeWith(normalizer)
			want, wantErr := referenceNormalizeDNWith(untouched, &singleAVABufferNormalizer{})
			if err != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v, %v; want %#v, %v", got, err, want, wantErr)
			}
			identity, err := referenceNormalizeDNWith(untouched, scopeIdentityNormalizer{})
			if err != nil || got.Key() != identity.Key() {
				t.Fatalf("identity observed canonical-name buffer mutation: %v", err)
			}
			parent, _ := got.Parent()
			wantParent, _ := want.Parent()
			for _, value := range normalizer.inputs {
				for index := range value {
					value[index] = '!'
				}
			}
			for index := range normalizer.buffer {
				normalizer.buffer[index] = '!'
			}
			values := got.RDNValues()
			values[0].Value[0] = '!'
			values[0].Type = "changed"
			recomputed, err := got.NormalizeWith(scopeIdentityNormalizer{})
			if err != nil || !reflect.DeepEqual(recomputed, identity) {
				t.Fatalf("renormalization lost original attributes: %v", err)
			}
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(parent, wantParent) ||
				!reflect.DeepEqual(original, untouched) || !reflect.DeepEqual(originalParent, wantOriginalParent) {
				t.Fatal("normalization or external buffer mutation changed a retained DN")
			}
		})
	}
}
