package directory

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func checkSimpleDNIdentitySingleAVA(t *testing.T, rdn []byte) {
	t.Helper()
	avas, err := referenceDecodeDNIdentityParts(rdn)
	want := false
	if err == nil && len(avas) == 1 {
		parts, err := referenceDecodeDNIdentityParts(avas[0])
		want = err == nil && len(parts) == 2 && len(parts[0]) != 0
	}
	payload := encodeDNIdentityParts(rdn)
	key := []byte(schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(payload))
	var scratch [1024]byte
	want = want && len(payload) <= len(scratch)
	rdns, ok := validatedSimpleDNIdentityRDNsBytes([]byte("cn=a"), key, scratch[:])
	if ok != want {
		t.Fatalf("single AVA %x: fast path = %t, reference = %t", rdn, ok, want)
	}
	if ok && (rdns.count != 1 || !bytes.Equal(rdns.next(), rdn) || len(rdns.data) != 0) {
		t.Fatalf("single AVA %x: returned an incomplete RDN view", rdn)
	}
}

func TestSimpleDNIdentitySingleAVAReference(t *testing.T) {
	for _, payload := range identityPayloadCorpus() {
		checkSimpleDNIdentitySingleAVA(t, payload)
		checkSimpleDNIdentitySingleAVA(t, encodeDNIdentityParts(payload))
	}
	for _, field := range [][]byte{
		{0x80},
		append(bytes.Repeat([]byte{0xff}, 9), 2),
		binary.AppendUvarint(nil, ^uint64(0)),
	} {
		for _, rdn := range [][]byte{
			field,
			append([]byte{1}, field...),
			encodeDNIdentityParts(field),
			encodeDNIdentityParts(append([]byte{2}, field...)),
			encodeDNIdentityParts(append([]byte{2, 1, 'c'}, field...)),
		} {
			checkSimpleDNIdentitySingleAVA(t, rdn)
		}
	}
	for _, typeSize := range []int{0, 1, 127, 128, 255, 256} {
		for _, valueSize := range []int{0, 1, 127, 128, 255, 256, 1011, 1012, 1013} {
			// Identity types and values are opaque bytes, with only the type
			// required to be nonempty, independently of the display DN.
			rdn := encodeDNIdentityParts(encodeDNIdentityParts(
				bytes.Repeat([]byte{0xff}, typeSize), bytes.Repeat([]byte{0}, valueSize),
			))
			checkSimpleDNIdentitySingleAVA(t, rdn)
		}
	}
}

func TestSimpleDNIdentitySingleAVANonminimalVarints(t *testing.T) {
	pad := func(value uint64, width int) []byte {
		encoded := binary.AppendUvarint(nil, value)
		for len(encoded) < width {
			encoded[len(encoded)-1] |= 0x80
			encoded = append(encoded, 0)
		}
		return encoded
	}
	// Independently vary all five count/length fields, including accepted
	// ten-byte nonminimal varints that end in zero.
	for combination := range 243 {
		var widths [5]int
		for index := range widths {
			widths[index] = []int{1, 2, 10}[combination%3]
			combination /= 3
		}
		ava := append(pad(2, widths[2]), pad(2, widths[3])...)
		ava = append(ava, 'c', 'n')
		ava = append(ava, pad(1, widths[4])...)
		ava = append(ava, 'a')
		rdn := append(pad(1, widths[0]), pad(uint64(len(ava)), widths[1])...)
		rdn = append(rdn, ava...)
		checkSimpleDNIdentitySingleAVA(t, rdn)
		for end := range len(rdn) {
			checkSimpleDNIdentitySingleAVA(t, rdn[:end])
		}
		for _, tail := range []byte{0, 1, 0x80, 0xff} {
			checkSimpleDNIdentitySingleAVA(t, append(bytes.Clone(rdn), tail))
			checkSimpleDNIdentitySingleAVA(t, encodeDNIdentityParts(append(bytes.Clone(ava), tail)))
		}
	}
}

func TestValidateDNIdentitySingleAVATailsAndErrorOrder(t *testing.T) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	ava := encodeDNIdentityParts([]byte("cn"), []byte("a"))
	rdn := encodeDNIdentityParts(ava)
	invalidRDN := encodeDNIdentityParts(encodeDNIdentityParts(nil, nil))
	overflow := append(bytes.Repeat([]byte{0xff}, 9), 2)
	for _, malformed := range [][]byte{
		append(bytes.Clone(rdn), 0),
		encodeDNIdentityParts(append(bytes.Clone(ava), 0)),
		encodeDNIdentityParts([]byte{2, 2, 'c', 'n', 0x80}),
		encodeDNIdentityParts(append([]byte{2, 2, 'c', 'n'}, overflow...)),
		encodeDNIdentityParts([]byte{2, 2, 'c', 'n', 1}),
		{2, 0, 0x80},
	} {
		for position := range 3 {
			rdns := [][]byte{rdn, base.identityRDNs[0], base.identityRDNs[1]}
			rdns[position] = malformed
			payload := encodeDNIdentityParts(rdns...)
			// Outer tails and later outer lengths must be checked even when
			// earlier RDN contents are invalid or scope would already fail.
			badOuter := binary.AppendUvarint(nil, 2)
			badOuter = binary.AppendUvarint(badOuter, uint64(len(invalidRDN)))
			badOuter = append(badOuter, invalidRDN...)
			badOuter = append(badOuter, 0x80)
			for _, raw := range [][]byte{payload, append(bytes.Clone(payload), 0), badOuter} {
				key := schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
				for _, candidateKey := range []string{key, key + "\r\n"} {
					for _, value := range []string{"cn=a,dc=example,dc=com", "cn=a", "cn"} {
						for _, scopeBase := range []DN{base, {}, {identityLevel: schemaAwareDNIdentityLevel}} {
							for scope := Scope(-1); scope <= Scope(4); scope++ {
								checkDNIdentityScope(t, value, candidateKey, scopeBase, scope)
							}
						}
					}
				}
			}
		}
	}
}

func FuzzSimpleDNIdentitySingleAVA(f *testing.F) {
	for _, payload := range identityPayloadCorpus()[:40] {
		f.Add(payload, int8(ScopeWholeSubtree))
	}
	base, err := ParseDNWithNormalizer("dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, payload []byte, scope int8) {
		for _, rdn := range [][]byte{
			payload,
			encodeDNIdentityParts(payload),
			encodeDNIdentityParts(encodeDNIdentityParts([]byte("cn"), payload)),
		} {
			checkSimpleDNIdentitySingleAVA(t, rdn)
			for position := range 3 {
				rdns := [][]byte{base.identityRDNs[0], base.identityRDNs[0], base.identityRDNs[1]}
				rdns[position] = rdn
				key := encodeDNIdentity(rdns)
				for _, scopeBase := range []DN{base, {}} {
					checkDNIdentityScope(t, "cn=a,dc=example,dc=com", key, scopeBase, Scope(scope))
				}
			}
		}
	})
}
