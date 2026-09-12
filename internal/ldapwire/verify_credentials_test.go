package ldapwire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestDecodeVerifyCredentialsRequestValue(t *testing.T) {
	t.Parallel()
	if VerifyCredentialsOID != "1.3.6.1.4.1.4203.666.6.5" {
		t.Fatal("unexpected Verify Credentials OID")
	}
	// Golden bytes follow ldap_verify_credentials in pinned OpenLDAP 2.6.13.
	// Cookies and credentials are OCTET STRINGs, not C strings or LDAPStrings.
	for _, test := range []struct {
		name string
		hex  string
		want VerifyCredentialsRequestValue
	}{
		{"anonymous", "300404008000", VerifyCredentialsRequestValue{
			Authentication: Authentication{Simple: []byte{}},
		}},
		{"binary password", "300d04047569643d800500ff808001", VerifyCredentialsRequestValue{
			Name: "uid=", Authentication: Authentication{Simple: []byte{0, 0xff, 0x80, 0x80, 1}},
		}},
		{"sasl absent credentials", "300b0400a3070405504c41494e", VerifyCredentialsRequestValue{
			Authentication: Authentication{IsSASL: true, SASLMechanism: "PLAIN"},
		}},
		{"sasl empty credentials", "300d0400a3090405504c41494e0400", VerifyCredentialsRequestValue{
			Authentication: Authentication{IsSASL: true, SASLMechanism: "PLAIN",
				HasSASLCredentials: true, SASLCredentials: []byte{}},
		}},
		{"sasl binary cookie and credentials", "3015800300ff000400a30c0405504c41494e040300ff00", VerifyCredentialsRequestValue{
			Cookie: []byte{0, 0xff, 0}, HasCookie: true,
			Authentication: Authentication{IsSASL: true, SASLMechanism: "PLAIN",
				HasSASLCredentials: true, SASLCredentials: []byte{0, 0xff, 0}},
		}},
		{"empty cookie retained for handler", "3006800004008000", VerifyCredentialsRequestValue{
			Cookie: []byte{}, HasCookie: true, Authentication: Authentication{Simple: []byte{}},
		}},
		{"empty controls", "300604008000a200", VerifyCredentialsRequestValue{
			Authentication: Authentication{Simple: []byte{}}, Controls: []Control{},
		}},
		{"binary control", "301604008000a210300e0405312e322e330101ff040200ff", VerifyCredentialsRequestValue{
			Authentication: Authentication{Simple: []byte{}},
			Controls:       []Control{{OID: "1.2.3", Critical: true, HasValue: true, Value: []byte{0, 0xff}}},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := verifyCredentialsHex(t, test.hex)
			got, err := DecodeVerifyCredentialsRequestValue(value, true)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("decode = %#v, %v; want %#v", got, err, test.want)
			}
			// Every exported value must survive reuse of the original wire buffer.
			clear(value)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("decoded request aliases input: %#v", got)
			}
		})
	}
}

func TestDecodeVerifyCredentialsControlsPreservesWireValues(t *testing.T) {
	t.Parallel()
	controls := verifyCredentialsTLV(0xa2,
		verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, []byte("1.2.3"))),
		verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, []byte("1.2.3")),
			verifyCredentialsTLV(0x01, []byte{0}), verifyCredentialsTLV(0x04, nil)),
		verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, []byte("1.2.4")),
			verifyCredentialsTLV(0x01, []byte{1})),
	)
	value := verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, nil),
		verifyCredentialsTLV(0x80, nil), controls)
	request, err := DecodeVerifyCredentialsRequestValue(value, true)
	want := []Control{
		{OID: "1.2.3"},
		{OID: "1.2.3", HasValue: true, Value: []byte{}},
		{OID: "1.2.4", Critical: true},
	}
	if err != nil || !reflect.DeepEqual(request.Controls, want) {
		t.Fatalf("controls = %#v, %v; want %#v", request.Controls, err, want)
	}
	// Repeated OIDs are preserved in order; operation-specific control policy
	// is distinct from rejecting duplicate fields inside a Control sequence.
}

func TestDecodeVerifyCredentialsAcceptsDefiniteNonminimalLengths(t *testing.T) {
	t.Parallel()
	canonical := verifyCredentialsHex(t, "301604008000a210300e0405312e322e330101ff040200ff")
	want, err := DecodeVerifyCredentialsRequestValue(canonical, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, width := range []int{1, 2, 4, 8} {
		t.Run(strconv.Itoa(width), func(t *testing.T) {
			value := verifyCredentialsNonminimal(t, canonical, width)
			got, err := DecodeVerifyCredentialsRequestValue(value, true)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("nonminimal lengths decode = %#v, %v", got, err)
			}
		})
	}
}

func TestDecodeVerifyCredentialsRejectsMalformed(t *testing.T) {
	t.Parallel()
	dn, password := verifyCredentialsTLV(0x04, []byte("uid=alice")), verifyCredentialsTLV(0x80, nil)
	mech := verifyCredentialsTLV(0x04, []byte("PLAIN"))
	oid := verifyCredentialsTLV(0x04, []byte("1.2.3"))
	valid := verifyCredentialsTLV(0x30, dn, password)
	withControl := func(fields ...[]byte) []byte {
		return verifyCredentialsTLV(0x30, dn, password,
			verifyCredentialsTLV(0xa2, verifyCredentialsTLV(0x30, fields...)))
	}
	cases := map[string][]byte{
		"empty":                  nil,
		"empty sequence":         {0x30, 0},
		"primitive sequence":     {0x10, 0},
		"trailing byte":          append(bytes.Clone(valid), 0),
		"two sequences":          append(bytes.Clone(valid), valid...),
		"missing auth":           verifyCredentialsTLV(0x30, dn),
		"duplicate DN":           verifyCredentialsTLV(0x30, dn, dn, password),
		"duplicate auth":         verifyCredentialsTLV(0x30, dn, password, password),
		"duplicate cookie":       verifyCredentialsTLV(0x30, password, password, dn, password),
		"cookie after DN":        verifyCredentialsTLV(0x30, dn, password, password),
		"constructed cookie":     verifyCredentialsTLV(0x30, verifyCredentialsTLV(0xa0, nil), dn, password),
		"wrong DN tag":           verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x80, nil), password),
		"constructed DN":         verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x24, dn), password),
		"NUL DN":                 verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, []byte("uid=\x00")), password),
		"invalid UTF8 DN":        verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, []byte{0xff}), password),
		"constructed simple":     verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0xa0, password)),
		"unknown auth":           verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0x81, nil)),
		"primitive SASL":         verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0x83, mech)),
		"empty SASL":             verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0xa3, nil)),
		"empty mechanism":        verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0xa3, verifyCredentialsTLV(0x04, nil))),
		"NUL mechanism":          verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0xa3, verifyCredentialsTLV(0x04, []byte("PLAIN\x00")))),
		"invalid UTF8 mechanism": verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0xa3, verifyCredentialsTLV(0x04, []byte{0xff}))),
		"wrong mechanism tag":    verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0xa3, password)),
		"wrong credential tag":   verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0xa3, mech, password)),
		"extra SASL field":       verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0xa3, mech, mech, mech)),
		"duplicate controls":     verifyCredentialsTLV(0x30, dn, password, verifyCredentialsTLV(0xa2, nil), verifyCredentialsTLV(0xa2, nil)),
		"controls before auth":   verifyCredentialsTLV(0x30, dn, verifyCredentialsTLV(0xa2, nil), password),
		"primitive controls":     verifyCredentialsTLV(0x30, dn, password, verifyCredentialsTLV(0x82, nil)),
		"wrong controls context": verifyCredentialsTLV(0x30, dn, password, verifyCredentialsTLV(0xa0, nil)),
		"empty control":          withControl(),
		"empty OID":              withControl(verifyCredentialsTLV(0x04, nil)),
		"NUL OID":                withControl(verifyCredentialsTLV(0x04, []byte("1.2\x00"))),
		"invalid UTF8 OID":       withControl(verifyCredentialsTLV(0x04, []byte{0xff})),
		"nonnumeric OID":         withControl(verifyCredentialsTLV(0x04, []byte("ppolicy"))),
		"noncanonical OID":       withControl(verifyCredentialsTLV(0x04, []byte("1.02.3"))),
		"single arc OID":         withControl(verifyCredentialsTLV(0x04, []byte("1"))),
		"empty boolean":          withControl(oid, verifyCredentialsTLV(0x01, nil)),
		"long boolean":           withControl(oid, verifyCredentialsTLV(0x01, []byte{0, 1})),
		"constructed boolean":    withControl(oid, verifyCredentialsTLV(0x21, []byte{0xff})),
		"duplicate boolean":      withControl(oid, verifyCredentialsTLV(0x01, []byte{0}), verifyCredentialsTLV(0x01, []byte{0})),
		"duplicate value":        withControl(oid, verifyCredentialsTLV(0x04, nil), verifyCredentialsTLV(0x04, nil)),
		"boolean after value":    withControl(oid, verifyCredentialsTLV(0x04, nil), verifyCredentialsTLV(0x01, []byte{0})),
		"constructed value":      withControl(oid, verifyCredentialsTLV(0x24, verifyCredentialsTLV(0x04, nil))),
		"indefinite outer":       {0x30, 0x80, 0x04, 0, 0x80, 0, 0, 0},
		"indefinite auth":        verifyCredentialsTLV(0x30, dn, []byte{0xa3, 0x80}, mech, []byte{0, 0}),
		"invalid length":         {0x30, 0xff},
		"excess length octets":   {0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"huge declared length":   {0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"huge inner length":      verifyCredentialsTLV(0x30, []byte{0x04, 0x84, 0x7f, 0xff, 0xff, 0xff}),
		"high tag number":        {0x3f, 0x10, 0},
		"high tag field":         verifyCredentialsTLV(0x30, []byte{0x1f, 0x04, 0}, password),
		"child beyond parent":    {0x30, 0x02, 0x04, 0x02, 0x80, 0},
		"unexpected EOC":         verifyCredentialsTLV(0x30, dn, password, []byte{0, 0}),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) { assertVerifyCredentialsMalformed(t, value, true) })
	}
	for _, value := range [][]byte{nil, valid} {
		assertVerifyCredentialsMalformed(t, value, false)
	}
	for length := 0; length < len(valid); length++ {
		assertVerifyCredentialsMalformed(t, valid[:length], true)
	}
	// A nested payload must be rejected at its first invalid structural tag,
	// without walking or allocating the untrusted constructed subtree.
	nested := []byte{0x30, 0}
	for range 2000 {
		nested = verifyCredentialsTLV(0x30, nested)
	}
	assertVerifyCredentialsMalformed(t, nested, true)
	assertVerifyCredentialsMalformed(t, verifyCredentialsTLV(0x30, dn,
		verifyCredentialsTLV(0xa3, nested)), true)
	assertVerifyCredentialsMalformed(t, withControl(oid, nested), true)
}

func TestVerifyCredentialsRequestBounds(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		limit int
		value func([]byte) []byte
	}{
		{"DN", maxVerifyCredentialsNameBytes, func(b []byte) []byte {
			return verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, b), verifyCredentialsTLV(0x80, nil))
		}},
		{"password", maxVerifyCredentialsAuthBytes, func(b []byte) []byte {
			return verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, nil), verifyCredentialsTLV(0x80, b))
		}},
		{"SASL credentials", maxVerifyCredentialsAuthBytes, func(b []byte) []byte {
			return verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, nil),
				verifyCredentialsTLV(0xa3, verifyCredentialsTLV(0x04, []byte("PLAIN")), verifyCredentialsTLV(0x04, b)))
		}},
		{"mechanism", maxVerifyCredentialsAuthBytes, func(b []byte) []byte {
			return verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, nil),
				verifyCredentialsTLV(0xa3, verifyCredentialsTLV(0x04, b)))
		}},
		{"cookie", maxVerifyCredentialsAuthBytes, func(b []byte) []byte {
			return verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x80, b),
				verifyCredentialsTLV(0x04, nil), verifyCredentialsTLV(0xa3, verifyCredentialsTLV(0x04, []byte("PLAIN"))))
		}},
		{"OID", maxVerifyCredentialsOIDBytes, func(b []byte) []byte {
			b = bytes.Clone(b)
			for index := range b {
				b[index] = '1'
			}
			b[1] = '.'
			return verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, nil), verifyCredentialsTLV(0x80, nil),
				verifyCredentialsTLV(0xa2, verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, b))))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := test.value(bytes.Repeat([]byte{'x'}, test.limit))
			if _, err := DecodeVerifyCredentialsRequestValue(value, true); err != nil {
				t.Fatalf("at limit: %v", err)
			}
			assertVerifyCredentialsMalformed(t, test.value(bytes.Repeat([]byte{'x'}, test.limit+1)), true)
		})
	}
	control := verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, []byte("1.2.3")))
	for _, count := range []int{maxVerifyCredentialsControls, maxVerifyCredentialsControls + 1} {
		value := verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, nil), verifyCredentialsTLV(0x80, nil),
			verifyCredentialsTLV(0xa2, bytes.Repeat(control, count)))
		if count == maxVerifyCredentialsControls {
			request, err := DecodeVerifyCredentialsRequestValue(value, true)
			if err != nil || len(request.Controls) != count {
				t.Fatalf("controls at limit = %d, %v", len(request.Controls), err)
			}
		} else {
			assertVerifyCredentialsMalformed(t, value, true)
		}
	}
	// The enclosing TLVs consume 31 bytes at this size, so a large opaque
	// control can reach exactly the value limit without large auth fields.
	for _, delta := range []int{0, 1} {
		value := verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, nil), verifyCredentialsTLV(0x80, nil),
			verifyCredentialsTLV(0xa2, verifyCredentialsTLV(0x30,
				verifyCredentialsTLV(0x04, []byte("1.2.3")),
				verifyCredentialsTLV(0x04, make([]byte, maxVerifyCredentialsValueBytes-31+delta)))))
		if len(value) != maxVerifyCredentialsValueBytes+delta {
			t.Fatalf("bad boundary fixture size: %d", len(value))
		}
		if delta == 0 {
			if _, err := DecodeVerifyCredentialsRequestValue(value, true); err != nil {
				t.Fatalf("value at limit: %v", err)
			}
		} else {
			assertVerifyCredentialsMalformed(t, value, true)
		}
	}
}

func TestEncodeVerifyCredentialsResponseValue(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		result   Result
		controls []Control
		hex      string
	}{
		{"success", Result{}, nil, "30050201000400"},
		{"failure", Result{Code: ResultInvalidCredentials, DiagnosticMessage: "bad"}, nil, "30080201310403626164"},
		{"positive integer sign bit", Result{Code: 128}, nil, "3006020200800400"},
		{"extended code", Result{Code: ResultSyncRefreshRequired}, nil, "3006020210000400"},
		{"max native integer", Result{Code: math.MaxInt32}, nil, "300802047fffffff0400"},
		{"outer-only fields omitted", Result{MatchedDN: "dc=example", Referrals: []string{"ldap://example/"}}, nil, "30050201000400"},
		{"empty controls omitted", Result{}, []Control{}, "30050201000400"},
		{"binary control", Result{Code: ResultInvalidCredentials},
			[]Control{{OID: "1.2.3", Critical: true, Value: []byte{0, 0xff}}},
			"30170201310400a210300e0405312e322e330101ff040200ff"},
		{"absent control value", Result{}, []Control{{OID: "1.2.3"}}, "30100201000400a20930070405312e322e33"},
		{"empty control value flag", Result{}, []Control{{OID: "1.2.3", HasValue: true}}, "30120201000400a20b30090405312e322e330400"},
		{"empty control value slice", Result{}, []Control{{OID: "1.2.3", Value: []byte{}}}, "30120201000400a20b30090405312e322e330400"},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := EncodeVerifyCredentialsResponseValue(test.result, test.controls)
			if err != nil || !bytes.Equal(encoded, verifyCredentialsHex(t, test.hex)) {
				t.Fatalf("encode = %x, %v; want %s", encoded, err, test.hex)
			}
			packet, err := ber.DecodePacketErr(encoded)
			if err != nil || len(packet.Children) < 2 || packet.Children[0].Tag != ber.TagInteger ||
				packet.Children[1].Tag != ber.TagOctetString {
				t.Fatalf("independent response decode = %#v, %v", packet, err)
			}
			if len(packet.Children) == 3 {
				if !isPacket(packet.Children[2], ber.ClassContext, ber.TypeConstructed, 2) {
					t.Fatal("response controls do not have context [2]")
				}
			}
			frame, err := ber.DecodePacketErr(EncodeExtendedResponse(1, Result{}, "", encoded, nil))
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range frame.Children[1].Children {
				if field.ClassType == ber.ClassContext && field.Tag == 10 {
					t.Fatal("VC ExtendedResponse contains a responseName")
				}
			}
		})
	}
}

func TestVerifyCredentialsLDAPStrings(t *testing.T) {
	t.Parallel()
	name, diagnostic := "uid=\u7528\u6237,dc=example", "\u5bc6\u7801\u65e0\u6548"
	request, err := DecodeVerifyCredentialsRequestValue(verifyCredentialsTLV(0x30,
		verifyCredentialsTLV(0x04, []byte(name)), verifyCredentialsTLV(0x80, []byte{0, 0xff})), true)
	if err != nil || request.Name != name {
		t.Fatalf("UTF8 name = %q, %v", request.Name, err)
	}
	encoded, err := EncodeVerifyCredentialsResponseValue(Result{DiagnosticMessage: diagnostic}, nil)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil || packet.Children[1].Data.String() != diagnostic {
		t.Fatalf("UTF8 diagnostic response = %x, %v", encoded, err)
	}
}

func TestVerifyCredentialsResponseBoundsAndValidation(t *testing.T) {
	t.Parallel()
	for _, result := range []Result{
		{Code: -1},
		{DiagnosticMessage: "bad\x00message"},
		{DiagnosticMessage: string([]byte{0xff})},
		{DiagnosticMessage: strings.Repeat("x", maxVerifyCredentialsValueBytes)},
	} {
		assertVerifyCredentialsResponseError(t, result, nil)
	}
	if strconv.IntSize == 64 {
		tooLarge := int64(math.MaxInt32) + 1
		assertVerifyCredentialsResponseError(t, Result{Code: ResultCode(tooLarge)}, nil)
	}
	for _, controls := range [][]Control{
		{{}},
		{{OID: "1.2\x00"}},
		{{OID: "1.02.3"}},
		{{OID: "1." + strings.Repeat("1", maxVerifyCredentialsOIDBytes)}},
		{{OID: "1.2.3", Value: make([]byte, maxVerifyCredentialsValueBytes+1)}},
		{{OID: "1.2.3", Value: make([]byte, maxVerifyCredentialsValueBytes/2)},
			{OID: "1.2.4", Value: make([]byte, maxVerifyCredentialsValueBytes/2)}},
		make([]Control, maxVerifyCredentialsControls+1),
	} {
		assertVerifyCredentialsResponseError(t, Result{}, controls)
	}
	controls := make([]Control, maxVerifyCredentialsControls)
	for index := range controls {
		controls[index].OID = "1.2." + strconv.Itoa(index)
	}
	if _, err := EncodeVerifyCredentialsResponseValue(Result{}, controls); err != nil {
		t.Fatalf("controls at limit: %v", err)
	}
	for _, delta := range []int{0, 1} {
		// At this length: outer header (5), integer (3), diagnostic header (5).
		result := Result{DiagnosticMessage: strings.Repeat("x", maxVerifyCredentialsValueBytes-13+delta)}
		encoded, err := EncodeVerifyCredentialsResponseValue(result, nil)
		if delta == 0 {
			if err != nil || len(encoded) != maxVerifyCredentialsValueBytes {
				t.Fatalf("response at limit = %d bytes, %v", len(encoded), err)
			}
		} else if !errors.Is(err, ErrMalformedMessage) || encoded != nil {
			t.Fatalf("oversized response = %d bytes, %v", len(encoded), err)
		}
	}
	for _, delta := range []int{0, 1} {
		controls := []Control{{OID: "1.2.3", Value: make([]byte, maxVerifyCredentialsValueBytes-32+delta)}}
		encoded, err := EncodeVerifyCredentialsResponseValue(Result{}, controls)
		if delta == 0 {
			if err != nil || len(encoded) != maxVerifyCredentialsValueBytes {
				t.Fatalf("response with control at limit = %d bytes, %v", len(encoded), err)
			}
		} else if !errors.Is(err, ErrMalformedMessage) || encoded != nil {
			t.Fatalf("oversized response with control = %d bytes, %v", len(encoded), err)
		}
	}
}

func FuzzEncodeVerifyCredentialsResponseValue(f *testing.F) {
	for _, count := range []uint8{0, 1, 64, 65} {
		f.Add(int64(49), "bad password", "1.2.3", []byte{0, 0xff}, uint8(3), count)
		f.Add(int64(128), "", "1.2.3", []byte{}, uint8(0), count)
	}
	f.Add(int64(-1), "", "", []byte{}, uint8(0), uint8(0))
	f.Add(int64(math.MaxInt32)+1, "", "", []byte{}, uint8(0), uint8(0))
	f.Add(int64(0), "invalid\x00", "invalid", []byte{}, uint8(3), uint8(1))
	f.Fuzz(func(t *testing.T, code int64, diagnostic, oid string, value []byte, flags, count uint8) {
		result := Result{Code: ResultCode(code), DiagnosticMessage: diagnostic}
		controls := make([]Control, int(count))
		for index := range controls {
			controls[index] = Control{OID: oid, Critical: flags&1 != 0, HasValue: flags&2 != 0}
			if flags&4 == 0 {
				controls[index].Value = value
			}
		}
		original := bytes.Clone(value)
		encoded, err := EncodeVerifyCredentialsResponseValue(result, controls)
		if !bytes.Equal(value, original) {
			t.Fatal("encoder mutated caller data")
		}
		if err != nil {
			if encoded != nil || !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("invalid response returned partial bytes or wrong error: %v", err)
			}
			return
		}
		if len(encoded) > maxVerifyCredentialsValueBytes || len(controls) > maxVerifyCredentialsControls {
			t.Fatal("encoder exceeded its bounds")
		}
		packet, err := ber.DecodePacketErr(encoded)
		if err != nil {
			t.Fatalf("independent BER decoder rejected output: %v", err)
		}
		fields := 2
		if len(controls) > 0 {
			fields++
		}
		if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) || len(packet.Children) != fields {
			t.Fatal("invalid response structure")
		}
		if !isPacket(packet.Children[0], ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger) ||
			packet.Children[0].Value != int64(result.Code) ||
			!isPacket(packet.Children[1], ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString) ||
			packet.Children[1].Data.String() != diagnostic {
			t.Fatal("response code or diagnostic changed")
		}
		if len(controls) > 0 {
			wrapper := packet.Children[2]
			if !isPacket(wrapper, ber.ClassContext, ber.TypeConstructed, 2) {
				t.Fatal("invalid response controls tag")
			}
			// Decode with the ordinary LDAP control path after translating only
			// the wrapper tag from VC [2] to LDAPMessage [0].
			wrapper.Tag = 0
			decoded, err := decodeControls(wrapper)
			if err != nil || len(decoded) != len(controls) {
				t.Fatalf("independent control decode: %v", err)
			}
			for index, control := range decoded {
				want := controls[index]
				if control.OID != want.OID || control.Critical != want.Critical ||
					control.HasValue != (want.HasValue || want.Value != nil) || !bytes.Equal(control.Value, want.Value) {
					t.Fatal("control content or value presence changed")
				}
			}
		}
		originalEncoded := bytes.Clone(encoded)
		clear(value)
		if !bytes.Equal(encoded, originalEncoded) {
			t.Fatal("response aliases caller data")
		}
	})
}

func FuzzDecodeVerifyCredentialsRequestValue(f *testing.F) {
	for _, value := range [][]byte{
		{0x30, 4, 4, 0, 0x80, 0},
		verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x80, []byte{0, 0xff}), verifyCredentialsTLV(0x04, nil),
			verifyCredentialsTLV(0xa3, verifyCredentialsTLV(0x04, []byte("PLAIN")), verifyCredentialsTLV(0x04, nil))),
		verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, []byte("uid=alice")), verifyCredentialsTLV(0x80, []byte{0, 0xff}),
			verifyCredentialsTLV(0xa2, verifyCredentialsTLV(0x30, verifyCredentialsTLV(0x04, []byte("1.2.3")),
				verifyCredentialsTLV(0x01, []byte{0xff}), verifyCredentialsTLV(0x04, nil)))),
		{0x30, 0x81, 4, 4, 0, 0x80, 0},
		{0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		nil,
	} {
		f.Add(value, true)
		f.Add(value, false)
	}
	f.Fuzz(func(t *testing.T, value []byte, present bool) {
		before := bytes.Clone(value)
		request, err := DecodeVerifyCredentialsRequestValue(value, present)
		if !bytes.Equal(value, before) {
			t.Fatal("decoder mutated the wire buffer")
		}
		if err != nil {
			if !errors.Is(err, ErrMalformedMessage) || !reflect.DeepEqual(request, VerifyCredentialsRequestValue{}) {
				t.Fatalf("malformed input returned a partial request or wrong error: %v", err)
			}
			return
		}
		if !present || len(value) > maxVerifyCredentialsValueBytes || len(request.Name) > maxVerifyCredentialsNameBytes ||
			len(request.Cookie) > maxVerifyCredentialsAuthBytes || len(request.Authentication.Simple) > maxVerifyCredentialsAuthBytes ||
			len(request.Authentication.SASLCredentials) > maxVerifyCredentialsAuthBytes ||
			len(request.Authentication.SASLMechanism) > maxVerifyCredentialsAuthBytes || len(request.Controls) > maxVerifyCredentialsControls {
			t.Fatal("decoder exceeded its bounds")
		}
		clear(value)
		again, err := DecodeVerifyCredentialsRequestValue(before, true)
		if err != nil || !reflect.DeepEqual(request, again) {
			t.Fatal("decoded data aliases the wire buffer")
		}
	})
}

func assertVerifyCredentialsMalformed(t *testing.T, value []byte, present bool) {
	t.Helper()
	request, err := DecodeVerifyCredentialsRequestValue(value, present)
	if !errors.Is(err, ErrMalformedMessage) || !reflect.DeepEqual(request, VerifyCredentialsRequestValue{}) {
		t.Fatalf("decode malformed %d-byte value = %#v, %v", len(value), request, err)
	}
}

func assertVerifyCredentialsResponseError(t *testing.T, result Result, controls []Control) {
	t.Helper()
	encoded, err := EncodeVerifyCredentialsResponseValue(result, controls)
	if !errors.Is(err, ErrMalformedMessage) || encoded != nil {
		t.Fatalf("invalid response = %d bytes, %v", len(encoded), err)
	}
}

func verifyCredentialsHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func verifyCredentialsTLV(tag byte, content ...[]byte) []byte {
	packet := ber.Encode(ber.Class(tag&0xc0), ber.Type(tag&0x20), ber.Tag(tag&0x1f), nil, "")
	for _, field := range content {
		_, _ = packet.Data.Write(field)
	}
	return packet.Bytes()
}

func verifyCredentialsNonminimal(t *testing.T, value []byte, width int) []byte {
	t.Helper()
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Clone(packet.Data.Bytes())
	if packet.TagType == ber.TypeConstructed {
		content = nil
		for _, child := range packet.Children {
			content = append(content, verifyCredentialsNonminimal(t, child.Bytes(), width)...)
		}
	}
	encoded := make([]byte, 2+width, 2+width+len(content))
	encoded[0], encoded[1] = value[0], 0x80|byte(width)
	length := len(content)
	for index := width + 1; index >= 2; index-- {
		encoded[index], length = byte(length), length>>8
	}
	if length != 0 {
		t.Fatal("test length does not fit")
	}
	return append(encoded, content...)
}
