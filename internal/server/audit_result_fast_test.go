package server

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestSimpleAuditResultCode(t *testing.T) {
	for _, tag := range []byte{0x61, 0x65, 0x67, 0x69, 0x6b, 0x6d, 0x6f, 0x78} {
		for _, code := range []byte{0, 5, 6, 49, 127} {
			encoded := auditResultShortFrame([]byte{1}, tag, code)
			if got, ok := simpleAuditResultCode(encoded); !ok || got != int(code) {
				t.Fatalf("tag=%x code=%d: got (%d, %t)", tag, code, got, ok)
			}
			checkAuditResultEquivalent(t, encoded)
		}
	}
	for width := range 10 {
		for _, fill := range []byte{0, 0xff} {
			encoded := auditResultShortFrame(bytes.Repeat([]byte{fill}, width), 0x61, 49)
			code, ok := simpleAuditResultCode(encoded)
			if want := width >= 1 && width <= 8; ok != want || (ok && code != 49) {
				t.Fatalf("messageID width=%d fill=%x: got (%d, %t)", width, fill, code, ok)
			}
			checkAuditResultEquivalent(t, encoded)
		}
	}
}

func TestSimpleAuditResultCodeMutations(t *testing.T) {
	canonical := auditResultShortFrame([]byte{1}, 0x61, 0)
	for position := range canonical {
		checkAuditResultEquivalent(t, canonical[:position])
		if _, ok := simpleAuditResultCode(canonical[:position]); ok {
			t.Fatalf("accepted truncation at %d", position)
		}
		for value := range 256 {
			encoded := bytes.Clone(canonical)
			encoded[position] = byte(value)
			want := encoded[position] == canonical[position]
			switch position {
			case 4: // The INTEGER contents are not interpreted by the observer.
				want = true
			case 5:
				want = slices.Contains([]byte{0x61, 0x65, 0x67, 0x69, 0x6b, 0x6d, 0x6f, 0x78}, byte(value))
			case 9:
				want = value <= 127
			}
			code, ok := simpleAuditResultCode(encoded)
			if ok != want || (ok && code != int(encoded[9])) {
				t.Fatalf("position=%d value=%x: got (%d, %t), want accepted=%t", position, value, code, ok, want)
			}
			checkAuditResultEquivalent(t, encoded)
		}
	}
}

func TestAuditResultFallbackMatchesLegacy(t *testing.T) {
	for _, fixture := range auditResultFallbackFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			if code, ok := simpleAuditResultCode(fixture.encoded); ok {
				t.Fatalf("fallback accepted with code %d", code)
			}
			checkAuditResultEquivalent(t, fixture.encoded)
			var observation *operationAuditObservation
			observation.observeResponse(fixture.encoded)
		})
	}
}

func TestAuditResultControlPresence(t *testing.T) {
	encoded := auditResultShortFrame([]byte{1}, 0x61, 0)
	observation := &operationAuditObservation{}
	observation.observeResponse(encoded)
	if observation.responseControls != nil {
		t.Fatal("absent controls must remain nil")
	}
	encoded[1] += 2
	encoded = append(encoded, 0xa0, 0)
	observation.observeResponse(encoded)
	if observation.responseControls == nil || len(observation.responseControls) != 0 {
		t.Fatalf("present empty controls = %#v", observation.responseControls)
	}
	observation.observeResponse(auditResultShortFrame([]byte{1}, 0x61, 0))
	if observation.responseControls != nil {
		t.Fatal("simple response must clear prior empty controls back to nil")
	}
}

func TestAuditResultRetainsOwnedBuffers(t *testing.T) {
	result := ldapwire.Result{
		Code: ldapwire.ResultReferral, DiagnosticMessage: "diagnostic\x00\xff",
		Referrals: []string{"ldap://one.example", "ldap://two.example/\x00\xff"},
	}
	controls := []ldapwire.Control{
		{OID: "1.2.3"},
		{OID: "1.2.4", HasValue: true, Value: []byte{}},
		{OID: "1.2.5", Critical: true, HasValue: true, Value: []byte{0, 0xff, 1}},
	}
	encoded := ldapwire.EncodeSearchResultDone(128, result, controls)
	got, want, other := &operationAuditObservation{}, &operationAuditObservation{}, &operationAuditObservation{}
	legacyAuditResultObserveResponse(want, bytes.Clone(encoded))
	got.observeResponse(encoded)
	other.observeResponse(encoded)
	retained := auditResultSnapshot(got)
	if !reflect.DeepEqual(retained, auditResultSnapshot(want)) {
		t.Fatalf("decoded state = %#v, want %#v", retained, auditResultSnapshot(want))
	}
	if got.responseControls[0].HasValue || !got.responseControls[1].HasValue ||
		len(got.responseControls[1].Value) != 0 || !got.responseControls[2].Critical {
		t.Fatalf("control presence or criticality lost: %#v", got.responseControls)
	}
	clear(encoded)
	clear(other.responseControls[2].Value)
	got.observeResponse(auditResultShortFrame([]byte{1}, 0x65, 0))
	if !reflect.DeepEqual(retained, auditResultSnapshot(want)) {
		t.Fatalf("retained state changed after input reuse: %#v", retained)
	}
	if got.diagnostic != "" || got.referrals != nil || got.responseControls != nil {
		t.Fatalf("simple response retained old fields: %#v", auditResultSnapshot(got))
	}
}

func FuzzAuditResultMatchesLegacy(f *testing.F) {
	for _, tag := range []byte{0x61, 0x65, 0x67, 0x69, 0x6b, 0x6d, 0x6f, 0x78} {
		f.Add(auditResultShortFrame([]byte{1}, tag, 0))
		f.Add(auditResultShortFrame(bytes.Repeat([]byte{0xff}, 8), tag, 127))
	}
	for _, fixture := range auditResultFallbackFixtures() {
		f.Add(fixture.encoded)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 4096 {
			t.Skip()
		}
		checkAuditResultEquivalent(t, encoded)
	})
}

func auditResultShortFrame(messageID []byte, tag, code byte) []byte {
	encoded := append([]byte{0x30, byte(11 + len(messageID)), 0x02, byte(len(messageID))}, messageID...)
	return append(encoded, tag, 7, 0x0a, 1, code, 4, 0, 4, 0)
}

func auditResultFallbackFixtures() []struct {
	name    string
	encoded []byte
} {
	simple := auditResultShortFrame([]byte{1}, 0x61, 0)
	return []struct {
		name    string
		encoded []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"matched-dn", ldapwire.EncodeBindResponse(1, ldapwire.Result{MatchedDN: "dc=example"}, nil)},
		{"diagnostic", ldapwire.EncodeBindResponse(1, ldapwire.Result{Code: ldapwire.ResultInvalidCredentials, DiagnosticMessage: "denied\x00\xff"}, nil)},
		{"long-diagnostic", ldapwire.EncodeBindResponse(1, ldapwire.Result{DiagnosticMessage: strings.Repeat("x", 128)}, nil)},
		{"referrals", ldapwire.EncodeSearchResultDone(1, ldapwire.Result{Code: ldapwire.ResultReferral, Referrals: []string{"ldap://one.example", "ldap://one.example", ""}}, nil)},
		{"controls", ldapwire.EncodeBindResponse(1, ldapwire.Result{}, []ldapwire.Control{{OID: "1.2.3"}, {OID: "1.2.4", HasValue: true}, {OID: "1.2.5", Critical: true, HasValue: true, Value: []byte{0, 0xff}}})},
		{"empty-controls", []byte("\x30\x0e\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00\xa0\x00")},
		{"empty-referrals", []byte("\x30\x0e\x02\x01\x01\x61\x09\x0a\x01\x00\x04\x00\x04\x00\xa3\x00")},
		{"sasl", ldapwire.EncodeSASLBindResponse(1, ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress}, []byte{}, true, nil)},
		{"extended", ldapwire.EncodeExtendedResponse(1, ldapwire.Result{}, "1.2.3", []byte{0, 0xff}, nil)},
		{"extended-empty-value", ldapwire.EncodeExtendedResponse(1, ldapwire.Result{}, "", []byte{}, nil)},
		{"search-entry", ldapwire.EncodeSearchResultEntry(1, directory.Entry{DN: "cn=one"}, nil)},
		{"search-reference", ldapwire.EncodeSearchResultReference(1, []string{"ldap://one.example"}, nil)},
		{"intermediate", ldapwire.EncodeIntermediateResponse(1, "1.2.3", []byte{}, nil)},
		{"wide-code", ldapwire.EncodeBindResponse(1, ldapwire.Result{Code: 128}, nil)},
		{"negative-code", ldapwire.EncodeBindResponse(1, ldapwire.Result{Code: -1}, nil)},
		{"long-outer", append([]byte{0x30, 0x81, 0x0c}, simple[2:]...)},
		{"long-operation", []byte("\x30\x0d\x02\x01\x01\x61\x81\x07\x0a\x01\x00\x04\x00\x04\x00")},
		{"long-integer", []byte("\x30\x0d\x02\x81\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00")},
		{"long-enum", []byte("\x30\x0d\x02\x01\x01\x61\x08\x0a\x81\x01\x00\x04\x00\x04\x00")},
		{"indefinite-outer", append(append([]byte{0x30, 0x80}, simple[2:]...), 0, 0)},
		{"high-operation-tag", ldapwire.EncodeResultResponse(1, 31, ldapwire.Result{}, nil)},
		{"trailing-field", []byte("\x30\x0e\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00\x05\x00")},
		{"trailing-data", append(bytes.Clone(simple), 0)},
		{"enum-only-panic", []byte("\x30\x08\x02\x01\x01\x61\x03\x0a\x01\x00")},
		{"two-children-panic", []byte("\x30\x0a\x02\x01\x01\x61\x05\x0a\x01\x00\x04\x00")},
	}
}

type auditResultState struct {
	result     int
	hasResult  bool
	diagnostic string
	entries    int
	referrals  []string
	controls   []ldapwire.Control
}

func auditResultSnapshot(observation *operationAuditObservation) auditResultState {
	return auditResultState{
		result: observation.result, hasResult: observation.hasResult,
		diagnostic: observation.diagnostic, entries: observation.entries,
		referrals: observation.referrals, controls: observation.responseControls,
	}
}

func checkAuditResultEquivalent(t *testing.T, encoded []byte) {
	t.Helper()
	original := bytes.Clone(encoded)
	code, ok, codePanic := auditResultCallCode(auditLDAPResultCode, encoded)
	wantCode, wantOK, wantCodePanic := auditResultCallCode(legacyAuditResultCode, encoded)
	if code != wantCode || ok != wantOK || !reflect.DeepEqual(codePanic, wantCodePanic) {
		t.Fatalf("%x: code=(%d, %t, %v), legacy=(%d, %t, %v)", encoded, code, ok, codePanic, wantCode, wantOK, wantCodePanic)
	}
	// Acceptance is deliberately narrower than the legacy decoder's success.
	if fastCode, fastOK := simpleAuditResultCode(encoded); fastOK && (!wantOK || wantCodePanic != nil || fastCode != wantCode) {
		t.Fatalf("%x: unsound fast result (%d, %t), legacy=(%d, %t)", encoded, fastCode, fastOK, wantCode, wantOK)
	}
	for _, seeded := range []bool{false, true} {
		got, want := &operationAuditObservation{}, &operationAuditObservation{}
		if seeded {
			seed := ldapwire.EncodeSearchResultDone(1, ldapwire.Result{
				Code: ldapwire.ResultInvalidCredentials, DiagnosticMessage: "prior diagnostic",
				Referrals: []string{"ldap://prior.example"},
			}, []ldapwire.Control{{OID: "1.2.3", HasValue: true, Value: []byte{1, 2}}})
			legacyAuditResultObserveResponse(got, seed)
			legacyAuditResultObserveResponse(want, seed)
			got.entries, want.entries = 3, 3
		}
		panicValue := auditResultCallObserver(got, encoded, false)
		wantPanic := auditResultCallObserver(want, encoded, true)
		if !reflect.DeepEqual(panicValue, wantPanic) || !reflect.DeepEqual(auditResultSnapshot(got), auditResultSnapshot(want)) {
			t.Fatalf("%x seeded=%t: state=%#v panic=%v; legacy=%#v panic=%v", encoded, seeded, auditResultSnapshot(got), panicValue, auditResultSnapshot(want), wantPanic)
		}
	}
	if !bytes.Equal(encoded, original) {
		t.Fatal("decoder changed its input buffer")
	}
}

func auditResultCallCode(decode func([]byte) (int, bool), encoded []byte) (code int, ok bool, panicValue any) {
	defer func() { panicValue = auditResultPanic(recover()) }()
	code, ok = decode(encoded)
	return
}

func auditResultCallObserver(observation *operationAuditObservation, encoded []byte, legacy bool) (panicValue any) {
	defer func() { panicValue = auditResultPanic(recover()) }()
	if legacy {
		legacyAuditResultObserveResponse(observation, encoded)
	} else {
		observation.observeResponse(encoded)
	}
	return
}

func auditResultPanic(value any) any {
	if value == nil {
		return nil
	}
	return fmt.Sprintf("%T: %v", value, value)
}

// Frozen from audit.go at f78523a, before the simple-result optimization.
// Keep the decoder's permissive behavior and malformed-input panics intact.
func legacyAuditResultObserveResponse(observation *operationAuditObservation, encoded []byte) {
	if observation == nil {
		return
	}
	if operationTag, ok := monitorResponseTag(encoded); ok &&
		operationTag == ldapwire.ApplicationSearchResultEntry {
		observation.mu.Lock()
		observation.entries++
		observation.mu.Unlock()
		return
	}
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil || len(packet.Children) < 2 {
		return
	}
	operation := packet.Children[1]
	if len(operation.Children) == 0 {
		return
	}
	result := operation.Children[0]
	if result.ClassType != ber.ClassUniversal ||
		result.TagType != ber.TypePrimitive ||
		result.Tag != ber.TagEnumerated {
		return
	}
	code, err := ber.ParseInt64(result.Data.Bytes())
	if err != nil {
		return
	}
	diagnostic := ""
	if len(operation.Children) > 2 {
		diagnostic = operation.Children[2].Data.String()
	}
	var referrals []string
	for _, child := range operation.Children[3:] {
		if child.ClassType == ber.ClassContext && child.Tag == 3 {
			for _, referral := range child.Children {
				referrals = append(referrals, referral.Data.String())
			}
		}
	}
	responseControls := legacyAuditResultDecodeControls(packet)
	observation.mu.Lock()
	observation.result = int(code)
	observation.hasResult = true
	observation.diagnostic = diagnostic
	observation.referrals = referrals
	observation.responseControls = responseControls
	observation.mu.Unlock()
}

func legacyAuditResultDecodeControls(packet *ber.Packet) []ldapwire.Control {
	if packet == nil || len(packet.Children) < 3 {
		return nil
	}
	wrapper := packet.Children[2]
	if wrapper.ClassType != ber.ClassContext ||
		wrapper.TagType != ber.TypeConstructed || wrapper.Tag != 0 {
		return nil
	}
	controls := make([]ldapwire.Control, 0, len(wrapper.Children))
	for _, encoded := range wrapper.Children {
		if len(encoded.Children) < 1 || len(encoded.Children) > 3 {
			continue
		}
		control := ldapwire.Control{OID: encoded.Children[0].Data.String()}
		position := 1
		if position < len(encoded.Children) &&
			encoded.Children[position].ClassType == ber.ClassUniversal &&
			encoded.Children[position].Tag == ber.TagBoolean {
			value := encoded.Children[position].Data.Bytes()
			control.Critical = len(value) == 1 && value[0] != 0
			position++
		}
		if position < len(encoded.Children) {
			control.Value = bytes.Clone(encoded.Children[position].Data.Bytes())
			control.HasValue = true
		}
		controls = append(controls, control)
	}
	return controls
}

func legacyAuditResultCode(encoded []byte) (int, bool) {
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil || len(packet.Children) < 2 {
		return 0, false
	}
	operation := packet.Children[1]
	if len(operation.Children) == 0 {
		return 0, false
	}
	result := operation.Children[0]
	if result.ClassType != ber.ClassUniversal ||
		result.TagType != ber.TypePrimitive ||
		result.Tag != ber.TagEnumerated {
		return 0, false
	}
	code, err := ber.ParseInt64(result.Data.Bytes())
	if err != nil {
		return 0, false
	}
	return int(code), true
}
