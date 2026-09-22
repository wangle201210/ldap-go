package ldapwire

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"
	"testing/iotest"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func bindCompareDecodeFixtures(tb testing.TB) map[string][]byte {
	tb.Helper()
	fixtures := make(map[string][]byte)
	for name, request := range map[string]Request{
		"Bind":          BindRequest{Version: 3, Name: "uid=alice,dc=example", Authentication: Authentication{Simple: []byte("secret")}},
		"AnonymousBind": BindRequest{Version: 3},
		"EmptyPassword": BindRequest{Version: 3, Name: "uid=alice"},
		"BinaryBind":    BindRequest{Version: 2, Name: "\x00\xff\x80", Authentication: Authentication{Simple: []byte{0, 0xff, 0x80}}},
		"SASL": BindRequest{Version: 3, Authentication: Authentication{
			IsSASL: true, SASLMechanism: "PLAIN", HasSASLCredentials: true, SASLCredentials: []byte("\x00alice\x00secret"),
		}},
		"LongBind":      BindRequest{Version: 3, Authentication: Authentication{Simple: bytes.Repeat([]byte("x"), 256)}},
		"Compare":       CompareRequest{DN: "uid=alice,dc=example", Attribute: "uid", Assertion: []byte("alice")},
		"EmptyCompare":  CompareRequest{Attribute: "uid"},
		"BinaryCompare": CompareRequest{DN: "\x00\xff\x80", Attribute: "\xff\x00", Assertion: []byte{0, 0xff, 0x80}},
		"LongCompare":   CompareRequest{Attribute: "uid", Assertion: bytes.Repeat([]byte("x"), 256)},
	} {
		message := Message{ID: 1234, Request: request}
		frame, err := EncodeRequestMessage(message)
		if err != nil {
			tb.Fatal(err)
		}
		fixtures[name] = frame
		if name == "Bind" || name == "Compare" {
			message.Controls = []Control{{OID: "1.2.3", Critical: true, HasValue: true, Value: []byte{0, 0xff}}}
			frame, err = EncodeRequestMessage(message)
			if err != nil {
				tb.Fatal(err)
			}
			fixtures[name+"Controls"] = frame
		}
	}
	return fixtures
}

func bindCompareTestFields(tag byte) [][]byte {
	if tag == 0x60 {
		return [][]byte{{0x02, 1, 3}, searchTestTLV(0x04, []byte("uid=alice")), searchTestTLV(0x80, []byte("secret"))}
	}
	return [][]byte{
		searchTestTLV(0x04, []byte("uid=alice")),
		searchTestTLV(0x30, searchTestTLV(0x04, []byte("uid")), searchTestTLV(0x04, []byte("alice"))),
	}
}

func bindCompareTestFrame(tag byte, fields ...[]byte) []byte {
	return searchTestTLV(0x30, []byte{0x02, 1, 1}, searchTestTLV(tag, fields...))
}

func checkShortBindCompareFrame(t testing.TB, frame []byte, eligible bool) {
	t.Helper()
	got, ok := decodeShortBindCompareFrame(frame)
	if ok != eligible {
		t.Fatalf("frame %x: fast path = %v, want %v", frame, ok, eligible)
	}
	if !ok {
		if !reflect.DeepEqual(got, Message{}) {
			t.Fatalf("fallback returned partial message: %#v", got)
		}
		return
	}
	want, size, err := readSearchMessageReference(bytes.NewReader(frame), 4096, 0, func() int { return 0 })
	if err != nil || size != len(frame) || !reflect.DeepEqual(got, want) {
		t.Fatalf("frame %x: fast path %#v, reference %#v, size %d, error %v", frame, got, want, size, err)
	}
}

func TestShortBindCompareFrameEligibility(t *testing.T) {
	for name, frame := range bindCompareDecodeFixtures(t) {
		t.Run(name, func(t *testing.T) {
			eligible := name != "SASL" && name != "LongBind" && name != "LongCompare" && name != "BindControls" && name != "CompareControls"
			checkShortBindCompareFrame(t, frame, eligible)
			for _, depth := range []int{-1, 0, DefaultMaxFilterDepth} {
				compareSearchDecode(t, frame, 4096, 0, depth)
			}
		})
	}
	for name, frame := range searchDecodeFixtures(t) {
		t.Run("Search/"+name, func(t *testing.T) {
			checkShortBindCompareFrame(t, frame, false)
		})
	}
}

func TestShortBindCompareIntegers(t *testing.T) {
	for _, tc := range []struct {
		value       []byte
		id, version bool
	}{
		{nil, false, false}, {[]byte{0}, false, true},
		{[]byte{1}, true, true}, {[]byte{2}, true, true}, {[]byte{3}, true, true}, {[]byte{4}, true, true},
		{[]byte{0x7f}, true, true}, {[]byte{0x80}, false, false}, {[]byte{0xff}, false, false},
		{[]byte{0, 0x80}, true, true}, {[]byte{0, 0, 1}, true, true},
		{[]byte{0x7f, 0xff, 0xff, 0xff}, true, true}, {[]byte{0x80, 0, 0, 0}, false, false},
		{[]byte{0, 0x80, 0, 0, 0}, false, false}, {[]byte{0xff, 0x7f, 0xff, 0xff, 0xff}, false, false},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 1}, true, true},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false, false},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 1}, false, false},
	} {
		for _, integerTag := range []byte{0x02, 0x0a} {
			integer := searchTestTLV(integerTag, tc.value)
			for _, tag := range []byte{0x60, 0x6e} {
				frame := searchTestTLV(0x30, integer, searchTestTLV(tag, bindCompareTestFields(tag)...))
				checkShortBindCompareFrame(t, frame, integerTag == 0x02 && tc.id)
				compareSearchDecode(t, frame, 4096, 0, -1)
			}
			fields := bindCompareTestFields(0x60)
			fields[0] = integer
			frame := bindCompareTestFrame(0x60, fields...)
			checkShortBindCompareFrame(t, frame, integerTag == 0x02 && tc.version)
			compareSearchDecode(t, frame, 4096, 0, -1)
		}
	}
}

// All of these shapes must fall back, including BER encodings the packet path accepts.
func bindCompareDecodeEdgeFrames() map[string][]byte {
	frames := make(map[string][]byte)
	for _, tag := range []byte{0x60, 0x6e} {
		fields := bindCompareTestFields(tag)
		operation := searchTestTLV(tag, fields...)
		id := []byte{0x02, 1, 1}
		prefix := fmt.Sprintf("%x/", tag)
		for name, controls := range map[string][]byte{
			"empty-controls":         {0xa0, 0},
			"wrong-controls-wrapper": {0x30, 0},
			"malformed-control":      {0xa0, 2, 0x04, 0},
			"invalid-control-value":  {0xa0, 8, 0x30, 6, 0x04, 1, 'x', 0x02, 1, 1},
			"malformed-control-ber":  {0xa0, 1, 0x30},
		} {
			frames[prefix+name] = searchTestTLV(0x30, id, operation, controls)
		}
		frames[prefix+"extra-envelope-child"] = searchTestTLV(0x30, id, operation, []byte{0xa0, 0, 0x04, 0})
		frames[prefix+"missing-operation"] = searchTestTLV(0x30, id)
		frames[prefix+"missing-field"] = bindCompareTestFrame(tag, fields[:len(fields)-1]...)
		frames[prefix+"extra-field"] = bindCompareTestFrame(tag, append(fields, []byte{0x04, 0})...)
		for index := -2; index < len(fields); index++ {
			element := operation
			if index == -1 {
				element = id
			} else if index >= 0 {
				element = fields[index]
			}
			for name, replacement := range map[string][]byte{
				"wrong-class":         searchTestTLV(element[0]^0x40, element[2:]),
				"wrong-type":          searchTestTLV(element[0]^0x20, element[2:]),
				"high-tag":            append([]byte{element[0]&0xe0 | 0x1f, element[0] & 0x1f}, element[1:]...),
				"long-length":         append([]byte{element[0], 0x81}, element[1:]...),
				"leading-zero-length": append([]byte{element[0], 0x82, 0}, element[1:]...),
				"indefinite-length":   bytes.Join([][]byte{{element[0], 0x80}, element[2:], {0, 0}}, nil),
				"truncated-value":     element[:len(element)-1],
			} {
				var frame []byte
				switch index {
				case -2:
					frame = searchTestTLV(0x30, id, replacement)
				case -1:
					frame = searchTestTLV(0x30, replacement, operation)
				default:
					changed := append([][]byte(nil), fields...)
					changed[index] = replacement
					frame = bindCompareTestFrame(tag, changed...)
				}
				frames[fmt.Sprintf("%sfield-%d/%s", prefix, index, name)] = frame
			}
		}
		frame := bindCompareTestFrame(tag, fields...)
		frames[prefix+"nonminimal-outer-length"] = append([]byte{0x30, 0x81}, frame[1:]...)
		frames[prefix+"trailing-frame"] = append(bytes.Clone(frame), frame...)
	}
	for name, authentication := range map[string][]byte{
		"unknown-auth":         {0x81, 0},
		"constructed-simple":   {0xa0, 0},
		"sasl-no-credentials":  searchTestTLV(0xa3, searchTestTLV(0x04, []byte("EXTERNAL"))),
		"sasl-empty-mechanism": {0xa3, 2, 0x04, 0},
	} {
		fields := bindCompareTestFields(0x60)
		fields[2] = authentication
		frames[name] = bindCompareTestFrame(0x60, fields...)
	}
	for name, assertion := range map[string][]byte{
		"empty-attribute":       searchTestTLV(0x30, []byte{0x04, 0}, []byte{0x04, 0}),
		"missing-assertion":     searchTestTLV(0x30, searchTestTLV(0x04, []byte("uid"))),
		"extra-assertion-field": searchTestTLV(0x30, searchTestTLV(0x04, []byte("uid")), []byte{0x04, 0}, []byte{0x04, 0}),
		"invalid-attribute":     searchTestTLV(0x30, []byte{0x02, 1, 1}, []byte{0x04, 0}),
		"invalid-assertion":     searchTestTLV(0x30, searchTestTLV(0x04, []byte("uid")), []byte{0x02, 1, 1}),
		"long-attribute-length": {0x30, 6, 0x04, 0x81, 1, 'x', 0x04, 0},
		"long-assertion-length": {0x30, 6, 0x04, 1, 'x', 0x04, 0x81, 0},
		"high-attribute-tag":    {0x30, 6, 0x1f, 4, 1, 'x', 0x04, 0},
		"high-assertion-tag":    {0x30, 6, 0x04, 1, 'x', 0x1f, 4, 0},
	} {
		fields := bindCompareTestFields(0x6e)
		fields[1] = assertion
		frames[name] = bindCompareTestFrame(0x6e, fields...)
	}
	return frames
}

func TestShortBindCompareBERCompatibility(t *testing.T) {
	for name, frame := range bindCompareDecodeEdgeFrames() {
		t.Run(name, func(t *testing.T) {
			checkShortBindCompareFrame(t, frame, false)
			for _, depth := range []int{-1, 0, DefaultMaxFilterDepth} {
				compareSearchDecode(t, frame, 4096, 0, depth)
			}
		})
	}
}

func TestShortBindCompareLengthBoundary(t *testing.T) {
	for _, tag := range []byte{0x60, 0x6e} {
		for _, contentLength := range []int{126, 127, 128, 129} {
			fields := bindCompareTestFields(tag)
			index := 0
			if tag == 0x60 {
				index = 1
			}
			fields[index] = []byte{0x04, 0}
			empty := bindCompareTestFrame(tag, fields...)
			fields[index] = searchTestTLV(0x04, bytes.Repeat([]byte("x"), contentLength-(len(empty)-2)))
			frame := bindCompareTestFrame(tag, fields...)
			headerLength := 2
			if frame[1]&0x80 != 0 {
				headerLength += int(frame[1] & 0x7f)
			}
			if len(frame)-headerLength != contentLength {
				t.Fatal("incorrect boundary fixture")
			}
			checkShortBindCompareFrame(t, frame, contentLength < 128)
			compareSearchDecode(t, frame, int64(len(frame)), uint64(contentLength), -1)
			compareSearchDecode(t, frame, int64(len(frame)-1), uint64(contentLength), -1)
			compareSearchDecode(t, frame, int64(len(frame)), uint64(contentLength-1), -1)
		}
	}
}

func TestShortBindCompareLimits(t *testing.T) {
	fixtures := bindCompareDecodeFixtures(t)
	for _, frame := range fixtures {
		headerLength := 2
		if frame[1]&0x80 != 0 {
			headerLength += int(frame[1] & 0x7f)
		}
		contentLength := len(frame) - headerLength
		for _, maxSize := range []int64{-1, 0, 1, int64(len(frame) - 1), int64(len(frame)), 4096} {
			for _, maxContent := range []uint64{0, 1, uint64(contentLength - 1), uint64(contentLength), 4096} {
				for _, depth := range []int{-1, 0, DefaultMaxFilterDepth} {
					compareSearchDecode(t, frame, maxSize, maxContent, depth)
				}
			}
		}
	}
	oldLength, oldDepth := ber.MaxPacketLengthBytes, ber.MaxNestingDepth
	t.Cleanup(func() { ber.MaxPacketLengthBytes, ber.MaxNestingDepth = oldLength, oldDepth })
	for name, frame := range fixtures {
		for _, maxLength := range []int64{-1, 0, 1, int64(len(frame) - 3), int64(len(frame) - 2)} {
			for _, maxDepth := range []int{-1, 0, 1, 2, 3, 4, 5} {
				ber.MaxPacketLengthBytes, ber.MaxNestingDepth = maxLength, maxDepth
				compareSearchDecode(t, frame, 4096, 0, -1)
				if name == "Bind" || name == "Compare" {
					depth := 2
					if name == "Compare" {
						depth = 3
					}
					checkShortBindCompareFrame(t, frame, (maxLength <= 0 || maxLength >= int64(len(frame)-2)) && (maxDepth <= 0 || maxDepth > depth))
				}
			}
		}
	}
}

func TestShortBindCompareByteMutations(t *testing.T) {
	fixtures := bindCompareDecodeFixtures(t)
	for _, name := range []string{"Bind", "Compare", "BindControls", "CompareControls", "SASL"} {
		t.Run(name, func(t *testing.T) {
			frame := fixtures[name]
			for offset := range frame {
				checkShortBindCompareFrame(t, frame[:offset], false)
				compareSearchDecode(t, frame[:offset], 4096, 0, -1)
				mutated := bytes.Clone(frame)
				for value := 0; value < 256; value++ {
					mutated[offset] = byte(value)
					compareSearchDecode(t, mutated, 4096, 0, -1)
				}
			}
		})
	}
}

func TestShortBindCompareStreamAndOwnership(t *testing.T) {
	for name, frame := range bindCompareDecodeFixtures(t) {
		t.Run(name, func(t *testing.T) {
			stream := bytes.NewReader(bytes.Repeat(frame, 3))
			calls := 0
			for index := range 3 {
				got, size, err := ReadMessageWithDynamicFilterDepthAndSize(iotest.OneByteReader(stream), 4096, 0, func() int {
					calls++
					if stream.Len() != (2-index)*len(frame) {
						t.Fatal("provider called before complete frame or after reading ahead")
					}
					return index - 1
				})
				want, _, referenceErr := readSearchMessageReference(bytes.NewReader(frame), 4096, 0, func() int { return index - 1 })
				if err != nil || referenceErr != nil || calls != index+1 || size != len(frame) || !reflect.DeepEqual(got, want) {
					t.Fatalf("stream decode = %#v, %d, %v, calls %d; reference %#v, %v", got, size, err, calls, want, referenceErr)
				}
			}
			compareSearchDecode(t, nil, 4096, 0, -1)
			if got, ok := decodeShortBindCompareFrame(frame); ok {
				want, _, err := readSearchMessageReference(bytes.NewReader(frame), 4096, 0, func() int { return 0 })
				if err != nil {
					t.Fatal(err)
				}
				clear(frame)
				if !reflect.DeepEqual(got, want) {
					t.Fatal("decoded fields alias the input frame")
				}
			}
		})
	}
}

func TestShortBindCompareProviderInvocation(t *testing.T) {
	for _, tag := range []byte{0x60, 0x6e} {
		frame := bindCompareTestFrame(tag, bindCompareTestFields(tag)...)
		for _, tc := range []struct {
			name  string
			data  []byte
			calls int
		}{
			{"success", frame, 1},
			{"frame-error", frame[:len(frame)-1], 0},
			{"ber-error", searchTestTLV(0x30, []byte{0x02, 1, 1}, []byte{tag, 1, 0x04}), 0},
			{"request-error", bindCompareTestFrame(tag), 1},
			{"controls-error", searchTestTLV(0x30, frame[2:], []byte{0xa0, 2, 0x04, 0}), 1},
		} {
			t.Run(fmt.Sprintf("%x/%s", tag, tc.name), func(t *testing.T) {
				calls := 0
				_, _, _ = ReadMessageWithDynamicFilterDepthAndSize(bytes.NewReader(tc.data), 4096, 0, func() int { calls++; return -1 })
				if calls != tc.calls {
					t.Fatalf("provider calls = %d, want %d", calls, tc.calls)
				}
				compareSearchDecode(t, tc.data, 4096, 0, -1)
			})
		}
		got, size, err := ReadMessageWithDynamicFilterDepthAndSize(bytes.NewReader(frame), 4096, 0, nil)
		want, referenceSize, referenceErr := readSearchMessageReference(bytes.NewReader(frame), 4096, 0, func() int { return DefaultMaxFilterDepth })
		if err != nil || referenceErr != nil || size != referenceSize || !reflect.DeepEqual(got, want) {
			t.Fatalf("nil provider: %#v, %d, %v; want %#v, %d, %v", got, size, err, want, referenceSize, referenceErr)
		}
		_, size, err = ReadMessageWithDynamicFilterDepthAndSize(bytes.NewReader(nil), 4096, 0, func() int { t.Fatal("provider called at EOF"); return 0 })
		if size != 0 || err != io.EOF {
			t.Fatalf("EOF: size %d, error %v", size, err)
		}
	}
}

func FuzzReadBindCompareMessageReference(f *testing.F) {
	for _, frame := range bindCompareDecodeFixtures(f) {
		f.Add(frame, int8(-1))
	}
	for _, frame := range bindCompareDecodeEdgeFrames() {
		f.Add(frame, int8(0))
	}
	f.Fuzz(func(t *testing.T, frame []byte, depth int8) {
		compareSearchDecode(t, frame, 64<<10, 32<<10, int(depth))
	})
}
