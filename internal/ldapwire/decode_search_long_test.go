package ldapwire

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"testing/iotest"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type searchLongLengthTarget struct {
	tag     byte
	content func(int) []byte
	wrap    func([]byte) []byte
}

func searchLongTestFrame(fields [][]byte) []byte {
	return searchTestTLV(0x30, []byte{0x02, 1, 1}, searchTestTLV(0x63, fields...))
}

func searchLongLengthTargets() map[string]searchLongLengthTarget {
	text := func(n int) []byte { return bytes.Repeat([]byte("x"), n) }
	binary := func(n int) []byte { return bytes.Repeat([]byte{0, 0xff, 0x80, 0x7f}, (n+3)/4)[:n] }
	field := func(index int, element []byte) []byte {
		fields := searchTestFields()
		fields[index] = element
		return searchLongTestFrame(fields)
	}
	equality := func(value []byte) []byte {
		return bytes.Join([][]byte{searchTestTLV(0x04, []byte("uid")), searchTestTLV(0x04, value)}, nil)
	}
	operation := func(n int) []byte {
		fields := searchTestFields()
		fields[0] = searchTestTLV(0x04, text(n))
		return bytes.Join(fields, nil)
	}
	return map[string]searchLongLengthTarget{
		"base-dn": {0x04, text, func(element []byte) []byte { return field(0, element) }},
		"equality-attribute": {0x04, text, func(element []byte) []byte {
			return field(6, searchTestTLV(0xa3, element, searchTestTLV(0x04, []byte("alice"))))
		}},
		"equality-value": {0x04, binary, func(element []byte) []byte {
			return field(6, searchTestTLV(0xa3, searchTestTLV(0x04, []byte("uid")), element))
		}},
		"presence": {0x87, text, func(element []byte) []byte { return field(6, element) }},
		"selected-attribute": {0x04, text, func(element []byte) []byte {
			return field(7, searchTestTLV(0x30, searchTestTLV(0x04, []byte("*")), element, searchTestTLV(0x04, []byte("+"))))
		}},
		"equality": {0xa3, func(n int) []byte { return equality(binary(n)) }, func(element []byte) []byte {
			return field(6, element)
		}},
		"selection": {0x30, func(n int) []byte { return searchTestTLV(0x04, text(n)) }, func(element []byte) []byte {
			return field(7, element)
		}},
		"operation": {0x63, operation, func(element []byte) []byte {
			return searchTestTLV(0x30, []byte{0x02, 1, 1}, element)
		}},
		"envelope": {0x30, func(n int) []byte {
			return bytes.Join([][]byte{{0x02, 1, 1}, searchTestTLV(0x63, operation(n))}, nil)
		}, func(element []byte) []byte { return element }},
	}
}

func searchLongBoundaryContent(t testing.TB, target searchLongLengthTarget, length int) []byte {
	t.Helper()
	// Include child headers when placing a constructed element at an exact boundary.
	for padding := range length + 1 {
		if content := target.content(padding); len(content) == length {
			return content
		}
	}
	t.Fatalf("cannot construct tag %x with %d content bytes", target.tag, length)
	return nil
}

func searchLongHeaderLength(element []byte) int {
	if element[1]&0x80 != 0 {
		return 2 + int(element[1]&0x7f)
	}
	return 2
}

func checkSearchLongFrame(t testing.TB, frame []byte, eligible bool) Message {
	t.Helper()
	got, ok := decodeSimpleSearchFrame(frame)
	if ok != eligible {
		t.Fatalf("fast path = %v, want %v (frame length %d)", ok, eligible, len(frame))
	}
	if !ok {
		if !reflect.DeepEqual(got, Message{}) {
			t.Fatalf("fallback returned partial message: %#v", got)
		}
		return got
	}
	want, size, err := readSearchMessageReference(bytes.NewReader(frame), int64(len(frame)), 0, func() int { return 0 })
	if err != nil || size != len(frame) || !reflect.DeepEqual(got, want) {
		t.Fatalf("fast path %#v, reference %#v, size %d, error %v", got, want, size, err)
	}
	return got
}

func TestSearchLongLengthBoundaries(t *testing.T) {
	for name, target := range searchLongLengthTargets() {
		for _, length := range []int{126, 127, 128, 129, 254, 255, 256, 257} {
			t.Run(fmt.Sprintf("%s/%d", name, length), func(t *testing.T) {
				content := searchLongBoundaryContent(t, target, length)
				frame := target.wrap(searchTestTLV(target.tag, content))
				checkSearchLongFrame(t, frame, true)
				contentLength := uint64(len(frame) - searchLongHeaderLength(frame))
				for _, depth := range []int{-1, 0, 1, DefaultMaxFilterDepth} {
					compareSearchDecode(t, frame, int64(len(frame)), contentLength, depth)
				}
				compareSearchDecode(t, frame, int64(len(frame)-1), contentLength, 0)
				compareSearchDecode(t, frame, int64(len(frame)), contentLength-1, 0)
			})
		}
	}
}

func TestSearchLongOuterOnly(t *testing.T) {
	target := searchLongLengthTargets()["envelope"]
	for _, wireLength := range []int{133, 135} {
		t.Run(fmt.Sprint(wireLength), func(t *testing.T) {
			content := searchLongBoundaryContent(t, target, wireLength-3)
			frame := searchTestTLV(0x30, content)
			// The fixed three-byte message ID precedes an entirely short-form operation.
			if len(frame) != wireLength || frame[1] != 0x81 || content[3] != 0x63 || content[4] >= 0x80 {
				t.Fatal("fixture must use long length only for the outer envelope")
			}
			checkSearchLongFrame(t, frame, true)
			for _, depth := range []int{-1, 0, 1} {
				compareSearchDecode(t, frame, int64(wireLength), uint64(len(content)), depth)
			}
		})
	}
}

// These fixtures can also seed FuzzReadSearchMessageReference.
func searchLongDecodeFixtures() map[string][]byte {
	frames := make(map[string][]byte)
	for name, target := range searchLongLengthTargets() {
		frames[name] = target.wrap(searchTestTLV(target.tag, target.content(256)))
	}
	fields := searchTestFields()
	fields[0] = searchTestTLV(0x04, []byte("uid=alice,"), bytes.Repeat([]byte("ou=engineering,"), 20), []byte("dc=example,dc=com"))
	attribute := searchTestTLV(0x04, bytes.Repeat([]byte("a"), 128))
	fields[6] = searchTestTLV(0xa3, attribute, searchTestTLV(0x04, bytes.Repeat([]byte{0, 0xff, 0x80, 0x7f}, 64)))
	fields[7] = searchTestTLV(0x30, []byte{0x04, 0}, searchTestTLV(0x04, []byte("*")), attribute,
		searchTestTLV(0x04, []byte("+")), searchTestTLV(0x04, bytes.Repeat([]byte("b"), 256)), attribute)
	frames["all-fields-equality"] = searchLongTestFrame(fields)
	fields[6] = searchTestTLV(0x87, bytes.Repeat([]byte("a"), 256))
	frames["all-fields-presence"] = searchLongTestFrame(fields)
	fields[7] = searchTestTLV(0x30)
	frames["empty-selection"] = searchLongTestFrame(fields)
	fields[6] = searchTestTLV(0xa3, attribute, searchTestTLV(0x04))
	frames["empty-assertion-selection"] = searchLongTestFrame(fields)
	fields[7] = searchTestTLV(0x30, bytes.Repeat(searchTestTLV(0x04, []byte("cn")), 256))
	frames["many-selected-attributes"] = searchLongTestFrame(fields)
	return frames
}

func TestSearchLongStreamAndOwnership(t *testing.T) {
	for name, frame := range searchLongDecodeFixtures() {
		t.Run(name, func(t *testing.T) {
			got := checkSearchLongFrame(t, frame, true)
			want, _, err := readSearchMessageReference(bytes.NewReader(frame), int64(len(frame)), 0, func() int { return 0 })
			if err != nil {
				t.Fatal(err)
			}
			stream := bytes.NewReader(bytes.Repeat(frame, 2))
			for index := range 2 {
				calls := 0
				message, size, err := ReadMessageWithDynamicFilterDepthAndSize(iotest.OneByteReader(stream), int64(len(frame)), 0, func() int {
					calls++
					if stream.Len() != (1-index)*len(frame) {
						t.Fatal("provider called before complete frame or after reading ahead")
					}
					return index
				})
				if err != nil || calls != 1 || size != len(frame) || !reflect.DeepEqual(message, want) {
					t.Fatalf("stream decode %#v, size %d, calls %d, error %v; want %#v", message, size, calls, err, want)
				}
			}
			clear(frame)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("decoded search fields alias input frame")
			}
		})
	}
}

func TestSearchLongBERLimits(t *testing.T) {
	oldLength, oldDepth := ber.MaxPacketLengthBytes, ber.MaxNestingDepth
	t.Cleanup(func() { ber.MaxPacketLengthBytes, ber.MaxNestingDepth = oldLength, oldDepth })
	fixtures := searchLongDecodeFixtures()
	for _, name := range []string{"all-fields-equality", "all-fields-presence", "empty-selection"} {
		frame := fixtures[name]
		contentLength := int64(len(frame) - searchLongHeaderLength(frame))
		for _, maxLength := range []int64{-1, 0, 1, 127, 128, 255, 256, contentLength - 1, contentLength, contentLength + 1} {
			for _, maxDepth := range []int{-1, 0, 1, 2, 3, 4, 5} {
				t.Run(fmt.Sprintf("%s/length-%d/depth-%d", name, maxLength, maxDepth), func(t *testing.T) {
					ber.MaxPacketLengthBytes, ber.MaxNestingDepth = maxLength, maxDepth
					for _, depth := range []int{-1, 0, 1} {
						compareSearchDecode(t, frame, int64(len(frame)), 0, depth)
					}
					// The decoder conservatively falls back below depth 4, even for empty selection.
					eligible := (maxLength <= 0 || maxLength >= contentLength) && (maxDepth <= 0 || maxDepth > 3)
					checkSearchLongFrame(t, frame, eligible)
				})
			}
		}
	}
}

func searchLongLengthEdgeFrames() map[string][]byte {
	frames := make(map[string][]byte)
	for name, target := range searchLongLengthTargets() {
		content := target.content(256)
		valid := searchTestTLV(target.tag, content)
		width := int(valid[1] & 0x7f)
		frames[name+"/nonminimal-length"] = target.wrap(append([]byte{target.tag, 0x80 | byte(width+1), 0}, valid[2:]...))
		frames[name+"/indefinite-length"] = target.wrap(bytes.Join([][]byte{{target.tag, 0x80}, content, {0, 0}}, nil))
		frames[name+"/high-tag"] = target.wrap(append([]byte{target.tag&0xe0 | 0x1f, target.tag & 0x1f}, valid[1:]...))
		tooLong := searchTestTLV(target.tag, append(bytes.Clone(content), 0))
		frames[name+"/beyond-parent"] = target.wrap(tooLong[:len(tooLong)-1])
		frames[name+"/uint64-max"] = target.wrap(append([]byte{target.tag, 0x88}, bytes.Repeat([]byte{0xff}, 8)...))
		frames[name+"/negative-int64"] = target.wrap([]byte{target.tag, 0x88, 0x80, 0, 0, 0, 0, 0, 0, 0})
		frames[name+"/nine-octets"] = target.wrap([]byte{target.tag, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0})
		frames[name+"/reserved-length"] = target.wrap([]byte{target.tag, 0xff})
		for _, cut := range []int{0, 1, 2, searchLongHeaderLength(valid) - 1, searchLongHeaderLength(valid), len(valid) - 1} {
			if cut == 0 && name == "selected-attribute" {
				continue // Removing a complete selected attribute leaves a valid selection.
			}
			frames[fmt.Sprintf("%s/truncated-%d", name, cut)] = target.wrap(valid[:cut])
		}
	}
	fields := searchTestFields()
	fields[0] = searchTestTLV(0x04, bytes.Repeat([]byte("x"), 256))
	for index := 1; index <= 5; index++ {
		changed := append([][]byte(nil), fields...)
		changed[index] = append([]byte{fields[index][0], 0x81}, fields[index][1:]...)
		frames[fmt.Sprintf("nonminimal-scalar-%d", index)] = searchLongTestFrame(changed)
	}
	operation := searchTestTLV(0x63, fields...)
	frames["nonminimal-id"] = searchTestTLV(0x30, []byte{0x02, 0x81, 1, 1}, operation)
	frames["controls"] = searchTestTLV(0x30, []byte{0x02, 1, 1}, operation, []byte{0xa0, 0})
	frames["extra-field"] = searchLongTestFrame(append(fields, []byte{0x04, 0}))
	fields[6] = searchTestTLV(0xa0, fields[6])
	frames["nested-filter"] = searchLongTestFrame(fields)
	return frames
}

func TestSearchLongLengthFallback(t *testing.T) {
	next := searchLongTestFrame(searchTestFields())
	frames := searchLongLengthEdgeFrames()
	for name, target := range searchLongLengthTargets() {
		content := searchLongBoundaryContent(t, target, 127)
		frames[name+"/long-form-short-length"] = target.wrap(append([]byte{target.tag, 0x81, 127}, content...))
	}
	for name, frame := range frames {
		t.Run(name, func(t *testing.T) {
			checkSearchLongFrame(t, frame, false)
			for _, depth := range []int{-1, 0, 1, DefaultMaxFilterDepth} {
				compareSearchDecode(t, frame, 4096, 0, depth)
				compareSearchDecode(t, append(bytes.Clone(frame), next...), 4096, 0, depth)
			}
		})
	}
}
