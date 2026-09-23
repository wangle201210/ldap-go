package ldapwire

import (
	"bytes"
	"fmt"
	"testing"
)

type bindCompareLengthTarget struct {
	tag     byte
	content []byte
	wrap    func([]byte) []byte
}

func bindCompareLongLengthTargets() map[string]bindCompareLengthTarget {
	value := bytes.Repeat([]byte{0, 0xff, 0x80, 0x7f}, 64)
	version := []byte{0x02, 1, 3}
	name := searchTestTLV(0x04, value)
	password := searchTestTLV(0x80, value)
	attribute := searchTestTLV(0x04, []byte("uid"))
	assertionValue := searchTestTLV(0x04, value)
	assertionContent := bytes.Join([][]byte{attribute, assertionValue}, nil)
	assertion := searchTestTLV(0x30, assertionContent)
	envelope := func(operation []byte) []byte {
		return searchTestTLV(0x30, []byte{0x02, 1, 1}, operation)
	}
	return map[string]bindCompareLengthTarget{
		"bind-name": {0x04, value, func(element []byte) []byte {
			return bindCompareTestFrame(0x60, version, element, password)
		}},
		"bind-password": {0x80, value, func(element []byte) []byte {
			return bindCompareTestFrame(0x60, version, name, element)
		}},
		"bind-operation": {0x60, bytes.Join([][]byte{version, name, password}, nil), envelope},
		"compare-dn": {0x04, value, func(element []byte) []byte {
			return bindCompareTestFrame(0x6e, element, assertion)
		}},
		"compare-attribute": {0x04, value, func(element []byte) []byte {
			return bindCompareTestFrame(0x6e, name, searchTestTLV(0x30, element, assertionValue))
		}},
		"compare-value": {0x04, value, func(element []byte) []byte {
			return bindCompareTestFrame(0x6e, name, searchTestTLV(0x30, attribute, element))
		}},
		"compare-assertion": {0x30, assertionContent, func(element []byte) []byte {
			return bindCompareTestFrame(0x6e, name, element)
		}},
		"compare-operation": {0x6e, bytes.Join([][]byte{name, assertion}, nil), envelope},
	}
}

func TestBindCompareLongLengthBoundaries(t *testing.T) {
	targets := bindCompareLongLengthTargets()
	for _, name := range []string{"bind-name", "bind-password", "compare-dn", "compare-attribute", "compare-value"} {
		target := targets[name]
		for _, length := range []int{0, 1, 126, 127, 128, 129, 254, 255, 256, 257, 65535, 65536} {
			t.Run(fmt.Sprintf("%s/%d", name, length), func(t *testing.T) {
				frame := target.wrap(searchTestTLV(target.tag, bytes.Repeat([]byte("x"), length)))
				checkBindCompareFrame(t, frame, name != "compare-attribute" || length != 0)
				headerLength := 2
				if frame[1]&0x80 != 0 {
					headerLength += int(frame[1] & 0x7f)
				}
				contentLength := uint64(len(frame) - headerLength)
				compareSearchDecode(t, frame, int64(len(frame)), contentLength, -1)
				compareSearchDecode(t, frame, int64(len(frame)-1), contentLength, -1)
				compareSearchDecode(t, frame, int64(len(frame)), contentLength-1, -1)
			})
		}
	}
}

func bindCompareLongLengthEdgeFrames() map[string][]byte {
	frames := make(map[string][]byte)
	for name, target := range bindCompareLongLengthTargets() {
		valid := searchTestTLV(target.tag, target.content)
		width := int(valid[1] & 0x7f)
		frames[name+"/nonminimal-length"] = target.wrap(
			append([]byte{target.tag, 0x80 | byte(width+1), 0}, valid[2:]...),
		)
		frames[name+"/indefinite-length"] = target.wrap(bytes.Join(
			[][]byte{{target.tag, 0x80}, target.content, {0, 0}}, nil,
		))
		frames[name+"/high-tag"] = target.wrap(append(
			[]byte{target.tag&0xe0 | 0x1f, target.tag & 0x1f}, valid[1:]...,
		))
		tooLong := searchTestTLV(target.tag, append(bytes.Clone(target.content), 0))
		frames[name+"/beyond-parent"] = target.wrap(tooLong[:len(tooLong)-1])
		frames[name+"/uint64-max"] = target.wrap(append([]byte{target.tag, 0x88}, bytes.Repeat([]byte{0xff}, 8)...))
		frames[name+"/negative-int64"] = target.wrap([]byte{target.tag, 0x88, 0x80, 0, 0, 0, 0, 0, 0, 0})
		frames[name+"/nine-octets"] = target.wrap([]byte{target.tag, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0})
		frames[name+"/reserved-length"] = target.wrap([]byte{target.tag, 0xff})
		for width := 1; width <= 8; width++ {
			length := make([]byte, width)
			length[0] = 0x80
			header := append([]byte{target.tag, 0x80 | byte(width)}, length...)
			frames[fmt.Sprintf("%s/oversized-%d", name, width)] = target.wrap(append(bytes.Clone(header), 0))
			for cut := 2; cut < len(header); cut++ {
				frames[fmt.Sprintf("%s/truncated-header-%d-%d", name, width, cut)] = target.wrap(header[:cut])
			}
		}
	}
	return frames
}

func TestBindCompareLongLengthFallback(t *testing.T) {
	next := bindCompareTestFrame(0x60, bindCompareTestFields(0x60)...)
	for name, frame := range bindCompareLongLengthEdgeFrames() {
		t.Run(name, func(t *testing.T) {
			checkBindCompareFrame(t, frame, false)
			for _, depth := range []int{-1, 0, DefaultMaxFilterDepth} {
				compareSearchDecode(t, append(bytes.Clone(frame), next...), 4096, 0, depth)
			}
		})
	}
}

func TestBindCompareLongInnerTruncation(t *testing.T) {
	for name, target := range bindCompareLongLengthTargets() {
		t.Run(name, func(t *testing.T) {
			element := searchTestTLV(target.tag, target.content)
			checkBindCompareFrame(t, target.wrap(element), true)
			for cut := range len(element) {
				// Keep ancestor lengths valid so truncation reaches the inner decoder.
				frame := target.wrap(element[:cut])
				checkBindCompareFrame(t, frame, false)
				compareSearchDecode(t, frame, 4096, 0, -1)
			}
		})
	}
}
