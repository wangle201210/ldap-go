package directory

import "testing"

func TestSimpleRDNValueByteClass(t *testing.T) {
	for c := range 256 {
		want := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
			c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_'
		if got := simpleRDNValueByteClass[c]; got != want {
			t.Errorf("byte 0x%02x: class=%v, want %v", c, got, want)
		}
	}
}

func TestParseSimpleRDNBytesByteClassImmutable(t *testing.T) {
	before := simpleRDNValueByteClass
	for _, prefix := range []string{"uid=", "2.5.4.3=", "01.2="} {
		value := []byte(prefix + "Aa-9_x.y")
		for c := range 256 {
			value[len(prefix)+2] = byte(c)
			checkSimpleRDNBytes(t, value)
			if simpleRDNValueByteClass != before {
				t.Fatalf("parsing %q modified the value byte class", value)
			}
		}
	}
}
