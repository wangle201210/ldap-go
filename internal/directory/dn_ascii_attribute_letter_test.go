package directory

import "testing"

func TestASCIIDNAttributeLetterAllBytes(t *testing.T) {
	for i := range 256 {
		value := byte(i)
		want := value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
		if got := asciiDNAttributeLetter(value); got != want {
			t.Errorf("asciiDNAttributeLetter(0x%02x) = %v, want %v", value, got, want)
		}
	}
}
