package directory

import (
	"bytes"
	"testing"
)

func checkMatchSimpleRDNValueBytes(t testing.TB, actual, expected []byte, fold bool) {
	t.Helper()
	actualBefore, expectedBefore := bytes.Clone(actual), bytes.Clone(expected)
	classBefore := simpleRDNValueByteClass
	depth, valid := SimpleDNDepthBytes(append([]byte("cn="), actual...))
	wantSimple := valid && depth == 1
	compared := actual
	if fold {
		compared = bytes.ToLower(actual)
	}
	wantMatch := wantSimple && bytes.Equal(compared, expected)
	matched, simple := MatchSimpleRDNValueBytes(actual, expected, fold)
	if matched != wantMatch || simple != wantSimple {
		t.Fatalf("actual=%q expected=%q fold=%v: got (%v,%v), want (%v,%v)",
			actual, expected, fold, matched, simple, wantMatch, wantSimple)
	}
	if !bytes.Equal(actual, actualBefore) || !bytes.Equal(expected, expectedBefore) || simpleRDNValueByteClass != classBefore {
		t.Fatal("value comparison modified input or byte class")
	}
}

func TestMatchSimpleRDNValueBytesOracle(t *testing.T) {
	for _, fold := range []bool{false, true} {
		for _, target := range []string{"A_b.c-9", "x", "longer-value"} {
			expected := []byte(target)
			if fold {
				expected = bytes.ToLower(expected)
			}
			checkMatchSimpleRDNValueBytes(t, nil, expected, fold)
			const original = "A_b.c-9"
			actual := []byte(original)
			for position := range actual {
				for c := range 256 {
					actual[position] = byte(c)
					checkMatchSimpleRDNValueBytes(t, actual, expected, fold)
				}
				actual[position] = original[position]
				checkMatchSimpleRDNValueBytes(t, actual[:position], expected, fold)
			}
			for c := range 256 {
				checkMatchSimpleRDNValueBytes(t, append(bytes.Clone(actual), byte(c)), expected, fold)
			}
		}
	}
}

func FuzzMatchSimpleRDNValueBytes(f *testing.F) {
	for _, actual := range []string{"A_b.c-9", "a_B.C-9", "", "x_b.c-!", "x\xff", `x\`, "x+uid=y"} {
		f.Add([]byte(actual), []byte("a_b.c-9"), true)
		f.Add([]byte(actual), []byte("A_b.c-9"), false)
	}
	f.Fuzz(func(t *testing.T, actual, expected []byte, fold bool) {
		if len(actual)+len(expected) > 4096 {
			t.Skip()
		}
		depth, valid := SimpleDNDepthBytes(append([]byte("cn="), expected...))
		if !valid || depth != 1 {
			t.Skip()
		}
		if fold {
			expected = bytes.ToLower(expected)
		}
		checkMatchSimpleRDNValueBytes(t, actual, expected, fold)
	})
}
