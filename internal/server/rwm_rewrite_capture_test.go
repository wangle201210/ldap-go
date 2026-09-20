package server

import (
	"runtime"
	"testing"
)

func TestRWMRewriteRepeatedUnionCaptures(t *testing.T) {
	for _, test := range []struct {
		name, pattern, input, flags string
		darwin, linux, other        string
	}{
		{"folded literal", `^((a)|b)*$`, "aB", ":", "B/aB/", "B/a/", "B//"},
		{"case sensitive literal", `^((a)|b)*$`, "ab", ":C", "b//", "b/a/", "b//"},
		{"shared ends", `^((a)|(b))*$`, "ab", ":", "b/ab/b", "b/a/b", "b//b"},
		{"latest captured start", `^((a)|b)*$`, "aab", ":", "b/ab/", "b/a/", "b//"},
		{"unmatched start", `^((a)|b)*$`, "b", ":", "b//", "b//", "b//"},
		{"explicit union", `^((a|c)|b)*$`, "ab", ":C", "b/ab/", "b/a/", "b//"},
		{"factored union", `^((a|ab)|b)*$`, "abb", ":C", "b/abb/", "b/a/", "b//"},
		{"bracket singleton", `^(([a])|b)*$`, "ab", ":", "b//", "b/a/", "b//"},
		{"bracket range", `^(([a-c])|d)*$`, "ad", ":", "d//", "d/a/", "d//"},
		{"extra capture", `^(((a))|b)*$`, "ab", ":", "b//", "b/a/a", "b//"},
		{"quantified capture", `^((a+)|b)*$`, "ab", ":", "b//", "b/a/", "b//"},
		{"nested shared tags", `^(((a)|b)|c)*$`, "abc", ":", "c/bc/abc", "c/b/a", "c//"},
		{"shared tags under concatenation", `^(((a)|b)c)*$`, "acbc", ":", "bc/b/acb", "bc/b/a", "bc/b/"},
		{"skipped optional branch", `^(((a)|b)?c)*$`, "acbcc", ":", "c/bc/acbc", "c/b/a", "c//"},
		{"skipped case sensitive optional branch", `^(((a)|b)?c)*$`, "acbcc", ":C", "c/bc/", "c/b/a", "c//"},
		{"skipped optional union branch", `^(((a)|b)?|c)*$`, "abc", ":", "c/bc/abc", "c/b/a", "c//"},
		{"bracket punctuation", `^[][()]((a)|b)*$`, "]ab", ":", "b/ab/", "b/a/", "b//"},
		{"bracket named class", `^[[:alpha:]]((a)|b)*$`, "xab", ":", "b/ab/", "b/a/", "b//"},
		{"escaped parentheses", `^\(((a)|b)*\)$`, "(ab)", ":", "b/ab/", "b/a/", "b//"},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := test.other
			switch runtime.GOOS {
			case "darwin":
				want = test.darwin
			case "linux":
				want = test.linux
			}
			engine := mustRWMRewriteEngine(t,
				[]string{"rewriteEngine", "on"},
				[]string{"rewriteRule", test.pattern, "$1/$2/$3", test.flags},
			)
			got, _, err := engine.rewrite("default", test.input)
			if err != nil || got != want {
				t.Fatalf("rewrite = %q, %v; want %q", got, err, want)
			}
		})
	}
}
