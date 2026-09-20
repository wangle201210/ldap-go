package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Compare runtime results instead of assuming that every libc selects the same
// captures. OpenLDAP delegates these choices to the host's regexec implementation.
func TestOpenLDAPReferenceRWMRewriteCaptures(t *testing.T) {
	path := os.Getenv("LDAP_GO_OPENLDAP_REWRITE")
	if path == "" {
		if os.Getenv(openLDAPReferenceTestsEnv) != "1" || os.Getenv("OPENLDAP_BUILD") == "" {
			t.Skip("set LDAP_GO_OPENLDAP_REWRITE to the OpenLDAP 2.6.13 rewrite executable")
		}
		path = filepath.Join(os.Getenv("OPENLDAP_BUILD"), "libraries", "librewrite", "rewrite")
	}
	for _, test := range []struct {
		name    string
		pattern string
		input   string
	}{
		{"short alternative first", `^(a|aa)(a?)$`, "aa"},
		{"long alternative first", `^(aa|a)(a?)$`, "aa"},
		{"nested short alternative first", `^((a|aa)*)(a?)$`, "aa"},
		{"nested long alternative first", `^((aa|a)*)(a?)$`, "aa"},
		{"repeated short alternative first", `^(a|aa)*$`, "aa"},
		{"repeated long alternative first", `^(aa|a)*$`, "aa"},
		{"repeated nullable capture", `^(a*)*b$`, "aaab"},
		{"repeated optional capture", `^(a?)*b$`, "aaab"},
		{"empty optional capture", `^(a*)?b$`, "b"},
		{"absent capture in final iteration", `^((a)?b)*$`, "abb"},
		{"alternative absent in final iteration", `^((a)|(b))*$`, "ab"},
		{"uncaptured final alternative", `^((a)|b)*$`, "ab"},
		{"uncaptured folded final alternative", `^((a)|b)*$`, "aB"},
		{"uncaptured two final alternatives", `^((a)|b)*$`, "abb"},
		{"uncaptured earlier repeated alternative", `^((a)|b)*$`, "aab"},
		{"never matched alternative", `^((a)|b)*$`, "b"},
		{"final captured alternative", `^((a)|b)*$`, "ba"},
		{"nonzero capture offset", `^x((a)|b)*y$`, "xaby"},
		{"capture before trailing literal", `^((a)|b)*c$`, "abbc"},
		{"three captured alternatives", `^((a)|(b)|(c))*$`, "abc"},
		{"repeated captured union", `^((a|c)|b)*$`, "ab"},
		{"repeated captured different length union", `^((a|ab)|b)*$`, "abb"},
		{"repeated bracket expression", `^(([a])|b)*$`, "ab"},
		{"repeated bracket range", `^(([a-c])|d)*$`, "ad"},
		{"repeated nonletter alternative", `^((1)|a)*$`, "1a"},
		{"repeated consecutive literal alternative", `^((ab)|c)*$`, "abc"},
		{"repeated quantified alternative", `^((a+)|b)*$`, "ab"},
		{"repeated nested captures", `^(((a))|b)*$`, "ab"},
		{"plus repeated alternative", `^((a)|b)+$`, "ab"},
		{"bounded repeated captured alternative", `^((a)|b){1,3}$`, "ab"},
		{"nested shared end tags", `^(((a)|b)|c)*$`, "abc"},
		{"shared tags under concatenation", `^(((a)|b)c)*$`, "acbc"},
		{"shared tags under optional branch", `^(((a)|b)?c)*$`, "acbcc"},
		{"shared tags under star branch", `^(((a)|b)*c)*$`, "acbcc"},
		{"shared tags under bounded branch", `^(((a)|b){0,3}c)*$`, "acbcc"},
		{"shared tags under rejected branch", `^(((a)|b)?|c)*$`, "abc"},
		{"shared tags under repeated rejected branch", `^(((a)|b)*|c)*$`, "abc"},
		{"shared tags under nonnullable rejected branch", `^(((a)|b)+|c)*$`, "abc"},
		{"shared tags under bounded rejected branch", `^(((a)|b){0,3}|c)*$`, "abc"},
		{"uncaptured union under optional branch", `^((a|b)?c)*$`, "acc"},
		{"uncaptured union under rejected branch", `^((a|d)?|b)*$`, "ab"},
		{"shared tag with unexposed capture", `^()()()()()()()(((a)|b)?c)*$`, "acbcc"},
		{"captured union followed by literal", `^((a|b)c|d)*$`, "acd"},
		{"bracket punctuation before capture", `^[][()]((a)|b)*$`, "]ab"},
		{"bracket class before capture", `^[[:alpha:]]((a)|b)*$`, "xab"},
		{"escaped parentheses before capture", `^\(((a)|b)*\)$`, "(ab)"},
		{"adjacent greedy captures", `^(a*)(a*)$`, "aaa"},
		{"nested greedy captures", `^((a*)*)(a*)$`, "aaa"},
		{"alternative before greedy suffix", `^(a|ab)(b*)$`, "ab"},
		{"repeated alternative before suffix", `^((a|ab)*)(b*)$`, "ab"},
		{"greedy capture before alternative", `^(a*)(ab|b)$`, "aab"},
		{"bounded repeated alternative", `^((a|ab){1,3})(b*)$`, "abab"},
		{"odd repeated short alternative", `^(a|aa)*(a?)$`, "aaa"},
		{"even repeated short alternative", `^(a|aa)*(a?)$`, "aaaa"},
		{"nested nullable repetitions", `^((a*)*)*$`, "aa"},
		{"empty nested nullable repetitions", `^((a*)*)*$`, ""},
		{"directory suffix capture", `^uid=([^,]+),(.*)$`, "uid=alice,ou=people,dc=example,dc=com"},
	} {
		for _, flags := range []string{":", ":C"} {
			t.Run(test.name+"/"+flags, func(t *testing.T) {
				const substitution = "$0/$1/$2/$3/$4/$5/$6/$7/$8/$9"
				engine := mustRWMRewriteEngine(t,
					[]string{"rewriteEngine", "on"},
					[]string{"rewriteContext", "default"},
					[]string{"rewriteRule", test.pattern, substitution, flags},
				)
				got, _, err := engine.rewrite("default", test.input)
				if err != nil {
					t.Fatalf("ldap-go rewrite: %v", err)
				}
				configuration := fmt.Sprintf("rewriteEngine on\nrewriteContext default\nrewriteRule \"%s\" \"%s\" \"%s\"\n", test.pattern, substitution, flags)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, path, test.input)
				command.Stdin = strings.NewReader(configuration)
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("reference rewrite: %v\n%s", err, output)
				}
				if wantSuffix := fmt.Sprintf(" -> %s [0:ok]\n", got); !strings.HasSuffix(string(output), wantSuffix) {
					t.Fatalf("pattern=%q input=%q: ldap-go=%q; OpenLDAP output=%q", test.pattern, test.input, got, output)
				}
			})
		}
	}
}
