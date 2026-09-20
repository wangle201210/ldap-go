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
// These cases use :C. Darwin REG_ICASE has additional unmatched-group capture
// differences; passing this matrix does not establish equivalence for that mode.
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
		t.Run(test.name, func(t *testing.T) {
			const substitution = "$0/$1/$2/$3"
			engine := mustRWMRewriteEngine(t,
				[]string{"rewriteEngine", "on"},
				[]string{"rewriteContext", "default"},
				[]string{"rewriteRule", test.pattern, substitution, ":C"},
			)
			got, _, err := engine.rewrite("default", test.input)
			if err != nil {
				t.Fatalf("ldap-go rewrite: %v", err)
			}
			configuration := fmt.Sprintf("rewriteEngine on\nrewriteContext default\nrewriteRule \"%s\" \"%s\" \":C\"\n", test.pattern, substitution)
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
