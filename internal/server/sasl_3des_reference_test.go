package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This control distinguishes an unusable native Cyrus provider from a Go
// interoperability defect. The standalone runner records any provider patch.
func TestOpenLDAPReferenceDIGESTMD5Native3DES(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	useCyrus3DESReference(t)
	const identity = "uid=replicator,ou=people,dc=example,dc=com"
	uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil,
		`sasl-realm example.com
sasl-secprops noplain,noanonymous,maxbufsize=128
authz-regexp "^uid=replicator,.*cn=auth$" "`+identity+`"`,
		`access to * by dn.exact="`+identity+`" read by anonymous auth by * none`,
		"\ndn: "+identity+"\nobjectClass: inetOrgPerson\nuid: replicator\ncn: Replicator\nsn: Replicator\nuserPassword: replication-secret\n")
	defer stop()
	for _, tool := range []string{"ldapwhoami", "ldapsearch"} {
		t.Run(tool, func(t *testing.T) {
			path, err := exec.LookPath(tool)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"-Y", "DIGEST-MD5", "-U", "replicator", "-R", "example.com",
				"-w", "replication-secret", "-O", "minssf=112,maxssf=112,maxbufsize=128", "-H", uri}
			if tool == "ldapsearch" {
				args = append(args, "-LLL", "-b", "dc=example,dc=com", "(objectClass=*)", "dn", "cn")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("native Cyrus 3DES self-check: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "SASL SSF: 112") {
				t.Fatalf("native command did not negotiate 3DES: %s", output)
			}
			if tool == "ldapwhoami" {
				if !strings.HasSuffix(strings.TrimSpace(string(output)), "dn:"+identity) {
					t.Fatalf("native WhoAmI identity: %s", output)
				}
			} else if !strings.Contains(string(output), "dn: "+identity+"\n") || strings.Count(string(output), "dn: ") < 3 {
				t.Fatalf("native framed Search returned incomplete entries: %s", output)
			}
		})
	}
}

// Only these DIGEST-MD5 tests select the repaired provider. The other native
// mechanisms keep the reference environment's ordinary Cyrus plugins.
func useCyrus3DESReference(t *testing.T) {
	t.Helper()
	root := os.Getenv("LDAP_GO_CYRUS_3DES_REFERENCE_DIR")
	if root == "" {
		return
	}
	provenance, err := os.ReadFile(filepath.Join(root, "provenance.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []string{
		"reference_kind=OpenLDAP-2.6.13-with-locally-patched-Cyrus-2.1.28",
		"openldap_commit=d172686d3d270bc961b78f3ff00d7019c8dfb094",
		"cyrus_commit=7a6b45b177070198fed0682bea5fa87c18abb084",
	} {
		if !strings.Contains("\n"+string(provenance), "\n"+record+"\n") {
			t.Fatalf("3DES provider provenance does not contain %q", record)
		}
	}
	source := filepath.Join(root, "cyrus-sasl-7a6b45b177070198fed0682bea5fa87c18abb084")
	data, err := os.ReadFile(filepath.Join(source, "plugins", "digestmd5.c"))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != "e38ac02818f2065fbbcda735314316168a8c38bfc8b4011ac46468cc7165a760" {
		t.Fatal("3DES provider source differs from the reviewed parity-only repair")
	}
	t.Setenv("SASL_PATH", filepath.Join(source, "plugins", ".libs"))
	t.Setenv("LDAP_GO_CYRUS_3DES_TESTS", "1")
	t.Log("Reference: unmodified OpenLDAP 2.6.13 with locally parity-repaired Cyrus 2.1.28; not an unmodified-Cyrus result")
}
