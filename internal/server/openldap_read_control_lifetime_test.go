package server

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// parseReadAttrs borrows names through ber_scanf("{M}"). Known attributes are
// rebound to schema-owned names, but a noncritical unrecognized name survives
// ber_free(ber, 1). The response subsequently reads that freed buffer. This
// pinned source contract guards the memory-safety exception without executing
// a use-after-free or treating allocator-dependent native output as correct.
func TestOpenLDAPReadControlNameLifetimeSource(t *testing.T) {
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skip("requires the pinned OpenLDAP reference source")
	}
	root := os.Getenv("OPENLDAP_SOURCE")
	if root == "" {
		t.Fatal("OPENLDAP_SOURCE is required")
	}
	for path, digest := range map[string]string{
		"servers/slapd/controls.c":   "dac19d7202fd319e7d79487a0d3263e5f773750f1459457ae88f5179bb9e61d6",
		"libraries/liblber/decode.c": "bc95337fe659d74596adf8f984b1b180fa1eda31837e9b4e4c3cdf5dc9ed69b9",
		"libraries/liblber/io.c":     "c4501b851c2d511bbd94bf624324830afa51f9451648c0477725712e2c432ec3",
	} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != digest {
			t.Fatalf("%s changed; re-audit the OpenLDAP 2.6.13 read-control lifetime exception", path)
		}
	}
}
