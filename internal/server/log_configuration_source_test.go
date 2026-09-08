package server

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenLDAP2613LogFileSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	path := filepath.Join(sourceRoot, "servers", "slapd", "logging.c")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP logging source: %v", err)
	}
	const digest = "ed63b4d2ddbd5fd364acc4515a231b9c203294fea025926c989b5307a25dc948"
	if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != digest {
		t.Fatalf("OpenLDAP logging.c SHA-256 = %s, want %s", got, digest)
	}
	for _, anchor := range []string{
		`fd = open( path, O_CREAT|O_WRONLY|O_APPEND, 0640 );`,
		`if ( logfile_fslimit && logfile_fsize + len > logfile_fslimit )`,
		`if ( logfile_age && tv.tv_sec - logfile_fcreated >= logfile_age )`,
		`sprintf( logpaths[0]+logpathlen, ".%02d", i );`,
		`rename( logpaths[0], logpaths[1] );`,
		`lf_mbyte * 1048576`,
		`lf_hour * 3600`,
		`Mbyte and hours cannot both be zero`,
		`invalid max value \"%s\" must be 1-99`,
	} {
		if !bytes.Contains(contents, []byte(anchor)) {
			t.Fatalf("OpenLDAP logging.c lacks %q", anchor)
		}
	}
}
