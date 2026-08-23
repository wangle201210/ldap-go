package server

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenLDAP2613MonitorLogRoutingSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	files := []struct {
		path    string
		digest  string
		anchors []string
	}{
		{
			path:   filepath.Join(sourceRoot, "include", "ldap_log.h"),
			digest: "ec11aa63beefb3151a3a76c76d67d34582d3b6ae61eb093a49391c39b24c7b5d",
			anchors: []string{
				"#define LDAP_DEBUG_TRACE\t0x0001",
				"#define LDAP_DEBUG_STATS2\t0x0200",
				"#define LDAP_DEBUG_SYNC\t\t0x4000",
				"#define LDAP_DEBUG_NONE\t\t0x8000",
				"#define LDAP_DEBUG_ANY\t\t(-1)",
				"#define LogTest(level) ( ( ldap_debug | ldap_syslog ) & (level) )",
			},
		},
		{
			path:   filepath.Join(sourceRoot, "servers", "slapd", "logging.c"),
			digest: "ed63b4d2ddbd5fd364acc4515a231b9c203294fea025926c989b5307a25dc948",
			anchors: []string{
				"{ BER_BVC(\"Any\"),\t(slap_mask_t) LDAP_DEBUG_ANY }",
				"{ BER_BVC(\"Packets\"),\tLDAP_DEBUG_PACKETS }",
				"{ BER_BVC(\"ACL\"),\tLDAP_DEBUG_ACL }",
				"{ BER_BVC(\"Stats2\"),\tLDAP_DEBUG_STATS2 }",
				"{ BER_BVC(\"Sync\"),\tLDAP_DEBUG_SYNC }",
				"{ BER_BVC(\"None\"),\tLDAP_DEBUG_NONE }",
			},
		},
		{
			path: filepath.Join(
				sourceRoot,
				"servers", "slapd", "back-monitor", "log.c",
			),
			digest: "cce714943b2dbf6b5ff6c78d4bc6715d7f6827254e0d66da98280049af29aaeb",
			anchors: []string{
				"ldap_pvt_thread_mutex_lock( &monitor_log_mutex );",
				"newsyslog = slap_syslog_get();",
				"slap_syslog_set( newsyslog );",
				"e->e_attrs = save_attrs;",
				"ldap_pvt_thread_mutex_unlock( &monitor_log_mutex );",
			},
		},
	}
	for _, file := range files {
		contents, err := os.ReadFile(file.path)
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", file.path, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != file.digest {
			t.Fatalf("OpenLDAP source hash for %s = %s, want %s", file.path, got, file.digest)
		}
		for _, anchor := range file.anchors {
			if !bytes.Contains(contents, []byte(anchor)) {
				t.Fatalf("OpenLDAP source %s lacks %q", file.path, anchor)
			}
		}
	}
}
