package server

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenLDAP2613AutoCALocalDNSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	path := filepath.Join(sourceRoot, "servers", "slapd", "overlays", "autoca.c")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read OpenLDAP AutoCA source: %v", err)
	}
	if got, want := fmt.Sprintf("%x", sha256.Sum256(contents)),
		"1334aaa1eea43090d26581706853b0fe410bff3dfe1eaa8f893614a85522e7d7"; got != want {
		t.Fatalf("OpenLDAP AutoCA source hash = %s, want %s", got, want)
	}
	for _, anchor := range []string{
		"EVP_PKEY2PKCS8( evpk )",
		"if ( dn_match( &rs->sr_entry->e_nname, &ai->ai_localndn ))",
		"autoca_setlocal( &op2, &args.dercert, &args.derpkey );",
		"slap_str2ad( \"olcTLSCertificate;binary\"",
		"slap_str2ad( \"olcTLSCertificateKey;binary\"",
		"extras[0].value = op->o_tmpalloc( sizeof(\"IP:\")",
		"{ \"extendedKeyUsage\", \"serverAuth,clientAuth\" }",
	} {
		if !bytes.Contains(contents, []byte(anchor)) {
			t.Fatalf("OpenLDAP AutoCA source lacks %q", anchor)
		}
	}
}
