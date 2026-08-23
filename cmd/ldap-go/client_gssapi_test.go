package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestLDAPClientGSSAPIExplicitEmptyPasswordUsesPasswordCredentials(t *testing.T) {
	configuration := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(configuration, []byte(
		"[libdefaults]\n"+
			" default_realm = LDAP-GO.TEST\n"+
			" dns_lookup_kdc = false\n"+
			"[realms]\n"+
			" LDAP-GO.TEST = {\n"+
			"  kdc = 127.0.0.1:1\n"+
			" }\n",
	), 0o600); err != nil {
		t.Fatalf("write krb5.conf: %v", err)
	}
	t.Setenv("KRB5_CONFIG", configuration)
	t.Setenv("KRB5_CLIENT_KTNAME", "")
	t.Setenv("KRB5_KTNAME", "")
	t.Setenv("KRB5CCNAME", "")

	flags := flag.NewFlagSet("ldapwhoami", flag.ContinueOnError)
	flags.SetOutput(&bytes.Buffer{})
	var options ldapClientOptions
	options.register(flags)
	t.Cleanup(options.clear)
	if err := flags.Parse([]string{
		"-Y", "GSSAPI",
		"-U", "alice",
		"-R", "LDAP-GO.TEST",
		"-w", "",
	}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if err := options.validateForWrite(flags, true); err != nil {
		t.Fatalf("validate GSSAPI flags: %v", err)
	}
	password, hasPassword, err := options.loadPassword(
		flags,
		bytes.NewReader(nil),
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatalf("load empty password: %v", err)
	}
	defer clear(password)
	if !hasPassword || len(password) != 0 {
		t.Fatalf("empty password state = %t, %q", hasPassword, password)
	}
	initiator, err := options.newGSSAPIInitiator(password, hasPassword)
	if err != nil {
		t.Fatalf("create password initiator: %v", err)
	}
	if err := initiator.Close(); err != nil {
		t.Fatalf("close password initiator: %v", err)
	}
}
