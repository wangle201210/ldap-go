package server

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestUnknownExtendedOperationMatchesOpenLDAP(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	_, err = client.Extended(ldap.NewExtendedRequest("1.3.6.1.4.1.99999.999", nil))
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("Extended() error = %v, want LDAP error", err)
	}
	if ldapErr.ResultCode != ldap.LDAPResultProtocolError {
		t.Fatalf("Extended() result = %d, want protocolError", ldapErr.ResultCode)
	}
	if ldapErr.Err == nil || ldapErr.Err.Error() != "unsupported extended operation" {
		t.Fatalf("Extended() diagnostic = %v", ldapErr.Err)
	}
}
