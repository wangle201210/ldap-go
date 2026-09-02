package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPSearchNamedExtensionsEncodeControls(t *testing.T) {
	t.Parallel()

	falseSubentries, err := parseLDAPSearchSubentriesExtension("!subentries=false")
	if err != nil {
		t.Fatal(err)
	}
	assertNamedRawControl(
		t, falseSubentries, ldapSubentriesControlOID, true, []byte{0x01, 0x01, 0x00},
	)
	syncControl, err := parseLDAPSearchSyncExtension("sync=ro=invalid")
	if err == nil || syncControl != nil {
		t.Fatalf("invalid sync extension = %#v, %v", syncControl, err)
	}
	syncControl, err = parseLDAPSearchSyncExtension("sync=ro/csn=one")
	if err != nil {
		t.Fatal(err)
	}
	raw := assertNamedRawControl(t, syncControl, ldapSyncRequestOID, false, nil)
	request, err := ldapwire.DecodeSyncRequestValue(raw.value)
	if err != nil || request.Mode != ldapwire.SyncRefreshOnly ||
		!request.HasCookie || string(request.Cookie) != "csn=one" {
		t.Fatalf("sync request = %#v, %v", request, err)
	}
	dontUseCopy, err := parseLDAPSearchDontUseCopyExtension("!dontUseCopy")
	if err != nil {
		t.Fatal(err)
	}
	assertNamedRawControl(t, dontUseCopy, ldapDontUseCopyOID, true, nil)
	account, err := parseLDAPSearchAccountUsabilityExtension("accountUsability")
	if err != nil {
		t.Fatal(err)
	}
	assertNamedRawControl(t, account, ldapAccountUsabilityOID, false, nil)
}

func assertNamedRawControl(
	t *testing.T,
	control ldap.Control,
	oid string,
	critical bool,
	wantValue []byte,
) *ldapRawControl {
	t.Helper()
	raw, ok := control.(*ldapRawControl)
	if !ok || raw.oid != oid || raw.critical != critical {
		t.Fatalf("control = %#v, want oid=%s critical=%v", control, oid, critical)
	}
	if wantValue != nil && !slices.Equal(raw.value, wantValue) {
		t.Fatalf("control value = %x, want %x", raw.value, wantValue)
	}
	return raw
}

func TestOpenLDAPReferenceLDAPSearchNamedExtensions(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run named extension differential")
	}
	referenceTool, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan []string, 2)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, search := message.Request.(ldapwire.SearchRequest); !search {
			return nil, nil
		}
		var signature []string
		for _, control := range message.Controls {
			criticality := "noncritical"
			if control.Critical {
				criticality = "critical"
			}
			signature = append(signature, fmt.Sprintf(
				"%s|%s|%s",
				control.OID,
				criticality,
				hex.EncodeToString(control.Value),
			))
		}
		sort.Strings(signature)
		requests <- signature
		return [][]byte{ldapwire.EncodeSearchResultDone(
			message.ID, ldapwire.Result{Code: ldapwire.ResultSuccess}, nil,
		)}, nil
	})
	arguments := []string{
		"-H", fixture.uri, "-x", "-b", clientToolBaseDN,
		"-E", "!subentries=false",
		"-E", "sync=ro/csn=one",
		"-E", "!dontUseCopy",
		"-E", "accountUsability",
		"-LLL", "(objectClass=*)", "cn",
	}
	if output, err := exec.Command(referenceTool, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("OpenLDAP ldapsearch: %v\n%s", err, output)
	}
	localOut, localErr, localCode := runLDAPClientCommand(
		append([]string{"ldapsearch"}, arguments...), "",
	)
	if localCode != 0 || localOut != "" || localErr != "" {
		t.Fatalf("ldap-go ldapsearch=%d/%q/%q", localCode, localOut, localErr)
	}
	reference := <-requests
	implementation := <-requests
	if !slices.Equal(implementation, reference) {
		t.Fatalf("named controls:\nldap-go:  %q\nOpenLDAP: %q", implementation, reference)
	}
}
