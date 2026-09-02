package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPSearchRendersDerefResponseControl(t *testing.T) {
	t.Parallel()

	value, err := ldapwire.EncodeDerefResponseValue([]ldapwire.DerefResult{
		{
			DerefAttr:  "member",
			DerefValue: "uid=a,dc=x",
			Attributes: []ldapwire.DerefAttribute{
				{Type: "uid", Values: [][]byte{[]byte("alice")}},
				{Type: "description", Values: [][]byte{{}}},
				{Type: "jpegPhoto", Values: [][]byte{{0x00, 0xff}}},
			},
		},
		{DerefAttr: "manager", DerefValue: "uid=b,dc=x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	output := ldapSearchLDIFOutput{writer: &rendered, level: 2}
	if err := output.writeKnownResponseControl(ldapSearchResponseControl{
		oid: ldapwire.DerefControlOID, value: value, hasValue: true,
	}); err != nil {
		t.Fatal(err)
	}
	want := "# member: <uid=alice>;<description=>;<jpegPhoto:=AP8=>;uid=a,dc=x\n" +
		"# manager: uid=b,dc=x\n"
	if got := rendered.String(); got != want {
		t.Fatalf("deref response output = %q, want %q", got, want)
	}
}

func TestLDAPSearchIgnoresMalformedDerefResponseControl(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer
	output := ldapSearchLDIFOutput{writer: &rendered, level: 2}
	if err := output.writeKnownResponseControl(ldapSearchResponseControl{
		oid: ldapwire.DerefControlOID, value: []byte{0x30, 0x01, 0xff}, hasValue: true,
	}); err != nil {
		t.Fatal(err)
	}
	if rendered.Len() != 0 {
		t.Fatalf("malformed deref response output = %q", rendered.String())
	}
}

func TestOpenLDAPReferenceLDAPSearchDerefResponseOutput(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run deref response differential")
	}
	referenceTool, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Fatal(err)
	}
	value, err := ldapwire.EncodeDerefResponseValue([]ldapwire.DerefResult{{
		DerefAttr:  "member",
		DerefValue: "uid=a,dc=x",
		Attributes: []ldapwire.DerefAttribute{
			{Type: "uid", Values: [][]byte{[]byte("alice")}},
			{Type: "jpegPhoto", Values: [][]byte{{0x00, 0xff}}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, search := message.Request.(ldapwire.SearchRequest); !search {
			return nil, nil
		}
		entry := directory.Entry{
			DN: "uid=a,dc=x",
			Attributes: []directory.Attribute{{
				Description: "uid",
				Values:      [][]byte{[]byte("a")},
			}},
		}
		return [][]byte{
			ldapwire.EncodeSearchResultEntry(message.ID, entry, []ldapwire.Control{{
				OID: ldapwire.DerefControlOID, Value: value, HasValue: true,
			}}),
			ldapwire.EncodeSearchResultDone(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			),
		}, nil
	})
	arguments := []string{
		"-H", fixture.uri, "-x", "-b", "dc=x",
		"-E", "deref=member:uid,jpegPhoto",
		"-LLL", "(objectClass=*)", "uid",
	}
	reference, err := exec.Command(referenceTool, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP ldapsearch: %v\n%s", err, reference)
	}
	stdout, stderr, code := runLDAPClientCommand(
		append([]string{"ldapsearch"}, arguments...),
		"",
	)
	if code != 0 || stderr != "" {
		t.Fatalf("ldap-go ldapsearch=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if stdout != string(reference) {
		t.Fatalf("deref response output:\nldap-go:  %q\nOpenLDAP: %q", stdout, reference)
	}
}
