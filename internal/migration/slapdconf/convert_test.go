package slapdconf

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldif"
)

func configFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "slapd.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func values(t *testing.T, document Document, dn, name string) []string {
	t.Helper()
	for _, entry := range document.Entries {
		if entry.DN == dn {
			for _, attribute := range entry.Attributes {
				if strings.EqualFold(attribute.Name, name) {
					return attribute.Values
				}
			}
		}
	}
	t.Fatalf("missing %s on %s", name, dn)
	return nil
}

func TestConvertCredentialsACLIndexReplication(t *testing.T) {
	path := configFile(t, `backend mdb
database config
rootdn cn=config
rootpw "config secret"
database mdb
suffix "dc=example,dc=com"
rootdn "cn=Directory Manager,dc=example,dc=com"
rootpw " leading password with \"quotes\" and \\ slash"
directory "/not opened/data directory"
maxsize 10485760
access to attrs=userPassword by self write by anonymous auth by * none
access to *
  by dn.exact="cn=Directory Manager,dc=example,dc=com" manage
  by * read
index objectClass eq
index cn,sn eq,sub
syncrepl rid=001 provider=ldap://localhost:1389
  searchbase="dc=example,dc=com" bindmethod=simple
  binddn="cn=Directory Manager,dc=example,dc=com" credentials="a secret"
  type=refreshAndPersist retry="5 5 300 +"
overlay syncprov
syncprov-checkpoint 100 10
syncprov-sessionlog 100
`)
	document, err := ConvertFile(path, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	db := "olcDatabase={1}mdb,cn=config"
	wantPassword := ` leading password with "quotes" and \ slash`
	if got := values(t, document, db, "olcRootPW"); !reflect.DeepEqual(got, []string{wantPassword}) {
		t.Fatalf("password = %q", got)
	}
	if got := values(t, document, db, "olcAccess"); len(got) != 2 || !strings.HasPrefix(got[1], "{1}to *") {
		t.Fatalf("ACL order = %q", got)
	}
	if got := values(t, document, db, "olcDbDirectory")[0]; got != "/not opened/data directory" {
		t.Fatalf("directory = %q", got)
	}
	var encoded bytes.Buffer
	if err := document.WriteLDIF(&encoded); err != nil {
		t.Fatal(err)
	}
	parsed := &ldif.LDIF{}
	for entry, err := range ldif.UnmarshalEntries(bytes.NewReader(encoded.Bytes()), parsed) {
		if err != nil {
			t.Fatal(err)
		}
		if entry.Entry.DN == db && entry.Entry.GetAttributeValue("olcRootPW") != wantPassword {
			t.Fatal("LDIF changed password")
		}
	}
	again, err := ConvertFile(path, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := again.WriteLDIF(&second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded.Bytes(), second.Bytes()) {
		t.Fatal("nondeterministic LDIF")
	}
}

func TestConvertFailsClosed(t *testing.T) {
	for _, test := range []struct{ name, config, fragment string }{
		{"unknown", "mystery-policy allow", "mystery-policy"},
		{"native", "moduleload custom.so", "pure Go"},
		{"module args", "moduleload syncprov arbitrary", "arguments"},
		{"backend", "backend mdb\nidlexp 20", "idlexp"},
		{"unsupported database", "database bdb", "backend"},
		{"root outside database", "rootpw secret", "database declaration"},
		{"missing directory", "database mdb\nsuffix dc=example", "directory"},
		{"missing suffix", "database mdb\ndirectory /tmp/unused", "suffix"},
		{"unknown overlay", "database mdb\noverlay custom", "overlay"},
		{"invalid ACL", "database mdb\nsuffix dc=example\ndirectory /tmp/unused\naccess to * by * imaginary", "olcAccess"},
		{"unknown syncrepl", "database mdb\nsuffix dc=example\ndirectory /tmp/unused\nsyncrepl rid=1 provider=ldap://localhost searchbase=dc=example madeup=true", "syncrepl"},
		{"bad index", "database mdb\nsuffix dc=example\ndirectory /tmp/unused\nindex cn nonsense", "index"},
		{"bad TLS", "TLSProtocolMin 99.9", "TLS"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := configFile(t, test.config+"\n")
			document, err := ConvertFile(path, ParseOptions{})
			var located *ParseError
			if err == nil || !errors.As(err, &located) || located.Position.Path != path || located.Position.Line < 1 || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.fragment)) {
				t.Fatalf("error = %v", err)
			}
			if len(document.Entries) != 0 {
				t.Fatal("partial conversion returned")
			}
		})
	}
}
