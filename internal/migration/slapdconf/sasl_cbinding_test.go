package slapdconf

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const saslCBindingOID = "1.3.6.1.4.1.4203.1.12.2.3.0.100"

func TestSASLCBindingConversion(t *testing.T) {
	for _, policy := range []string{"none", "tls-unique", "tls-endpoint", "NoNe", "TLS-UNIQUE", "tls-ENDPOINT"} {
		for _, quoted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/quoted=%t", policy, quoted), func(t *testing.T) {
				argument := policy
				if quoted {
					argument = `"` + policy + `"`
				}
				path := configFile(t, "# policy\nSaSl-CbInDiNg "+argument+"\n")
				document, err := ConvertFile(path, ParseOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if got := values(t, document, "cn=config", "olcSaslCBinding"); !reflect.DeepEqual(got, []string{policy}) {
					t.Fatalf("policy = %q, want %q", got, policy)
				}
				for _, attribute := range document.Entries[0].Attributes {
					if attribute.Name == "olcSaslCBinding" && !reflect.DeepEqual(attribute.Sources, []Position{{Path: path, Line: 2}}) {
						t.Fatalf("sources = %#v", attribute.Sources)
					}
				}
				var output bytes.Buffer
				if err := document.WriteLDIF(&output); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(output.String(), "olcSaslCBinding: "+policy+"\n") {
					t.Fatalf("LDIF changed policy: %s", &output)
				}
			})
		}
	}
}

func TestSASLCBindingInvalidSource(t *testing.T) {
	for _, test := range []struct{ name, argument, diagnostic string }{
		{"missing", "", "requires 1 argument"},
		{"multiple", "none tls-unique", "requires 1 argument"},
		{"empty", `""`, "empty value"},
		{"blank", `" "`, "empty value"},
		{"unknown", "required", "unsupported policy"},
		{"endpoint alias", "tls-server-end-point", "unsupported policy"},
		{"exporter", "tls-exporter", "unsupported policy"},
		{"quoted unknown", `"required"`, "unsupported policy"},
		{"leading space", `" none"`, "unsupported policy"},
		{"trailing space", `"none "`, "unsupported policy"},
		{"quoted list", `"none tls-unique"`, "unsupported policy"},
		{"literal quotes", `"\"none\""`, "unsupported policy"},
		{"single quotes", "'none'", "unsupported policy"},
		{"ordered", "{0}none", "unsupported policy"},
		{"unicode", "tls-un\u0130que", "unsupported policy"},
		{"unterminated", `"none`, "quote"},
	} {
		t.Run(test.name, func(t *testing.T) {
			child := configFile(t, "# included policy\n\nsasl-cbinding "+test.argument+"\n")
			path := configFile(t, fmt.Sprintf("sasl-host localhost\ninclude %q\n", child))
			document, err := ConvertFile(path, ParseOptions{})
			var located *ParseError
			if !errors.As(err, &located) || located.Position != (Position{Path: child, Line: 3}) || !strings.Contains(err.Error(), test.diagnostic) {
				t.Fatalf("error = %v, want %s:3 and %q", err, child, test.diagnostic)
			}
			if len(document.Entries) != 0 {
				t.Fatal("invalid policy returned partial configuration")
			}
		})
	}
}

func TestSASLCBindingGlobalPlacementAndRepetition(t *testing.T) {
	for _, prefix := range []string{"", "backend mdb\n", "database config\n", "database mdb\nsuffix dc=example\ndirectory /unused\n", "database mdb\nsuffix dc=example\ndirectory /unused\noverlay syncprov\n"} {
		t.Run(prefix, func(t *testing.T) {
			path := configFile(t, prefix+"sasl-cbinding tls-endpoint\n")
			document, err := ConvertFile(path, ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}
			values(t, document, "cn=config", "olcSaslCBinding")
			for _, entry := range document.Entries[1:] {
				for _, attribute := range entry.Attributes {
					if attribute.Name == "olcSaslCBinding" {
						t.Fatalf("global policy placed on %s", entry.DN)
					}
				}
			}
			for _, repeated := range []string{"tls-endpoint", "TLS-ENDPOINT", "none"} {
				child := configFile(t, "# repeated\nSASL-CBINDING "+repeated+"\n")
				path := configFile(t, "sasl-cbinding tls-endpoint\n"+prefix+fmt.Sprintf("include %q\n", child))
				document, err := ConvertFile(path, ParseOptions{})
				if err == nil || !strings.Contains(err.Error(), child+":2:") || !strings.Contains(err.Error(), "already configured") || len(document.Entries) != 0 {
					t.Fatalf("repeated policy: document=%+v error=%v", document, err)
				}
			}
		})
	}
}

func TestSASLCBindingImportValidation(t *testing.T) {
	for _, test := range []struct {
		name, attribute string
		values          []string
		database        bool
		valid           bool
	}{
		{"OID", saslCBindingOID, []string{"TLS-ENDPOINT"}, false, true},
		{"unknown OID policy", saslCBindingOID, []string{"required"}, false, false},
		{"option", "olcSaslCBinding;lang-en", []string{"none"}, false, false},
		{"OID option", saslCBindingOID + ";binary", []string{"none"}, false, false},
		{"multiple", "olcSaslCBinding", []string{"none", "tls-unique"}, false, false},
		{"empty", "olcSaslCBinding", []string{""}, false, false},
		{"database", "olcSaslCBinding", []string{"none"}, true, false},
		{"database OID", saslCBindingOID, []string{"none"}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			document, err := ConvertFile(configFile(t, "database mdb\nsuffix dc=example\ndirectory /unused\n"), ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}
			target := &document.Entries[0]
			if test.database {
				target = &document.Entries[len(document.Entries)-1]
			}
			target.Attributes = append(target.Attributes, Attribute{Name: test.attribute, Values: test.values})
			store := storage.NewMemory()
			defer store.Close()
			if err := document.Validate(t.Context()); (err == nil) != test.valid {
				t.Fatalf("Validate() = %v, valid=%t", err, test.valid)
			}
			if err := document.Import(t.Context(), store); (err == nil) != test.valid {
				t.Fatalf("Import() = %v, valid=%t", err, test.valid)
			}
			if !test.valid {
				assertEmptySASLCBindingStore(t, store)
			} else if _, err := server.ValidateConfiguration(t.Context(), server.Config{Store: store}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSASLCBindingOfflineValidation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	base := t.TempDir()
	path := configFile(t, fmt.Sprintf(`sasl-cbinding "TLS-ENDPOINT"
sasl-host localhost
serverid 1 ldap://%s
database mdb
suffix dc=example
directory %q
syncrepl rid=001 provider=ldap://%s searchbase=dc=example type=refreshAndPersist retry="1 +"
`, listener.Addr(), filepath.Join(base, "unused-mdb"), listener.Addr()))
	document, err := ConvertFile(path, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewMemory()
	defer store.Close()
	var input bytes.Buffer
	if err := document.WriteLDIF(&input); err != nil {
		t.Fatal(err)
	}
	validated := false
	_, err = migration.ImportLDIF(t.Context(), store, &input, migration.ImportOptions{
		DryRun: true,
		ValidateConfigTransaction: func(reader storage.Reader) error {
			validated = true
			summary, err := server.ValidateConfigurationReader(t.Context(), server.Config{Store: store}, reader)
			if err == nil && summary.SyncreplConsumers != 1 {
				t.Fatalf("syncrepl consumers = %d", summary.SyncreplConsumers)
			}
			return err
		},
	})
	if err != nil || !validated {
		t.Fatalf("dry-run validation=%t error=%v", validated, err)
	}
	assertEmptySASLCBindingStore(t, store)
	if err := document.Import(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err == nil {
		connection.Close()
		t.Fatal("offline conversion/import contacted the replication provider")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("accept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "unused-mdb")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("opened metadata directory: %v", err)
	}
}

func assertEmptySASLCBindingStore(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		return reader.ForEachPartition(func(partition string, entry directory.Entry) error {
			return fmt.Errorf("unexpected entry %s in %s", entry.DN, partition)
		})
	}); err != nil {
		t.Fatal(err)
	}
}
