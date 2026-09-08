package migration

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/mdbentry"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestImportMaxEntrySize(t *testing.T) {
	for _, bolt := range []bool{false, true} {
		for _, generate := range []bool{false, true} {
			t.Run(strconv.FormatBool(bolt)+"/generated="+strconv.FormatBool(generate), func(t *testing.T) {
				var store storage.Store = storage.NewMemory()
				if bolt {
					var err error
					store, err = storage.OpenBolt(filepath.Join(t.TempDir(), "import.db"))
					if err != nil {
						t.Fatal(err)
					}
				}
				defer store.Close()
				config := directory.Entry{DN: "olcDatabase={1}mdb,cn=config", Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: [][]byte{[]byte("{1}mdb")}},
					{Description: "olcSuffix", Values: [][]byte{[]byte("dc=example,dc=com")}},
					{Description: mdbentry.Attribute, Values: [][]byte{[]byte("180")}},
				}}
				if err := store.Update(context.Background(), func(w storage.Writer) error { return w.PutIn(storage.OpenLDAPConfigPartition, config, false) }); err != nil {
					t.Fatal(err)
				}
				input := "dn: dc=example,dc=com\nobjectClass: domain\ndc: example\n\ndn: cn=small,dc=example,dc=com\nobjectClass: person\ncn: small\nsn: Test\n\n"
				if !generate {
					input += "dn: cn=large,dc=example,dc=com\nobjectClass: person\ncn: large\nsn: Test\ndescription: " + strings.Repeat("x", 200) + "\n\n"
				}
				_, err := ImportLDIF(context.Background(), store, strings.NewReader(input), ImportOptions{Database: "1", GenerateOperationalAttributes: generate})
				if !errors.Is(err, mdbentry.ErrTooLarge) {
					t.Fatalf("import size error=%v", err)
				}
				if err := store.View(context.Background(), func(r storage.Reader) error {
					return r.ForEachIn(storage.OpenLDAPDatabasePartition("{1}mdb", nil), func(e directory.Entry) error { t.Fatalf("failed atomic import kept %s", e.DN); return nil })
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
