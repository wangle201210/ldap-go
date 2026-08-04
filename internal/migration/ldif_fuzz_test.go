package migration

import (
	"bytes"
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/storage"
)

func FuzzLDIFSemanticRoundTrip(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(""),
		[]byte("dn: dc=example,dc=com\nobjectClass: top\nobjectClass: domain\ndc: example\n\n"),
		[]byte("dn: uid=alice,dc=example,dc=com\nobjectClass: inetOrgPerson\nuid: alice\ncn: Alice\nsn: Example\njpegPhoto:: AP8Q\n\n"),
		[]byte("dn: cn=config\nobjectClass: olcGlobal\ncn: config\n\ndn: olcDatabase={1}mdb,cn=config\nobjectClass: olcDatabaseConfig\nolcDatabase: {1}mdb\nolcSuffix: dc=example,dc=com\n\n"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		first := storage.NewMemory()
		defer first.Close()
		if _, err := ImportLDIF(
			context.Background(),
			first,
			bytes.NewReader(data),
			ImportOptions{Replace: true},
		); err != nil {
			return
		}

		var canonical bytes.Buffer
		if _, err := ExportLDIF(context.Background(), first, &canonical); err != nil {
			t.Fatalf("export successfully imported LDIF: %v", err)
		}
		second := storage.NewMemory()
		defer second.Close()
		if _, err := ImportLDIF(
			context.Background(),
			second,
			bytes.NewReader(canonical.Bytes()),
			ImportOptions{Replace: true},
		); err != nil {
			t.Fatalf("re-import canonical LDIF: %v\n%s", err, canonical.Bytes())
		}
		var roundTripped bytes.Buffer
		if _, err := ExportLDIF(context.Background(), second, &roundTripped); err != nil {
			t.Fatalf("re-export canonical LDIF: %v", err)
		}
		if !bytes.Equal(canonical.Bytes(), roundTripped.Bytes()) {
			t.Fatalf(
				"LDIF round trip mismatch\nfirst:\n%s\nsecond:\n%s",
				canonical.Bytes(),
				roundTripped.Bytes(),
			)
		}
	})
}
