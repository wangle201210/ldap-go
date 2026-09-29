package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func legacyReaderAccessSubject(reader storage.Reader, dn string) acl.Subject {
	subject := acl.Subject{DN: dn, RealDN: dn}
	if provider, ok := reader.(interface{ AccessContext() any }); ok {
		if contextual, ok := provider.AccessContext().(acl.Subject); ok {
			subject = contextual
			subject.DN = dn
			if subject.RealDN == "" {
				subject.RealDN = dn
			}
		}
	}
	return subject
}

func TestReaderACLSubjectForwarding(t *testing.T) {
	t.Parallel()
	for _, subject := range []acl.Subject{
		{},
		{DN: "cn=bound", RealDN: "cn=proxy", PeerName: "IP=127.0.0.1:1234",
			SockName: "IP=127.0.0.1:389", Domain: "example.com", SockURL: "ldap:///",
			SSF: 256, TransportSSF: 128, TLSSSF: 256, SASLSSF: 112},
	} {
		for _, reader := range []storage.Reader{
			nil,
			accessContextReader{subject: subject},
			accessContextWriter{subject: subject},
			&accessContextReader{subject: subject},
			&accessContextWriter{subject: subject},
			storageRevisionReader{Reader: accessContextReader{subject: subject}},
			storage.ReaderInPartition(accessContextReader{subject: subject}, "db"),
			storage.ReaderInPartition(storageRevisionReader{Reader: accessContextWriter{subject: subject}}, "db"),
			storageRevisionReader{Reader: storage.ReaderInPartition(accessContextReader{subject: subject}, "db")},
		} {
			for _, dn := range []string{"", "uid=effective,dc=example,dc=com"} {
				if got, want := accessSubject(reader, dn), legacyReaderAccessSubject(reader, dn); got != want {
					t.Fatalf("reader %T, dn %q: got %+v; want %+v", reader, dn, got, want)
				}
			}
		}
	}
}

type changingACLSubjectReader struct {
	storage.Reader
	calls int
}

func (reader *changingACLSubjectReader) AccessContext() any {
	reader.calls++
	return acl.Subject{RealDN: "cn=proxy", SSF: reader.calls}
}

func TestReaderACLSubjectKeepsCustomCallbacksLive(t *testing.T) {
	t.Parallel()
	custom := &changingACLSubjectReader{Reader: accessContextReader{subject: acl.Subject{SSF: 999}}}
	reader := storage.ReaderInPartition(storageRevisionReader{Reader: custom}, "db")
	for want := 1; want <= 3; want++ {
		got := accessSubject(reader, "cn=effective")
		if got.SSF != want || custom.calls != want || got.RealDN != "cn=proxy" || got.DN != "cn=effective" {
			t.Fatalf("custom context was bypassed or cached: %+v, calls=%d", got, custom.calls)
		}
	}
}

func BenchmarkReaderACLSubject(b *testing.B) {
	reader := storage.ReaderInPartition(accessContextReader{
		subject: acl.Subject{RealDN: "cn=proxy", SSF: 256, PeerName: "IP=127.0.0.1:1234"},
	}, "db")
	for _, tc := range []struct {
		name string
		read func(storage.Reader, string) acl.Subject
	}{
		{"forwardedInterface", legacyReaderAccessSubject},
		{"directValue", accessSubject},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if got := tc.read(reader, "cn=effective"); got.SSF != 256 || got.RealDN != "cn=proxy" {
					b.Fatal(got)
				}
			}
		})
	}
}
