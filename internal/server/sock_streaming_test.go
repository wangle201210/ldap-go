package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSockBackendSearchStreamsEntriesAndReferrals(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	firstWritten := make(chan struct{})
	release := make(chan struct{})
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		if request.command == "UNBIND" {
			return nil
		}
		if request.command != "SEARCH" {
			return fmt.Errorf("unexpected socket command %q", request.command)
		}
		if err := writeAll(connection, []byte(sockStreamingBareEntry("first"))); err != nil {
			return err
		}
		close(firstWritten)
		<-release
		return writeAll(connection, []byte(
			"REFERRAL\n"+
				"uri: ldap://ref.example/dc=ref,dc=example\n\n"+
				sockStreamingExplicitEntry("second")+
				"RESULT\ncode: 0\nmatched:\ninfo:\n\n",
		))
	})
	address, stop := startSockStreamingLDAPServer(t, fixture)
	defer stop()
	connection := dialAndBindRawLDAP(t, address, "", "")
	defer connection.Close()

	writeRawLDAPRequest(t, connection, 2, rawCancellationSearch(t), nil)
	assertSockRuntimeCommand(t, fixture.take(t), "SEARCH")
	select {
	case <-firstWritten:
	case <-time.After(3 * time.Second):
		t.Fatal("socket fixture did not write its first entry")
	}
	first := readRawLDAPPacket(t, connection)
	assertSockStreamingEntry(t, first, 2, "uid=first,dc=example,dc=com")

	close(release)
	reference := readRawLDAPPacket(t, connection)
	assertSockStreamingReference(
		t,
		reference,
		2,
		"ldap://ref.example/dc=ref,dc=example",
	)
	second := readRawLDAPPacket(t, connection)
	assertSockStreamingEntry(t, second, 2, "uid=second,dc=example,dc=com")
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		2,
		ldapwire.ApplicationSearchResultDone,
		int64(ldap.LDAPResultSuccess),
	)
}

func TestSockBackendSearchPartialCancelAndAbandon(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	blocked := make(chan chan error, 2)
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		if request.command == "UNBIND" {
			return nil
		}
		if request.command != "SEARCH" {
			return fmt.Errorf("unexpected socket command %q", request.command)
		}
		if err := writeAll(connection, []byte(sockStreamingBareEntry("partial"))); err != nil {
			return err
		}
		closed := make(chan error, 1)
		blocked <- closed
		var buffer [1]byte
		count, err := connection.Read(buffer[:])
		if count != 0 || err == nil {
			return fmt.Errorf("blocked socket Read() = %d, %v; want closure", count, err)
		}
		closed <- err
		return nil
	})
	address, stop := startSockStreamingLDAPServer(t, fixture)
	defer stop()
	connection := dialAndBindRawLDAP(t, address, "", "")
	defer connection.Close()

	writeRawLDAPRequest(t, connection, 2, rawCancellationSearch(t), nil)
	assertSockRuntimeCommand(t, fixture.take(t), "SEARCH")
	firstClosed := takeSockRuntimeBlockedConnection(t, fixture, blocked)
	assertSockStreamingEntry(
		t,
		readRawLDAPPacket(t, connection),
		2,
		"uid=partial,dc=example,dc=com",
	)
	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest(cancelOID, ldapwire.EncodeCancelRequestValue(2), true),
		nil,
	)
	waitForSockRuntimeClosure(t, firstClosed)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		2,
		ldapwire.ApplicationSearchResultDone,
		int64(ldap.LDAPResultCanceled),
	)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		3,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)

	writeRawLDAPRequest(t, connection, 4, rawCancellationSearch(t), nil)
	assertSockRuntimeCommand(t, fixture.take(t), "SEARCH")
	secondClosed := takeSockRuntimeBlockedConnection(t, fixture, blocked)
	assertSockStreamingEntry(
		t,
		readRawLDAPPacket(t, connection),
		4,
		"uid=partial,dc=example,dc=com",
	)
	writeRawLDAPRequest(t, connection, 5, rawAbandonRequest(4), nil)
	waitForSockRuntimeClosure(t, secondClosed)
	writeRawLDAPRequest(t, connection, 6, rawExtendedRequest(whoAmIOID, nil, false), nil)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		6,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
}

func TestSockBackendSearchMalformedMidstreamKeepsLDAPConnection(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		if request.command == "UNBIND" {
			return nil
		}
		return writeAll(connection, []byte(
			sockStreamingBareEntry("valid")+
				"ENTRY\n"+
				"dn: uid=broken,dc=example,dc=com\n"+
				"cn without separator\n\n"+
				"RESULT\ncode: 0\n\n",
		))
	})
	address, stop := startSockStreamingLDAPServer(t, fixture)
	defer stop()
	connection := dialAndBindRawLDAP(t, address, "", "")
	defer connection.Close()

	writeRawLDAPRequest(t, connection, 2, rawCancellationSearch(t), nil)
	assertSockRuntimeCommand(t, fixture.take(t), "SEARCH")
	assertSockStreamingEntry(
		t,
		readRawLDAPPacket(t, connection),
		2,
		"uid=valid,dc=example,dc=com",
	)
	failed := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		failed,
		2,
		ldapwire.ApplicationSearchResultDone,
		int64(ldap.LDAPResultOther),
	)
	if diagnostic := rawLDAPDiagnostic(failed); diagnostic != sockBackendFailureDiagnostic {
		t.Fatalf("Search diagnostic = %q, want %q", diagnostic, sockBackendFailureDiagnostic)
	}

	writeRawLDAPRequest(t, connection, 3, rawExtendedRequest(whoAmIOID, nil, false), nil)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		3,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
}

func TestSockBackendSearchEnforcesVisibleSizeLimit(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	fixture := startSockRuntimeFixture(t, sockRuntimeResponseHandler(
		sockStreamingBareEntry("first")+
			sockStreamingBareEntry("second")+
			"RESULT\ncode: 0\n\n",
	))
	address, stop := startSockStreamingLDAPServer(t, fixture)
	defer stop()
	connection := dialAndBindRawLDAP(t, address, "", "")
	defer connection.Close()

	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 2,
		Request: ldapwire.SearchRequest{
			BaseDN:       "dc=example,dc=com",
			Scope:        directory.ScopeWholeSubtree,
			DerefAliases: ldapwire.NeverDerefAliases,
			SizeLimit:    1,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: []string{"dn"},
		},
	})
	if err != nil {
		t.Fatalf("EncodeRequestMessage(): %v", err)
	}
	if err := ldapwire.Write(connection, encoded); err != nil {
		t.Fatalf("write size-limited Search: %v", err)
	}
	captured := fixture.take(t)
	assertSockRuntimeCommand(t, captured, "SEARCH")
	assertSockRuntimeField(t, captured, "sizelimit", "1")
	assertSockStreamingEntry(
		t,
		readRawLDAPPacket(t, connection),
		2,
		"uid=first,dc=example,dc=com",
	)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		2,
		ldapwire.ApplicationSearchResultDone,
		int64(ldap.LDAPResultSizeLimitExceeded),
	)
}

func TestStreamSockResponseKeepsOnlyCurrentRecord(t *testing.T) {
	t.Parallel()

	const entries = 256
	reader := &sockStreamingGeneratedReader{
		entries: entries,
		value:   strings.Repeat("x", 32<<10),
	}
	limits := SockProtocolLimits{
		MaxResponseBytes: 40 << 20,
		MaxLineBytes:     40 << 10,
		MaxEntryBytes:    40 << 10,
		MaxEntries:       entries,
		MaxAttributes:    8,
		MaxValues:        8,
	}
	result, err := StreamSockResponse(
		reader,
		limits,
		func(record SockResponseRecord) error {
			if record.Entry == nil || record.Entry.DN == "" {
				return errors.New("stream emitted a non-entry record")
			}
			reader.markEmitted()
			return nil
		},
	)
	if err != nil {
		t.Fatalf("StreamSockResponse(): %v", err)
	}
	if result.Code != ldapwire.ResultSuccess || reader.emittedCount() != entries {
		t.Fatalf("stream result = %#v, emitted = %d", result, reader.emittedCount())
	}
	if maximum := reader.maximumReadSize(); maximum > 64<<10 {
		t.Fatalf("maximum parser read = %d bytes, want at most 64 KiB", maximum)
	}
}

func TestStreamSockResponseLineLimitAfterPartialRecord(t *testing.T) {
	t.Parallel()

	emitted := 0
	_, err := StreamSockResponse(
		strings.NewReader(
			sockStreamingBareEntry("first")+
				"dn: uid=second,dc=example,dc=com\n"+
				"description: this line is too long\n\n"+
				"RESULT\n\n",
		),
		SockProtocolLimits{
			MaxResponseBytes: 1 << 10,
			MaxLineBytes:     32,
			MaxEntryBytes:    256,
			MaxEntries:       8,
			MaxAttributes:    8,
			MaxValues:        8,
		},
		func(record SockResponseRecord) error {
			emitted++
			return nil
		},
	)
	if !errors.Is(err, ErrSockProtocolLimit) {
		t.Fatalf("StreamSockResponse() error = %v, want ErrSockProtocolLimit", err)
	}
	if emitted != 1 {
		t.Fatalf("records emitted before line limit = %d, want 1", emitted)
	}
}

func startSockStreamingLDAPServer(
	t *testing.T,
	fixture *sockRuntimeFixture,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockRuntimeConfiguration(t, store, sockRuntimeDatabaseSeed{
		order:  1,
		suffix: "dc=example,dc=com",
		path:   fixture.path,
	})
	return startServer(t, store, Config{})
}

func sockStreamingBareEntry(uid string) string {
	return fmt.Sprintf(
		"dn: uid=%s,dc=example,dc=com\n"+
			"objectClass: inetOrgPerson\n"+
			"uid: %s\n"+
			"cn: %s\n"+
			"sn: User\n\n",
		uid,
		uid,
		uid,
	)
}

func sockStreamingExplicitEntry(uid string) string {
	return "ENTRY\n" + sockStreamingBareEntry(uid)
}

func assertSockStreamingEntry(
	t *testing.T,
	packet *ber.Packet,
	messageID int64,
	wantDN string,
) {
	t.Helper()
	operation := assertSockStreamingPacket(t, packet, messageID, ldapwire.ApplicationSearchResultEntry)
	if len(operation.Children) < 1 {
		t.Fatalf("SearchResultEntry has no DN: %#v", operation)
	}
	if got := string(operation.Children[0].Data.Bytes()); got != wantDN {
		t.Fatalf("SearchResultEntry DN = %q, want %q", got, wantDN)
	}
}

func assertSockStreamingReference(
	t *testing.T,
	packet *ber.Packet,
	messageID int64,
	want string,
) {
	t.Helper()
	operation := assertSockStreamingPacket(
		t,
		packet,
		messageID,
		ldapwire.ApplicationSearchResultReference,
	)
	if len(operation.Children) != 1 || string(operation.Children[0].Data.Bytes()) != want {
		t.Fatalf("SearchResultReference = %#v, want %q", operation.Children, want)
	}
}

func assertSockStreamingPacket(
	t *testing.T,
	packet *ber.Packet,
	messageID int64,
	tag uint64,
) *ber.Packet {
	t.Helper()
	if packet == nil || len(packet.Children) < 2 {
		t.Fatalf("malformed LDAP response: %#v", packet)
	}
	gotMessageID, err := ber.ParseInt64(packet.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse LDAP message ID: %v", err)
	}
	operation := packet.Children[1]
	if gotMessageID != messageID ||
		operation.ClassType != ber.ClassApplication ||
		uint64(operation.Tag) != tag {
		t.Fatalf(
			"LDAP response = id %d tag %d, want id %d tag %d",
			gotMessageID,
			operation.Tag,
			messageID,
			tag,
		)
	}
	return operation
}

type sockStreamingGeneratedReader struct {
	mu          sync.Mutex
	entries     int
	generated   int
	emitted     int
	value       string
	current     []byte
	offset      int
	resultSent  bool
	maximumRead int
}

func (reader *sockStreamingGeneratedReader) Read(buffer []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(buffer) > reader.maximumRead {
		reader.maximumRead = len(buffer)
	}
	if reader.offset == len(reader.current) {
		if reader.generated > reader.emitted {
			return 0, errors.New("parser read the next record before emitting the current record")
		}
		switch {
		case reader.generated < reader.entries:
			reader.generated++
			reader.current = []byte(fmt.Sprintf(
				"dn: uid=user-%d,dc=example,dc=com\n"+
					"description: %s\n\n",
				reader.generated,
				reader.value,
			))
			reader.offset = 0
		case !reader.resultSent:
			reader.resultSent = true
			reader.current = []byte("RESULT\ncode: 0\n\n")
			reader.offset = 0
		default:
			return 0, io.EOF
		}
	}
	count := copy(buffer, reader.current[reader.offset:])
	reader.offset += count
	return count, nil
}

func (reader *sockStreamingGeneratedReader) markEmitted() {
	reader.mu.Lock()
	reader.emitted++
	reader.mu.Unlock()
}

func (reader *sockStreamingGeneratedReader) emittedCount() int {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.emitted
}

func (reader *sockStreamingGeneratedReader) maximumReadSize() int {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.maximumRead
}
