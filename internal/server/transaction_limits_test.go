package server

import (
	"bytes"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPTransactionQueueLimitDefaultsAndValidation(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(default transaction limits): %v", err)
	}
	if got := instance.config.MaxTransactionOperations; got != defaultTransactionMaxOperations {
		t.Fatalf("default transaction operation limit = %d, want %d", got, defaultTransactionMaxOperations)
	}
	if got := instance.config.MaxTransactionQueuedBytes; got != defaultTransactionMaxQueuedBytes {
		t.Fatalf("default transaction queued byte limit = %d, want %d", got, defaultTransactionMaxQueuedBytes)
	}

	for _, test := range []struct {
		name   string
		config Config
		text   string
	}{
		{
			name:   "operations",
			config: Config{Store: store, MaxTransactionOperations: -1},
			text:   "maximum transaction operations cannot be negative",
		},
		{
			name:   "bytes",
			config: Config{Store: store, MaxTransactionQueuedBytes: -1},
			text:   "maximum transaction queued bytes cannot be negative",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.config)
			if err == nil || !strings.Contains(err.Error(), test.text) {
				t.Fatalf("New() error = %v, want %q", err, test.text)
			}
		})
	}
}

func TestLDAPTransactionRetainedBytesReleaseExactlyOnce(t *testing.T) {
	t.Parallel()

	limiter := newResourceByteLimiter(16)
	if !limiter.tryAcquire(7) {
		t.Fatal("acquire transaction bytes failed")
	}
	transaction := &ldapTransaction{
		retainedBytes:   7,
		releaseRetained: limiter.release,
	}
	clearLDAPTransaction(transaction)
	clearLDAPTransaction(transaction)
	if limiter.active.Load() != 0 {
		t.Fatalf("transaction retained bytes = %d, want 0", limiter.active.Load())
	}
}

func TestLDAPTransactionQueueLimitsSendAbortedNotice(t *testing.T) {
	tests := []struct {
		name              string
		maxOperations     int
		maxQueuedBytes    int64
		queueFirst        bool
		firstMessageID    int64
		overflowMessageID int64
	}{
		{
			name:              "operation-count",
			maxOperations:     1,
			maxQueuedBytes:    1 << 20,
			queueFirst:        true,
			firstMessageID:    3,
			overflowMessageID: 4,
		},
		{
			name:              "encoded-bytes",
			maxOperations:     10,
			maxQueuedBytes:    1,
			firstMessageID:    3,
			overflowMessageID: 3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			address, stop := startServer(t, store, Config{
				RootDN:                    "cn=admin,dc=example,dc=com",
				RootPassword:              []byte("admin-secret"),
				MaxTransactionOperations:  test.maxOperations,
				MaxTransactionQueuedBytes: test.maxQueuedBytes,
			})
			defer stop()

			connection := dialAndBindRawLDAP(
				t,
				address,
				"cn=admin,dc=example,dc=com",
				"admin-secret",
			)
			defer connection.Close()
			identifier := startRawLDAPTransaction(t, connection, 2)
			first := transactionTestPerson("limit-first")
			if test.queueFirst {
				response := sendRawLDAPOperation(
					t,
					connection,
					test.firstMessageID,
					rawAddRequest(first),
					rawTransactionSpecificationControl(identifier, true, true),
				)
				assertRawLDAPMessageID(t, response, test.firstMessageID)
				assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
			}

			overflow := transactionTestPerson("limit-overflow")
			notice := sendRawLDAPOperation(
				t,
				connection,
				test.overflowMessageID,
				rawAddRequest(overflow),
				rawTransactionSpecificationControl(identifier, true, true),
			)
			assertAbortedTransactionNotice(t, notice, identifier)

			endResponse := endRawLDAPTransaction(t, connection, 5, true, identifier)
			assertRawLDAPMessageID(t, endResponse, 5)
			assertRawLDAPResult(
				t,
				endResponse,
				int64(ldapwire.ResultTransactionIDInvalid),
			)
			if transactionEntryExists(t, store, first.DN) ||
				transactionEntryExists(t, store, overflow.DN) {
				t.Fatal("resource-limit-aborted transaction retained a queued Add")
			}

			newIdentifier := startRawLDAPTransaction(t, connection, 6)
			abortResponse := endRawLDAPTransaction(t, connection, 7, false, newIdentifier)
			assertRawLDAPMessageID(t, abortResponse, 7)
			assertRawLDAPResult(t, abortResponse, int64(ldapwire.ResultSuccess))
		})
	}
}

func TestLDAPTransactionRespectsProcessPendingByteLimit(t *testing.T) {
	t.Parallel()

	entry := transactionTestPerson("process-byte-limit")
	requestSize := rawLDAPRequestRetainedSizeWithControls(
		t,
		3,
		rawAddRequest(entry),
		rawTransactionSpecificationControl(nil, true, true),
	)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:                   "cn=admin,dc=example,dc=com",
		RootPassword:             []byte("admin-secret"),
		MaxPendingOperationBytes: requestSize,
	})
	defer stop()
	connection := dialAndBindRawLDAP(
		t, address, "cn=admin,dc=example,dc=com", "admin-secret",
	)
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)
	if len(identifier) != 0 {
		t.Fatalf("transaction identifier = %x, want empty", identifier)
	}
	notice := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(entry),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertAbortedTransactionNotice(t, notice, identifier)
	if transactionEntryExists(t, store, entry.DN) {
		t.Fatal("process-byte-limited transaction retained its Add")
	}
	newIdentifier := startRawLDAPTransaction(t, connection, 4)
	abortResponse := endRawLDAPTransaction(t, connection, 5, false, newIdentifier)
	assertRawLDAPResult(t, abortResponse, int64(ldapwire.ResultSuccess))
}

func rawLDAPRequestRetainedSizeWithControls(
	t *testing.T,
	messageID int64,
	operation *ber.Packet,
	controls ...*ber.Packet,
) int64 {
	t.Helper()
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	message.AppendChild(operation)
	if len(controls) != 0 {
		wrapper := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			0,
			nil,
			"controls",
		)
		for _, control := range controls {
			wrapper.AppendChild(control)
		}
		message.AppendChild(wrapper)
	}
	encoded := message.Bytes()
	decoded, encodedSize, err := ldapwire.ReadMessageWithDynamicFilterDepthAndSize(
		bytes.NewReader(encoded),
		int64(len(encoded)),
		math.MaxUint64,
		nil,
	)
	if err != nil {
		t.Fatalf("decode retained-size LDAP request: %v", err)
	}
	return ldapMessageRetainedBytes(decoded, int64(encodedSize))
}

func TestLDAPUnbindAbortsTransactionWithoutNotice(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("unbind-abort")
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawAddRequest(entry),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)

	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID:      4,
		Request: ldapwire.UnbindRequest{},
	})
	if err != nil {
		t.Fatalf("EncodeRequestMessage(Unbind): %v", err)
	}
	if err := ldapwire.Write(connection, encoded); err != nil {
		t.Fatalf("write Unbind: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	response, err := ber.ReadPacket(connection)
	if err == nil {
		t.Fatalf("Unbind produced an unsolicited response: %#v", response)
	}
	if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatalf("connection remained open after Unbind: %v", err)
	}
	_ = connection.Close()
	if transactionEntryExists(t, store, entry.DN) {
		t.Fatal("Unbind-aborted transaction committed its queued Add")
	}
}

func assertAbortedTransactionNotice(
	t *testing.T,
	response *ber.Packet,
	identifier []byte,
) {
	t.Helper()
	assertRawLDAPMessageID(t, response, 0)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultAdminLimitExceeded))
	if len(response.Children) < 2 ||
		response.Children[1].ClassType != ber.ClassApplication ||
		response.Children[1].Tag != ldapwire.ApplicationExtendedResponse {
		t.Fatalf("aborted transaction notice is not an ExtendedResponse: %#v", response)
	}
	var (
		responseName  string
		responseValue []byte
		valuePresent  bool
	)
	for _, child := range response.Children[1].Children {
		if child.ClassType != ber.ClassContext || child.TagType != ber.TypePrimitive {
			continue
		}
		switch child.Tag {
		case 10:
			responseName = string(child.Data.Bytes())
		case 11:
			responseValue = child.Data.Bytes()
			valuePresent = true
		}
	}
	if responseName != transactionAbortedNoticeOID {
		t.Fatalf("aborted transaction responseName = %q", responseName)
	}
	if !valuePresent || string(responseValue) != string(identifier) {
		t.Fatalf(
			"aborted transaction responseValue present=%v value=%x, want %x",
			valuePresent,
			responseValue,
			identifier,
		)
	}
}

func assertRawLDAPMessageID(t *testing.T, response *ber.Packet, want int64) {
	t.Helper()
	if response == nil || len(response.Children) < 1 {
		t.Fatalf("malformed LDAP response: %#v", response)
	}
	got, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("decode LDAP message ID: %v", err)
	}
	if got != want {
		t.Fatalf("LDAP message ID = %d, want %d", got, want)
	}
}
