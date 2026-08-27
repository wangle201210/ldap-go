package server

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPIncomingContentLimitBoundaryAndSilentClose(t *testing.T) {
	encoded := encodedPaddedWhoAmIRequest(t, 2, 512)
	contentLength := ldapFrameContentLength(t, encoded)
	for _, test := range []struct {
		name  string
		limit uint64
		close bool
	}{
		{name: "equal accepted", limit: contentLength},
		{name: "one byte over closes", limit: contentLength - 1, close: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			putIncomingLimitRuntimeEntry(t, store, test.limit, 4096)
			address, stop := startServer(t, store, Config{})
			defer stop()
			connection, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				t.Fatalf("Dial(): %v", err)
			}
			defer connection.Close()
			if err := ldapwire.Write(connection, encoded); err != nil {
				t.Fatalf("write padded request: %v", err)
			}
			if test.close {
				assertIncomingLimitSilentClose(t, connection)
				return
			}
			response := readRawLDAPPacket(t, connection)
			assertRawLDAPEnvelope(
				t,
				response,
				2,
				ldapwire.ApplicationExtendedResponse,
				int64(ldap.LDAPResultProtocolError),
			)
		})
	}
}

func TestLDAPIncomingLimitSwitchesAfterBindIdentity(t *testing.T) {
	const (
		anonymousLimit     = uint64(256)
		authenticatedLimit = uint64(4096)
	)
	encoded := encodedPaddedWhoAmIRequest(t, 2, 1024)
	if content := ldapFrameContentLength(t, encoded); content <= anonymousLimit || content > authenticatedLimit {
		t.Fatalf("test request content length = %d", content)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putIncomingLimitRuntimeEntry(t, store, anonymousLimit, authenticatedLimit)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stop()

	t.Run("authenticated", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			"cn=admin,dc=example,dc=com",
			"secret",
		)
		defer connection.Close()
		if err := ldapwire.Write(connection, encoded); err != nil {
			t.Fatalf("write authenticated request: %v", err)
		}
		response := readRawLDAPPacket(t, connection)
		assertRawLDAPEnvelope(
			t,
			response,
			2,
			ldapwire.ApplicationExtendedResponse,
			int64(ldap.LDAPResultProtocolError),
		)
	})

	for _, test := range []struct {
		name     string
		dn       string
		password string
		code     int64
	}{
		{name: "failed bind", dn: "cn=admin,dc=example,dc=com", password: "wrong", code: int64(ldap.LDAPResultInvalidCredentials)},
		{name: "anonymous bind", code: int64(ldap.LDAPResultSuccess)},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				t.Fatalf("Dial(): %v", err)
			}
			defer connection.Close()
			bind := sendRawLDAPOperation(
				t,
				connection,
				1,
				rawSimpleBindRequest(test.dn, test.password),
			)
			assertRawLDAPEnvelope(
				t,
				bind,
				1,
				ldapwire.ApplicationBindResponse,
				test.code,
			)
			if err := ldapwire.Write(connection, encoded); err != nil {
				t.Fatalf("write anonymous-limit request: %v", err)
			}
			assertIncomingLimitSilentClose(t, connection)
		})
	}
}

func encodedPaddedWhoAmIRequest(
	t *testing.T,
	messageID int64,
	padding int,
) []byte {
	t.Helper()
	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.ExtendedRequest{
			Name:     whoAmIOID,
			Value:    make([]byte, padding),
			HasValue: true,
		},
	})
	if err != nil {
		t.Fatalf("EncodeRequestMessage(): %v", err)
	}
	return encoded
}

func ldapFrameContentLength(t *testing.T, frame []byte) uint64 {
	t.Helper()
	if len(frame) < 2 || frame[0] != 0x30 {
		t.Fatalf("invalid LDAP frame: %x", frame)
	}
	if frame[1]&0x80 == 0 {
		return uint64(frame[1])
	}
	lengthBytes := int(frame[1] & 0x7f)
	if lengthBytes == 0 || lengthBytes > 8 || len(frame) < 2+lengthBytes {
		t.Fatalf("invalid LDAP frame length: %x", frame[:min(len(frame), 10)])
	}
	var length uint64
	for _, value := range frame[2 : 2+lengthBytes] {
		length = length*256 + uint64(value)
	}
	return length
}

func assertIncomingLimitSilentClose(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	packet, err := ber.ReadPacket(connection)
	if err == nil {
		t.Fatalf("incoming overflow returned LDAP packet: %#v", packet)
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatalf("incoming overflow did not close connection: %v", err)
	}
}

func putIncomingLimitRuntimeEntry(
	t *testing.T,
	store storage.Store,
	anonymous,
	authenticated uint64,
) {
	t.Helper()
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.PutIn(storage.OpenLDAPConfigPartition, directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
				{Description: "olcSockbufMaxIncoming", Values: stringValues(strconv.FormatUint(anonymous, 10))},
				{Description: "olcSockbufMaxIncomingAuth", Values: stringValues(strconv.FormatUint(authenticated, 10))},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed incoming limits: %v", err)
	}
}
