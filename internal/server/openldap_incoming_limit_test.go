package server

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceIncomingPDUIdentityLimits(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	small := encodedPaddedWhoAmIRequest(t, 2, 256)
	overflow := encodedPaddedWhoAmIRequest(t, 2, 257)
	large := encodedPaddedWhoAmIRequest(t, 2, 1024)
	anonymousLimit := ldapFrameContentLength(t, small)
	authenticatedLimit := ldapFrameContentLength(t, large)
	if ldapFrameContentLength(t, overflow) <= anonymousLimit {
		t.Fatal("overflow request did not cross anonymous content limit")
	}
	globalConfig := "sockbuf_max_incoming " + uint64String(anonymousLimit) +
		"\nsockbuf_max_incoming_auth " + uint64String(authenticatedLimit)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		globalConfig,
		"",
		"",
	)
	defer stopReference()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putIncomingLimitRuntimeEntry(t, store, anonymousLimit, authenticatedLimit)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLocal()

	reference := observeIncomingIdentityLimits(
		t,
		strings.TrimPrefix(referenceURI, "ldap://"),
		small,
		overflow,
		large,
	)
	local := observeIncomingIdentityLimits(
		t,
		localAddress,
		small,
		overflow,
		large,
	)
	if !reflect.DeepEqual(reference, local) {
		t.Fatalf("incoming PDU limits: OpenLDAP=%#v ldap-go=%#v", reference, local)
	}
	if reference.anonymousCode != int64(ldap.LDAPResultProtocolError) ||
		!reference.anonymousOverflowClosed ||
		reference.authenticatedCode != int64(ldap.LDAPResultProtocolError) ||
		!reference.failedBindOverflowClosed ||
		!reference.anonymousBindOverflowClosed {
		t.Fatalf("OpenLDAP incoming PDU observation = %#v", reference)
	}
}

func TestOpenLDAPReferenceIncomingPDULimitsSnapshotUntilIdentityTransition(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI := startOpenLDAPDynamicConfigReferralServer(t, tools)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLocal()

	reference := observeIncomingLimitRuntimeSnapshot(t, referenceURI)
	local := observeIncomingLimitRuntimeSnapshot(t, "ldap://"+localAddress)
	if !reflect.DeepEqual(reference, local) {
		t.Fatalf("incoming limit snapshots: OpenLDAP=%#v ldap-go=%#v", reference, local)
	}
	if reference != (incomingLimitSnapshotObservation{
		existingAnonymousCode: int64(ldap.LDAPResultProtocolError),
		existingAuthCode:      int64(ldap.LDAPResultProtocolError),
		newAnonymousClosed:    true,
		reboundAuthClosed:     true,
	}) {
		t.Fatalf("OpenLDAP incoming limit snapshot = %#v", reference)
	}
}

type incomingLimitSnapshotObservation struct {
	existingAnonymousCode int64
	existingAuthCode      int64
	newAnonymousClosed    bool
	reboundAuthClosed     bool
}

func observeIncomingLimitRuntimeSnapshot(
	t *testing.T,
	uri string,
) incomingLimitSnapshotObservation {
	t.Helper()
	const reducedLimit = uint64(200)
	medium := encodedPaddedWhoAmIRequest(t, 2, 512)
	initialLimit := ldapFrameContentLength(t, medium)
	if initialLimit <= reducedLimit {
		t.Fatalf("medium content length = %d", initialLimit)
	}
	configClient, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s config): %v", uri, err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(%s cn=config): %v", uri, err)
	}
	replaceIncomingLimits(t, configClient, initialLimit, initialLimit)

	address := strings.TrimPrefix(uri, "ldap://")
	existingAnonymous := dialRawIncomingLimitConnection(t, address)
	defer existingAnonymous.Close()
	existingAuth := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer existingAuth.Close()
	replaceIncomingLimits(t, configClient, reducedLimit, reducedLimit)

	observation := incomingLimitSnapshotObservation{}
	if err := ldapwire.Write(existingAnonymous, medium); err != nil {
		t.Fatalf("write existing anonymous request: %v", err)
	}
	response := readRawLDAPPacket(t, existingAnonymous)
	observation.existingAnonymousCode = rawLDAPResultCode(t, response.Children[1])
	if err := ldapwire.Write(existingAuth, medium); err != nil {
		t.Fatalf("write existing authenticated request: %v", err)
	}
	response = readRawLDAPPacket(t, existingAuth)
	observation.existingAuthCode = rawLDAPResultCode(t, response.Children[1])

	newAnonymous := dialRawIncomingLimitConnection(t, address)
	if err := ldapwire.Write(newAnonymous, medium); err != nil {
		t.Fatalf("write new anonymous request: %v", err)
	}
	observation.newAnonymousClosed = incomingLimitConnectionClosed(t, newAnonymous)
	_ = newAnonymous.Close()

	rebind := sendRawLDAPOperation(
		t,
		existingAuth,
		3,
		rawSimpleBindRequest("cn=admin,dc=example,dc=com", "secret"),
	)
	assertRawLDAPResult(t, rebind, int64(ldap.LDAPResultSuccess))
	reboundRequest := encodedPaddedWhoAmIRequest(t, 4, 512)
	if err := ldapwire.Write(existingAuth, reboundRequest); err != nil {
		t.Fatalf("write rebound authenticated request: %v", err)
	}
	observation.reboundAuthClosed = incomingLimitConnectionClosed(t, existingAuth)
	return observation
}

func replaceIncomingLimits(
	t *testing.T,
	client *ldap.Conn,
	anonymous,
	authenticated uint64,
) {
	t.Helper()
	modify := ldap.NewModifyRequest("cn=config", nil)
	modify.Replace(incomingLimitAnonymousAttribute, []string{uint64String(anonymous)})
	modify.Replace(incomingLimitAuthenticatedAttribute, []string{uint64String(authenticated)})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("replace incoming limits: %v", err)
	}
}

type incomingIdentityLimitObservation struct {
	anonymousCode               int64
	anonymousOverflowClosed     bool
	authenticatedCode           int64
	failedBindOverflowClosed    bool
	anonymousBindOverflowClosed bool
}

func observeIncomingIdentityLimits(
	t *testing.T,
	address string,
	small,
	overflow,
	large []byte,
) incomingIdentityLimitObservation {
	t.Helper()
	observation := incomingIdentityLimitObservation{}

	anonymous := dialRawIncomingLimitConnection(t, address)
	if err := ldapwire.Write(anonymous, small); err != nil {
		t.Fatalf("write anonymous boundary request: %v", err)
	}
	response := readRawLDAPPacket(t, anonymous)
	observation.anonymousCode = rawLDAPResultCode(t, response.Children[1])
	_ = anonymous.Close()

	anonymousOverflow := dialRawIncomingLimitConnection(t, address)
	if err := ldapwire.Write(anonymousOverflow, overflow); err != nil {
		t.Fatalf("write anonymous overflow request: %v", err)
	}
	observation.anonymousOverflowClosed = incomingLimitConnectionClosed(
		t,
		anonymousOverflow,
	)
	_ = anonymousOverflow.Close()

	authenticated := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	if err := ldapwire.Write(authenticated, large); err != nil {
		t.Fatalf("write authenticated boundary request: %v", err)
	}
	response = readRawLDAPPacket(t, authenticated)
	observation.authenticatedCode = rawLDAPResultCode(t, response.Children[1])
	_ = authenticated.Close()

	failed := dialRawIncomingLimitConnection(t, address)
	bind := sendRawLDAPOperation(
		t,
		failed,
		1,
		rawSimpleBindRequest("cn=admin,dc=example,dc=com", "wrong"),
	)
	assertRawLDAPResult(t, bind, int64(ldap.LDAPResultInvalidCredentials))
	if err := ldapwire.Write(failed, large); err != nil {
		t.Fatalf("write failed-Bind overflow request: %v", err)
	}
	observation.failedBindOverflowClosed = incomingLimitConnectionClosed(t, failed)
	_ = failed.Close()

	anonymousBind := dialRawIncomingLimitConnection(t, address)
	bind = sendRawLDAPOperation(t, anonymousBind, 1, rawSimpleBindRequest("", ""))
	assertRawLDAPResult(t, bind, int64(ldap.LDAPResultSuccess))
	if err := ldapwire.Write(anonymousBind, large); err != nil {
		t.Fatalf("write anonymous-Bind overflow request: %v", err)
	}
	observation.anonymousBindOverflowClosed = incomingLimitConnectionClosed(
		t,
		anonymousBind,
	)
	_ = anonymousBind.Close()
	return observation
}

func dialRawIncomingLimitConnection(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(%s): %v", address, err)
	}
	return connection
}

func incomingLimitConnectionClosed(t *testing.T, connection net.Conn) bool {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	_, err := ber.ReadPacket(connection)
	if err == nil {
		return false
	}
	var networkError net.Error
	return !errors.As(err, &networkError) || !networkError.Timeout()
}

func uint64String(value uint64) string {
	return strconv.FormatUint(value, 10)
}
