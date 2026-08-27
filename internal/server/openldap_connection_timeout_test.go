package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceConnectionTimeoutOnlineConfiguration(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI := startOpenLDAPDynamicConfigReferralServer(t, tools)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	replaceGlobalConfigurationValues(t, store, idleTimeoutAttribute, "0")
	replaceGlobalConfigurationValues(t, store, writeTimeoutAttribute, "0")
	localAddress, stopLocal := startServer(t, store, Config{})
	defer stopLocal()

	reference := observeConnectionTimeoutOnlineConfiguration(t, referenceURI)
	local := observeConnectionTimeoutOnlineConfiguration(t, "ldap://"+localAddress)
	if !reflect.DeepEqual(reference, local) {
		t.Fatalf(
			"online connection timeouts:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			local,
		)
	}
}

type connectionTimeoutOnlineObservation struct {
	idleExistingClosed bool
	idleAdd            uint16
	idleEnable         uint16
	idleDuplicate      uint16
	idleDifferent      uint16
	idleMultiple       uint16
	idleNoncanonical   uint16
	idleNegative       uint16
	idleReplace        uint16
	idleDelete         uint16
	writeAdd           uint16
	writeEnable        uint16
	writeDuplicate     uint16
	writeNoncanonical  uint16
	writeNegative      uint16
	writeDelete        uint16
}

func observeConnectionTimeoutOnlineConfiguration(
	t *testing.T,
	uri string,
) connectionTimeoutOnlineObservation {
	t.Helper()
	address := strings.TrimPrefix(uri, "ldap://")
	existing, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(%s existing): %v", uri, err)
	}
	defer existing.Close()
	configClient := bindConnectionTimeoutConfigClient(t, uri)
	addIdle := ldap.NewModifyRequest("cn=config", nil)
	addIdle.Add(idleTimeoutAttribute, []string{"1"})
	observation := connectionTimeoutOnlineObservation{
		idleAdd: defaultReferralLDAPResultCode(configClient.Modify(addIdle)),
	}
	enableIdle := ldap.NewModifyRequest("cn=config", nil)
	enableIdle.Replace(idleTimeoutAttribute, []string{"1"})
	observation.idleEnable = defaultReferralLDAPResultCode(
		configClient.Modify(enableIdle),
	)
	configClient.Close()
	if err := existing.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(%s existing): %v", uri, err)
	}
	_, closeErr := ber.ReadPacket(existing)
	var networkError net.Error
	observation.idleExistingClosed = closeErr != nil &&
		(!errors.As(closeErr, &networkError) || !networkError.Timeout())

	configClient = bindConnectionTimeoutConfigClient(t, uri)
	defer configClient.Close()
	modifyCode := func(request *ldap.ModifyRequest) uint16 {
		return defaultReferralLDAPResultCode(configClient.Modify(request))
	}
	duplicate := ldap.NewModifyRequest("cn=config", nil)
	duplicate.Add(idleTimeoutAttribute, []string{"1"})
	observation.idleDuplicate = modifyCode(duplicate)
	different := ldap.NewModifyRequest("cn=config", nil)
	different.Add(idleTimeoutAttribute, []string{"2"})
	observation.idleDifferent = modifyCode(different)
	multiple := ldap.NewModifyRequest("cn=config", nil)
	multiple.Replace(idleTimeoutAttribute, []string{"1", "2"})
	observation.idleMultiple = modifyCode(multiple)
	noncanonical := ldap.NewModifyRequest("cn=config", nil)
	noncanonical.Replace(idleTimeoutAttribute, []string{"01"})
	observation.idleNoncanonical = modifyCode(noncanonical)
	negative := ldap.NewModifyRequest("cn=config", nil)
	negative.Replace(idleTimeoutAttribute, []string{"-1"})
	observation.idleNegative = modifyCode(negative)
	replace := ldap.NewModifyRequest("cn=config", nil)
	replace.Replace(idleTimeoutAttribute, []string{"2"})
	observation.idleReplace = modifyCode(replace)
	remove := ldap.NewModifyRequest("cn=config", nil)
	remove.Delete(idleTimeoutAttribute, nil)
	observation.idleDelete = modifyCode(remove)

	addWrite := ldap.NewModifyRequest("cn=config", nil)
	addWrite.Add(writeTimeoutAttribute, []string{"1"})
	observation.writeAdd = modifyCode(addWrite)
	enableWrite := ldap.NewModifyRequest("cn=config", nil)
	enableWrite.Replace(writeTimeoutAttribute, []string{"1"})
	observation.writeEnable = modifyCode(enableWrite)
	duplicateWrite := ldap.NewModifyRequest("cn=config", nil)
	duplicateWrite.Add(writeTimeoutAttribute, []string{"1"})
	observation.writeDuplicate = modifyCode(duplicateWrite)
	noncanonicalWrite := ldap.NewModifyRequest("cn=config", nil)
	noncanonicalWrite.Replace(writeTimeoutAttribute, []string{"0x10"})
	observation.writeNoncanonical = modifyCode(noncanonicalWrite)
	negativeWrite := ldap.NewModifyRequest("cn=config", nil)
	negativeWrite.Replace(writeTimeoutAttribute, []string{"-1"})
	observation.writeNegative = modifyCode(negativeWrite)
	removeWrite := ldap.NewModifyRequest("cn=config", nil)
	removeWrite.Delete(writeTimeoutAttribute, nil)
	observation.writeDelete = modifyCode(removeWrite)
	return observation
}

func bindConnectionTimeoutConfigClient(t *testing.T, uri string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s config): %v", uri, err)
	}
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		client.Close()
		t.Fatalf("Bind(%s cn=config): %v", uri, err)
	}
	return client
}

func TestOpenLDAPReferenceIdleTimeout(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"idletimeout 1",
		"",
		"",
	)
	defer stopReference()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putConnectionTimeoutGlobalEntry(t, store, []string{"1"}, nil)
	localAddress, stopLocal := startServer(t, store, Config{})
	defer stopLocal()

	reference := observeIdleTimeoutClose(
		t,
		strings.TrimPrefix(referenceURI, "ldap://"),
	)
	local := observeIdleTimeoutClose(t, localAddress)
	for name, elapsed := range map[string]time.Duration{
		"OpenLDAP": reference,
		"ldap-go":  local,
	} {
		if elapsed < 700*time.Millisecond || elapsed > 4*time.Second {
			t.Fatalf("%s idle timeout elapsed = %s", name, elapsed)
		}
	}
}

func observeIdleTimeoutClose(t *testing.T, address string) time.Duration {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(%s): %v", address, err)
	}
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(%s): %v", address, err)
	}
	started := time.Now()
	packet, err := ber.ReadPacket(connection)
	if err == nil {
		t.Fatalf("idle timeout from %s returned LDAP packet %#v", address, packet)
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatalf("idle connection %s remained open: %v", address, err)
	}
	return time.Since(started)
}

func TestOpenLDAPReferenceWriteTimeout(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	largeValue := bytes.Repeat([]byte{0xa5}, 2<<20)
	extraData := `
dn: uid=large,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: large
cn: Large Response
sn: Response
jpegPhoto:: ` + base64.StdEncoding.EncodeToString(largeValue) + "\n"
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"writetimeout 1",
		"",
		extraData,
	)
	defer stopReference()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putConnectionTimeoutGlobalEntry(t, store, nil, []string{"1"})
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "uid=large,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("large")},
				{Description: "cn", Values: stringValues("Large Response")},
				{Description: "sn", Values: stringValues("Response")},
				{Description: "jpegPhoto", Values: [][]byte{largeValue}},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed large ldap-go entry: %v", err)
	}
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLocal()

	for name, endpoint := range map[string]string{
		"OpenLDAP": strings.TrimPrefix(referenceURI, "ldap://"),
		"ldap-go":  localAddress,
	} {
		t.Run(name, func(t *testing.T) {
			observation := observeBlockedWriteTimeout(t, endpoint)
			if observation.finalResult {
				t.Fatalf("%s returned a complete SearchResultDone", name)
			}
			if !observation.closed {
				t.Fatalf("%s did not close the blocked writer", name)
			}
		})
	}
}

type blockedWriteTimeoutObservation struct {
	closed      bool
	finalResult bool
}

func observeBlockedWriteTimeout(
	t *testing.T,
	address string,
) blockedWriteTimeoutObservation {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()
	if tcp, ok := connection.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(1024)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear connection deadline: %v", err)
	}
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"uid=large,ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			"(objectClass=inetOrgPerson)",
		),
		nil,
	)
	time.Sleep(2200 * time.Millisecond)
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	observation := blockedWriteTimeoutObservation{}
	for {
		packet, err := ber.ReadPacket(connection)
		if err != nil {
			var networkError net.Error
			observation.closed = !errors.As(err, &networkError) || !networkError.Timeout()
			return observation
		}
		if len(packet.Children) > 1 &&
			packet.Children[1].ClassType == ber.ClassApplication &&
			uint64(packet.Children[1].Tag) == ldapwire.ApplicationSearchResultDone {
			observation.finalResult = true
			return observation
		}
	}
}
