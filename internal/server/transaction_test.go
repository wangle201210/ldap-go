package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPTransactionCommitIsAtomic(t *testing.T) {
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
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("bob")
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
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			4,
			rawModifyReplaceRequest(entry.DN, "cn", "Robert Transaction"),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	if transactionEntryExists(t, store, entry.DN) {
		t.Fatal("queued transaction entry became visible before commit")
	}

	response := endRawLDAPTransaction(t, connection, 5, true, identifier)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	if value, present := rawExtendedResponseValue(response); present {
		t.Fatalf("successful transaction response value = %x, want absent", value)
	}
	stored := readStoredEntry(t, store, entry.DN)
	if got := string(stored.Values("cn")[0]); got != "Robert Transaction" {
		t.Fatalf("committed cn = %q, want Robert Transaction", got)
	}
}

func TestLDAPTransactionFailureRollsBackAndReturnsMessageID(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	testLDAPTransactionFailureRollsBackAndReturnsMessageID(t, store)
}

func TestLDAPTransactionBoltFailureRollsBack(t *testing.T) {
	t.Parallel()

	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	testLDAPTransactionFailureRollsBackAndReturnsMessageID(t, store)
}

func TestLDAPTransactionFailureRollsBackSyncMetadata(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
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
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("sync-rollback")
	for _, messageID := range []int64{3, 4} {
		assertRawLDAPResult(
			t,
			sendRawLDAPOperation(
				t,
				connection,
				messageID,
				rawAddRequest(entry),
				rawTransactionSpecificationControl(identifier, true, true),
			),
			int64(ldapwire.ResultSuccess),
		)
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 5, true, identifier),
		int64(ldapwire.ResultEntryAlreadyExists),
	)

	partition := configuredDatabasePartition("{1}mdb")
	err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Metadata(syncContextCSNMetadataKey(partition))
		return err
	})
	if !errors.Is(err, storage.ErrMetadataNotFound) {
		t.Fatalf("rolled-back contextCSN metadata error = %v", err)
	}
}

func testLDAPTransactionFailureRollsBackAndReturnsMessageID(
	t *testing.T,
	store storage.Store,
) {
	t.Helper()

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
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("duplicate")
	for _, messageID := range []int64{3, 4} {
		assertRawLDAPResult(
			t,
			sendRawLDAPOperation(
				t,
				connection,
				messageID,
				rawAddRequest(entry),
				rawTransactionSpecificationControl(identifier, true, true),
			),
			int64(ldapwire.ResultSuccess),
		)
	}

	response := endRawLDAPTransaction(t, connection, 5, true, identifier)
	assertRawLDAPResult(
		t,
		response,
		int64(ldapwire.ResultEntryAlreadyExists),
	)
	value, present := rawExtendedResponseValue(response)
	if !present {
		t.Fatal("failed transaction response value is absent")
	}
	decoded, err := ldapwire.DecodeTransactionEndResponseValue(value)
	if err != nil {
		t.Fatalf("DecodeTransactionEndResponseValue(): %v", err)
	}
	if !decoded.HasFailedMessageID || decoded.FailedMessageID != 4 {
		t.Fatalf("transaction end response = %#v, want failed message ID 4", decoded)
	}
	if transactionEntryExists(t, store, entry.DN) {
		t.Fatal("failed transaction left its first Add committed")
	}
}

func TestLDAPTransactionAbortDiscardsQueuedUpdates(t *testing.T) {
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
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("aborted")
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
	response := endRawLDAPTransaction(t, connection, 4, false, identifier)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	if transactionEntryExists(t, store, entry.DN) {
		t.Fatal("aborted transaction committed its queued Add")
	}
}

func TestLDAPTransactionModifyDNAndDeleteShareOneView(t *testing.T) {
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
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	oldDN := "uid=alice,ou=people,dc=example,dc=com"
	newDN := "uid=transaction-renamed,ou=people,dc=example,dc=com"
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawModifyDNRequest(oldDN, "uid=transaction-renamed", true),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			4,
			rawDeleteRequest(newDN),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 5, true, identifier),
		int64(ldapwire.ResultSuccess),
	)
	if transactionEntryExists(t, store, oldDN) ||
		transactionEntryExists(t, store, newDN) {
		t.Fatal("transactional ModifyDN/Delete did not commit in request order")
	}
}

func TestLDAPBindAbortsOutstandingTransaction(t *testing.T) {
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
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("bind-abort")
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
	bindResponse := sendRawLDAPOperation(
		t,
		connection,
		4,
		rawSimpleBindRequest(
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		),
	)
	assertRawLDAPMessageID(t, bindResponse, 4)
	assertRawLDAPResult(t, bindResponse, int64(ldapwire.ResultSuccess))
	response := endRawLDAPTransaction(t, connection, 5, true, identifier)
	assertRawLDAPResult(
		t,
		response,
		int64(ldapwire.ResultTransactionIDInvalid),
	)
	if transactionEntryExists(t, store, entry.DN) {
		t.Fatal("Bind-aborted transaction committed its queued Add")
	}
}

func TestLDAPTransactionStateErrors(t *testing.T) {
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
	defer connection.Close()

	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			2,
			rawExtendedRequest(transactionStartOID, []byte{}, true),
		),
		int64(ldapwire.ResultProtocolError),
	)
	identifier := startRawLDAPTransaction(t, connection, 3)
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			4,
			rawExtendedRequest(transactionStartOID, nil, false),
		),
		int64(ldapwire.ResultBusy),
	)

	preRead := rawControlWithValue(
		preReadControlOID,
		true,
		ber.NewSequence("AttributeSelection").Bytes(),
	)
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			5,
			rawModifyReplaceRequest(
				"uid=alice,ou=people,dc=example,dc=com",
				"cn",
				"Not Applied",
			),
			rawTransactionSpecificationControl(identifier, true, true),
			preRead,
		),
		int64(ldapwire.ResultUnwillingToPerform),
	)

	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 6, true, identifier),
		int64(ldapwire.ResultOperationsError),
	)
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 7, false, identifier),
		int64(ldapwire.ResultTransactionIDInvalid),
	)
}

func TestLDAPTransactionRejectsInvalidSpecificationControls(t *testing.T) {
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
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)

	tests := []struct {
		name     string
		controls []*ber.Packet
		want     ldapwire.ResultCode
	}{
		{
			name: "noncritical",
			controls: []*ber.Packet{
				rawTransactionSpecificationControl(identifier, false, true),
			},
			want: ldapwire.ResultProtocolError,
		},
		{
			name: "absent value",
			controls: []*ber.Packet{
				rawTransactionSpecificationControl(nil, true, false),
			},
			want: ldapwire.ResultProtocolError,
		},
		{
			name: "wrong identifier",
			controls: []*ber.Packet{
				rawTransactionSpecificationControl([]byte("wrong"), true, true),
			},
			want: ldapwire.ResultTransactionIDInvalid,
		},
		{
			name: "duplicate",
			controls: []*ber.Packet{
				rawTransactionSpecificationControl(identifier, true, true),
				rawTransactionSpecificationControl(identifier, true, true),
			},
			want: ldapwire.ResultProtocolError,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := sendRawLDAPOperation(
				t,
				connection,
				int64(index+3),
				rawAddRequest(transactionTestPerson(test.name)),
				test.controls...,
			)
			assertRawLDAPResult(t, response, int64(test.want))
		})
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 10, false, identifier),
		int64(ldapwire.ResultSuccess),
	)
}

func TestLDAPTransactionCannotSpanDatabaseContexts(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSecondTransactionDatabase(t, store)
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
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)

	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawAddRequest(transactionTestPerson("first")),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	other := directory.Entry{
		DN: "uid=second,dc=other,dc=example",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("second")},
			{Description: "cn", Values: stringValues("Second")},
			{Description: "sn", Values: stringValues("Second")},
		},
	}
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			4,
			rawAddRequest(other),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultAffectsMultipleDSAs),
	)
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 5, false, identifier),
		int64(ldapwire.ResultSuccess),
	)
}

func TestLDAPPasswordModifyInTransaction(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"uid=alice,ou=people,dc=example,dc=com",
		"secret",
	)
	identifier := startRawLDAPTransaction(t, connection, 2)
	passwordValue := rawPasswordModifyRequestValue(
		[]byte("secret"),
		[]byte("transaction-secret"),
	)
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawExtendedRequest(passwordModifyOID, passwordValue, true),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 4, true, identifier),
		int64(ldapwire.ResultSuccess),
	)
	_ = connection.Close()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"uid=alice,ou=people,dc=example,dc=com",
		"transaction-secret",
	); err != nil {
		t.Fatalf("Bind with transaction password: %v", err)
	}
}

func TestLDAPTransactionDiscovery(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedExtension", "supportedControl"},
		nil,
	))
	if err != nil {
		t.Fatalf("Root DSE Search(): %v", err)
	}
	extensions := result.Entries[0].GetAttributeValues("supportedExtension")
	controls := result.Entries[0].GetAttributeValues("supportedControl")
	if !containsString(extensions, transactionStartOID) ||
		!containsString(extensions, transactionEndOID) ||
		!containsString(controls, transactionSpecificationControlOID) {
		t.Fatalf(
			"transaction discovery extensions=%q controls=%q",
			extensions,
			controls,
		)
	}
}

func TestOpenLDAPLDAPModifyTransactionInteroperability(t *testing.T) {
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run the OpenLDAP ldapmodify interoperability test",
			openLDAPReferenceTestsEnv,
		)
	}
	ldapmodify, err := exec.LookPath("ldapmodify")
	if err != nil {
		t.Skip("OpenLDAP ldapmodify is not installed")
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	committedDN := "uid=openldap-commit,ou=people,dc=example,dc=com"
	runOpenLDAPLDAPModifyTransaction(
		t,
		ldapmodify,
		address,
		"commit",
		`dn: `+committedDN+`
changetype: add
objectClass: inetOrgPerson
uid: openldap-commit
cn: OpenLDAP Transaction
sn: Transaction

dn: `+committedDN+`
changetype: modify
replace: cn
cn: OpenLDAP Transaction Committed

`,
	)
	committed := readStoredEntry(t, store, committedDN)
	if got := string(committed.Values("cn")[0]); got != "OpenLDAP Transaction Committed" {
		t.Fatalf("OpenLDAP transaction cn = %q", got)
	}

	abortedDN := "uid=openldap-abort,ou=people,dc=example,dc=com"
	runOpenLDAPLDAPModifyTransaction(
		t,
		ldapmodify,
		address,
		"abort",
		`dn: `+abortedDN+`
changetype: add
objectClass: inetOrgPerson
uid: openldap-abort
cn: OpenLDAP Transaction Abort
sn: Transaction

`,
	)
	if transactionEntryExists(t, store, abortedDN) {
		t.Fatal("OpenLDAP ldapmodify abort committed its Add")
	}
}

func TestOpenLDAPReferenceTransactionRollback(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServer(t, tools, nil)
	defer stop()

	address := strings.TrimPrefix(uri, "ldap://")
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("openldap-rollback")
	for _, messageID := range []int64{3, 4} {
		assertRawLDAPResult(
			t,
			sendRawLDAPOperation(
				t,
				connection,
				messageID,
				rawAddRequest(entry),
				rawTransactionSpecificationControl(identifier, true, true),
			),
			int64(ldapwire.ResultSuccess),
		)
	}
	response := endRawLDAPTransaction(t, connection, 5, true, identifier)
	assertRawLDAPResult(
		t,
		response,
		int64(ldapwire.ResultEntryAlreadyExists),
	)
	value, present := rawExtendedResponseValue(response)
	if !present {
		t.Fatal("OpenLDAP failed transaction response value is absent")
	}
	decoded, err := ldapwire.DecodeTransactionEndResponseValue(value)
	if err != nil {
		t.Fatalf("decode OpenLDAP txnEndRes: %v", err)
	}
	if !decoded.HasFailedMessageID || decoded.FailedMessageID != 4 {
		t.Fatalf("OpenLDAP txnEndRes = %#v, want failed message ID 4", decoded)
	}

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(OpenLDAP): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(OpenLDAP): %v", err)
	}
	_, err = client.Search(ldap.NewSearchRequest(
		entry.DN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		1,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}

func runOpenLDAPLDAPModifyTransaction(
	t *testing.T,
	ldapmodify, address, settlement, ldif string,
) {
	t.Helper()
	command := exec.Command(
		ldapmodify,
		"-x",
		"-H",
		"ldap://"+address,
		"-D",
		"cn=admin,dc=example,dc=com",
		"-w",
		"admin-secret",
		"-E",
		"txn="+settlement,
	)
	command.Stdin = bytes.NewBufferString(ldif)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"ldapmodify transaction %s: %v\n%s",
			settlement,
			err,
			output,
		)
	}
}

func startRawLDAPTransaction(
	t *testing.T,
	connection net.Conn,
	messageID int64,
) []byte {
	t.Helper()
	response := sendRawLDAPOperation(
		t,
		connection,
		messageID,
		rawExtendedRequest(transactionStartOID, nil, false),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	identifier, present := rawExtendedResponseValue(response)
	if !present || len(identifier) != 0 {
		t.Fatalf("transaction identifier = %x, want explicitly present empty value", identifier)
	}
	return identifier
}

func endRawLDAPTransaction(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	commit bool,
	identifier []byte,
) *ber.Packet {
	t.Helper()
	value := ldapwire.EncodeTransactionEndRequestValue(
		ldapwire.TransactionEndRequestValue{
			Commit:     commit,
			Identifier: identifier,
		},
	)
	return sendRawLDAPOperation(
		t,
		connection,
		messageID,
		rawExtendedRequest(transactionEndOID, value, true),
	)
}

func rawTransactionSpecificationControl(
	identifier []byte,
	critical bool,
	hasValue bool,
) *ber.Packet {
	control := ber.NewSequence("TransactionSpecificationControl")
	control.AppendChild(rawOctetString([]byte(
		transactionSpecificationControlOID,
	)))
	if critical {
		control.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	if hasValue {
		control.AppendChild(rawOctetString(identifier))
	}
	return control
}

func rawControlWithValue(
	oid string,
	critical bool,
	value []byte,
) *ber.Packet {
	control := ber.NewSequence("Control")
	control.AppendChild(rawOctetString([]byte(oid)))
	if critical {
		control.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	control.AppendChild(rawOctetString(value))
	return control
}

func rawExtendedResponseValue(response *ber.Packet) ([]byte, bool) {
	if response == nil || len(response.Children) < 2 {
		return nil, false
	}
	for _, child := range response.Children[1].Children {
		if child.ClassType == ber.ClassContext &&
			child.TagType == ber.TypePrimitive &&
			child.Tag == 11 {
			return bytes.Clone(child.Data.Bytes()), true
		}
	}
	return nil, false
}

func rawSimpleBindRequest(dn, password string) *ber.Packet {
	return rawSimpleBindRequestVersion(3, dn, password)
}

func rawSimpleBindRequestVersion(
	version int64,
	dn, password string,
) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		version,
		"version",
	))
	request.AppendChild(rawOctetString([]byte(dn)))
	authentication := ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		nil,
		"simple authentication",
	)
	_, _ = authentication.Data.Write([]byte(password))
	request.AppendChild(authentication)
	return request
}

func rawPasswordModifyRequestValue(oldPassword, newPassword []byte) []byte {
	value := ber.NewSequence("PasswordModifyRequestValue")
	for _, elementValue := range []struct {
		tag      ber.Tag
		password []byte
	}{
		{tag: 1, password: oldPassword},
		{tag: 2, password: newPassword},
	} {
		element := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			elementValue.tag,
			nil,
			"password",
		)
		_, _ = element.Data.Write(elementValue.password)
		value.AppendChild(element)
	}
	return value.Bytes()
}

func transactionTestPerson(uid string) directory.Entry {
	return directory.Entry{
		DN: "uid=" + uid + ",ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues("Transaction User")},
			{Description: "sn", Values: stringValues("User")},
		},
	}
}

func transactionEntryExists(
	t *testing.T,
	store storage.Store,
	rawDN string,
) bool {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		return err
	})
	switch {
	case err == nil:
		return true
	case errors.Is(err, storage.ErrEntryNotFound):
		return false
	default:
		t.Fatalf("read transaction entry %q: %v", rawDN, err)
		return false
	}
}

func seedSecondTransactionDatabase(t *testing.T, store storage.Store) {
	t.Helper()
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(directory.Entry{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=other,dc=example")},
			},
		}, false); err != nil {
			return err
		}
		if err := writer.Put(directory.Entry{
			DN: "dc=other,dc=example",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("domain")},
				{Description: "dc", Values: stringValues("other")},
			},
		}, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{
			"dc=example,dc=com",
			"dc=other,dc=example",
		})
	})
	if err != nil {
		t.Fatalf("seed second transaction database: %v", err)
	}
}
