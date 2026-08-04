package server

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPTransactionGeneratedPasswordIsReturnedAndCommitted(t *testing.T) {
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
	response := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawExtendedRequest(
			passwordModifyOID,
			rawTransactionPasswordModifyRequestValue(nil, []byte("secret")),
			true,
		),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPMessageID(t, response, 3)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	generated := rawGeneratedPassword(t, response)
	defer clear(generated)
	if len(generated) != generatedPasswordLength {
		t.Fatalf("generated password length = %d, want %d", len(generated), generatedPasswordLength)
	}

	endResponse := endRawLDAPTransaction(t, connection, 4, true, identifier)
	assertRawLDAPMessageID(t, endResponse, 4)
	assertRawLDAPResult(t, endResponse, int64(ldapwire.ResultSuccess))
	if value, present := rawExtendedResponseValue(endResponse); present {
		t.Fatalf("successful txnEndRes unexpectedly present: %x", value)
	}
	_ = connection.Close()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"uid=alice,ou=people,dc=example,dc=com",
		string(generated),
	); err != nil {
		t.Fatalf("Bind with generated transaction password: %v", err)
	}
}

func TestLDAPTransactionGeneratedPasswordRollsBackWithLaterFailure(t *testing.T) {
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
	response := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawExtendedRequest(
			passwordModifyOID,
			rawTransactionPasswordModifyRequestValue(
				[]byte("uid=alice,ou=people,dc=example,dc=com"),
				nil,
			),
			true,
		),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	generated := rawGeneratedPassword(t, response)
	defer clear(generated)

	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			4,
			rawAddRequest(transactionTestPerson("alice")),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	endResponse := endRawLDAPTransaction(t, connection, 5, true, identifier)
	assertRawLDAPResult(t, endResponse, int64(ldapwire.ResultEntryAlreadyExists))
	endValue, present := rawExtendedResponseValue(endResponse)
	if !present {
		t.Fatal("failed transaction response value is absent")
	}
	decoded, err := ldapwire.DecodeTransactionEndResponseValue(endValue)
	if err != nil {
		t.Fatalf("DecodeTransactionEndResponseValue(): %v", err)
	}
	if !decoded.HasFailedMessageID || decoded.FailedMessageID != 4 {
		t.Fatalf("txnEndRes = %#v, want failed message ID 4", decoded)
	}
	_ = connection.Close()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	assertLDAPResultCode(
		t,
		client.Bind("uid=alice,ou=people,dc=example,dc=com", string(generated)),
		ldap.LDAPResultInvalidCredentials,
	)
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind with rolled-back original password: %v", err)
	}
}

func rawTransactionPasswordModifyRequestValue(userIdentity, oldPassword []byte) []byte {
	value := ber.NewSequence("PasswordModifyRequestValue")
	for _, element := range []struct {
		tag     ber.Tag
		value   []byte
		present bool
	}{
		{tag: 0, value: userIdentity, present: userIdentity != nil},
		{tag: 1, value: oldPassword, present: oldPassword != nil},
	} {
		if !element.present {
			continue
		}
		child := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			element.tag,
			nil,
			"password",
		)
		_, _ = child.Data.Write(element.value)
		value.AppendChild(child)
	}
	return value.Bytes()
}

func rawGeneratedPassword(t *testing.T, response *ber.Packet) []byte {
	t.Helper()
	value, present := rawExtendedResponseValue(response)
	if !present {
		t.Fatal("Password Modify generated password response value is absent")
	}
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		t.Fatalf("decode PasswordModifyResponseValue: %v", err)
	}
	if packet.ClassType != ber.ClassUniversal ||
		packet.TagType != ber.TypeConstructed ||
		packet.Tag != ber.TagSequence ||
		len(packet.Children) != 1 {
		t.Fatalf("invalid PasswordModifyResponseValue: %#v", packet)
	}
	generated := packet.Children[0]
	if generated.ClassType != ber.ClassContext ||
		generated.TagType != ber.TypePrimitive ||
		generated.Tag != 0 {
		t.Fatalf("invalid generated password element: %#v", generated)
	}
	return bytes.Clone(generated.Data.Bytes())
}
