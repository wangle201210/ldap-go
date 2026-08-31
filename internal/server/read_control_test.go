package server

import (
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPReadControlsOnWriteOperations(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	const rootDN = "cn=admin,dc=example,dc=com"
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, rootDN, "admin-secret")
	defer connection.Close()

	rollbackDN := "uid=read-rollback,ou=people,dc=example,dc=com"
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawAddRequest(readControlTestEntry(rollbackDN, "read-rollback")),
		rawReadControl(postReadControlOID, true, "notInSchema"),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultUndefinedAttributeType))
	if entryExists(t, store, rollbackDN) {
		t.Fatal("critical post-read failure did not roll back Add")
	}

	addedDN := "uid=read-added,ou=people,dc=example,dc=com"
	response = sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(readControlTestEntry(addedDN, "read-added")),
		rawReadControl(postReadControlOID, true, "cn", "entryUUID"),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	added := rawReadControlEntry(t, response, postReadControlOID)
	if added.DN != addedDN ||
		singleRawValue(t, added, "cn") != "Read Control User" ||
		singleRawValue(t, added, "entryUUID") == "" ||
		added.HasAttribute("sn") {
		t.Fatalf("Add post-read entry = %#v", added)
	}

	response = sendRawLDAPOperation(
		t,
		connection,
		4,
		rawModifyReplaceRequest(addedDN, "cn", "Updated Read User"),
		rawReadControl(preReadControlOID, true, "cn"),
		rawReadControl(postReadControlOID, true, "cn"),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	preModify := rawReadControlEntry(t, response, preReadControlOID)
	postModify := rawReadControlEntry(t, response, postReadControlOID)
	if preModify.DN != addedDN ||
		singleRawValue(t, preModify, "cn") != "Read Control User" ||
		postModify.DN != addedDN ||
		singleRawValue(t, postModify, "cn") != "Updated Read User" {
		t.Fatalf("Modify read controls = pre %#v, post %#v", preModify, postModify)
	}

	renamedDN := "uid=read-renamed,ou=people,dc=example,dc=com"
	response = sendRawLDAPOperation(
		t,
		connection,
		5,
		rawModifyDNRequest(addedDN, "uid=read-renamed", true),
		rawReadControl(preReadControlOID, true, "uid", "cn"),
		rawReadControl(postReadControlOID, true, "uid", "cn"),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	preRename := rawReadControlEntry(t, response, preReadControlOID)
	postRename := rawReadControlEntry(t, response, postReadControlOID)
	if preRename.DN != addedDN ||
		singleRawValue(t, preRename, "uid") != "read-added" ||
		postRename.DN != renamedDN ||
		singleRawValue(t, postRename, "uid") != "read-renamed" {
		t.Fatalf("ModifyDN read controls = pre %#v, post %#v", preRename, postRename)
	}

	response = sendRawLDAPOperation(
		t,
		connection,
		6,
		rawDeleteRequest(renamedDN),
		rawReadControl(preReadControlOID, true),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	deleted := rawReadControlEntry(t, response, preReadControlOID)
	if deleted.DN != renamedDN ||
		singleRawValue(t, deleted, "cn") != "Updated Read User" ||
		deleted.HasAttribute("entryUUID") {
		t.Fatalf("Delete pre-read entry = %#v", deleted)
	}
	if entryExists(t, store, renamedDN) {
		t.Fatal("Delete with pre-read control did not remove entry")
	}
}

func TestLDAPReadControlsApplyReadACL(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, aliceDN, "secret")
	defer connection.Close()

	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawModifyReplaceRequest(aliceDN, "cn", "Alice Updated"),
		rawReadControl(preReadControlOID, true, "cn", "userPassword"),
		rawReadControl(postReadControlOID, true, "cn", "userPassword"),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	preRead := rawReadControlEntry(t, response, preReadControlOID)
	postRead := rawReadControlEntry(t, response, postReadControlOID)
	if singleRawValue(t, preRead, "cn") != "Alice Example" ||
		singleRawValue(t, postRead, "cn") != "Alice Updated" ||
		preRead.HasAttribute("userPassword") ||
		postRead.HasAttribute("userPassword") {
		t.Fatalf("ACL-filtered read controls = pre %#v, post %#v", preRead, postRead)
	}
}

func TestParseReadControls(t *testing.T) {
	t.Parallel()

	value := rawAttributeSelection("cn")
	valid := ldapwire.Control{
		OID:      preReadControlOID,
		Critical: true,
		Value:    value,
		HasValue: true,
	}
	parsed, result := parseRequestControls(
		[]ldapwire.Control{valid},
		supportsPreRead,
	)
	if result != nil || parsed.preRead == nil ||
		len(parsed.preRead.attributes) != 1 ||
		parsed.preRead.attributes[0] != "cn" {
		t.Fatalf("valid pre-read control = %#v, %#v", parsed, result)
	}

	tests := []struct {
		name      string
		controls  []ldapwire.Control
		supported requestControlSupport
		wantCode  ldapwire.ResultCode
	}{
		{
			name:      "absent value",
			controls:  []ldapwire.Control{{OID: preReadControlOID}},
			supported: supportsPreRead,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name: "empty value",
			controls: []ldapwire.Control{{
				OID:      postReadControlOID,
				HasValue: true,
			}},
			supported: supportsPostRead,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name: "malformed value",
			controls: []ldapwire.Control{{
				OID:      preReadControlOID,
				Value:    []byte{0x04, 0x00},
				HasValue: true,
			}},
			supported: supportsPreRead,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name:      "duplicate",
			controls:  []ldapwire.Control{valid, valid},
			supported: supportsPreRead,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name: "critical on unsupported operation",
			controls: []ldapwire.Control{{
				OID:      preReadControlOID,
				Critical: true,
				Value:    value,
				HasValue: true,
			}},
			supported: supportsPostRead,
			wantCode:  ldapwire.ResultUnavailableCriticalExtension,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, result := parseRequestControls(test.controls, test.supported)
			if result == nil || result.Code != test.wantCode {
				t.Fatalf("parseRequestControls() result = %#v", result)
			}
		})
	}

	parsed, result = parseRequestControls(
		[]ldapwire.Control{{
			OID:      preReadControlOID,
			Critical: false,
			Value:    []byte{0x04, 0x00},
			HasValue: true,
		}},
		supportsPostRead,
	)
	if result != nil || parsed.preRead != nil {
		t.Fatalf("unsupported noncritical pre-read = %#v, %#v", parsed, result)
	}
}

func readControlTestEntry(dn, uid string) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues("Read Control User")},
			{Description: "sn", Values: stringValues("User")},
		},
	}
}

func dialAndBindRawLDAP(
	t *testing.T,
	address, bindDN, password string,
) net.Conn {
	t.Helper()

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		connection.Close()
		t.Fatalf("SetDeadline(): %v", err)
	}
	bind := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	bind.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(3),
		"version",
	))
	bind.AppendChild(rawOctetString([]byte(bindDN)))
	authentication := ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		nil,
		"simple authentication",
	)
	_, _ = authentication.Data.Write([]byte(password))
	bind.AppendChild(authentication)
	response := sendRawLDAPOperation(t, connection, 1, bind)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	return connection
}

func sendRawLDAPOperation(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	operation *ber.Packet,
	controls ...*ber.Packet,
) *ber.Packet {
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
	if len(controls) > 0 {
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
	if err := ldapwire.Write(connection, message.Bytes()); err != nil {
		t.Fatalf("write LDAP operation: %v", err)
	}
	response, err := ber.ReadPacket(connection)
	if err != nil {
		t.Fatalf("read LDAP response: %v", err)
	}
	return response
}

func rawAddRequest(entry directory.Entry) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationAddRequest,
		nil,
		"AddRequest",
	)
	request.AppendChild(rawOctetString([]byte(entry.DN)))
	attributes := ber.NewSequence("attributes")
	for _, attribute := range entry.Attributes {
		attributes.AppendChild(rawPartialAttribute(
			attribute.Description,
			attribute.Values,
		))
	}
	request.AppendChild(attributes)
	return request
}

func rawModifyReplaceRequest(
	dn, description string,
	values ...string,
) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationModifyRequest,
		nil,
		"ModifyRequest",
	)
	request.AppendChild(rawOctetString([]byte(dn)))
	changes := ber.NewSequence("changes")
	change := ber.NewSequence("change")
	change.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(ldapwire.ModificationReplace),
		"replace",
	))
	rawValues := make([][]byte, len(values))
	for index := range values {
		rawValues[index] = []byte(values[index])
	}
	change.AppendChild(rawPartialAttribute(description, rawValues))
	changes.AppendChild(change)
	request.AppendChild(changes)
	return request
}

func rawDeleteRequest(dn string) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypePrimitive,
		ldapwire.ApplicationDeleteRequest,
		nil,
		"DeleteRequest",
	)
	_, _ = request.Data.Write([]byte(dn))
	return request
}

func rawModifyDNRequest(
	dn, newRDN string,
	deleteOldRDN bool,
) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationModifyDNRequest,
		nil,
		"ModifyDNRequest",
	)
	request.AppendChild(rawOctetString([]byte(dn)))
	request.AppendChild(rawOctetString([]byte(newRDN)))
	request.AppendChild(ber.NewBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		deleteOldRDN,
		"deleteOldRDN",
	))
	return request
}

func rawPartialAttribute(
	description string,
	values [][]byte,
) *ber.Packet {
	attribute := ber.NewSequence("PartialAttribute")
	attribute.AppendChild(rawOctetString([]byte(description)))
	set := ber.Encode(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSet,
		nil,
		"values",
	)
	for _, value := range values {
		set.AppendChild(rawOctetString(value))
	}
	attribute.AppendChild(set)
	return attribute
}

func rawReadControl(
	oid string,
	critical bool,
	attributes ...string,
) *ber.Packet {
	control := ber.NewSequence("Control")
	control.AppendChild(rawOctetString([]byte(oid)))
	if critical {
		control.AppendChild(ber.NewBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	control.AppendChild(rawOctetString(rawAttributeSelection(attributes...)))
	return control
}

func rawAttributeSelection(attributes ...string) []byte {
	selection := ber.NewSequence("AttributeSelection")
	for _, attribute := range attributes {
		selection.AppendChild(rawOctetString([]byte(attribute)))
	}
	return selection.Bytes()
}

func rawOctetString(value []byte) *ber.Packet {
	packet := ber.Encode(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
		"LDAPString",
	)
	_, _ = packet.Data.Write(value)
	return packet
}

func assertRawLDAPResult(
	t *testing.T,
	response *ber.Packet,
	want int64,
) {
	t.Helper()

	if response == nil || len(response.Children) < 2 ||
		len(response.Children[1].Children) < 1 {
		t.Fatalf("malformed LDAP response: %#v", response)
	}
	code, err := ber.ParseInt64(response.Children[1].Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("decode LDAP result code: %v", err)
	}
	if code != want {
		t.Fatalf("LDAP result code = %d, want %d", code, want)
	}
}

func rawReadControlEntry(
	t *testing.T,
	response *ber.Packet,
	oid string,
) directory.Entry {
	t.Helper()

	if len(response.Children) != 3 {
		t.Fatalf("response controls missing for %s: %#v", oid, response)
	}
	for _, control := range response.Children[2].Children {
		if len(control.Children) < 2 ||
			control.Children[0].Data.String() != oid {
			continue
		}
		value := control.Children[len(control.Children)-1].Data.Bytes()
		packet, err := ber.DecodePacketErr(value)
		if err != nil {
			t.Fatalf("decode %s value: %v", oid, err)
		}
		if packet.ClassType != ber.ClassApplication ||
			packet.TagType != ber.TypeConstructed ||
			packet.Tag != ldapwire.ApplicationSearchResultEntry ||
			len(packet.Children) != 2 {
			t.Fatalf("invalid %s SearchResultEntry: %#v", oid, packet)
		}
		entry := directory.Entry{DN: packet.Children[0].Data.String()}
		for _, partial := range packet.Children[1].Children {
			if len(partial.Children) != 2 {
				t.Fatalf("invalid %s PartialAttribute: %#v", oid, partial)
			}
			attribute := directory.Attribute{
				Description: partial.Children[0].Data.String(),
			}
			for _, rawValue := range partial.Children[1].Children {
				attribute.Values = append(
					attribute.Values,
					append([]byte(nil), rawValue.Data.Bytes()...),
				)
			}
			entry.Attributes = append(entry.Attributes, attribute)
		}
		return entry
	}
	t.Fatalf("response control %s not found", oid)
	return directory.Entry{}
}

func singleRawValue(
	t *testing.T,
	entry directory.Entry,
	description string,
) string {
	t.Helper()

	values := entry.Values(description)
	if len(values) != 1 {
		t.Fatalf("%s values in %#v = %q, want one", description, entry, values)
	}
	return string(values[0])
}
