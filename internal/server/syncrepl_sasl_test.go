package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/xdg-go/scram"
)

func TestBindSyncConsumerSCRAMSHA256(t *testing.T) {
	t.Parallel()

	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()
	transport := &syncConsumerTransport{
		connection:       clientConnection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}
	config := syncConsumerConfig{
		bindMethod:         "sasl",
		saslMechanism:      "SCRAM-SHA-256",
		authenticationID:   "replicator",
		authorizationID:    "dn:cn=sync,dc=example,dc=com",
		credentials:        []byte("correct horse battery staple"),
		securityProperties: defaultSyncConsumerSASLSecurityProperties(),
	}

	serverError := make(chan error, 1)
	go func() {
		err := runSyncConsumerSCRAMTestServer(
			serverConnection,
			config,
		)
		_ = serverConnection.Close()
		serverError <- err
	}()
	bindErr := bindSyncConsumerSASL(transport, config)
	serveErr := <-serverError
	if bindErr != nil || serveErr != nil {
		t.Fatalf(
			"SCRAM bind/server errors = %v / %v",
			bindErr,
			serveErr,
		)
	}
}

func TestSyncConsumerSASLMechanismPayloads(t *testing.T) {
	t.Parallel()

	plainConfig := syncConsumerConfig{
		saslMechanism:    "PLAIN",
		authenticationID: "replicator",
		authorizationID:  "dn:cn=sync,dc=example,dc=com",
		credentials:      []byte("secret"),
	}
	mechanism, conversation, err := newSyncConsumerSASLConversation(
		plainConfig,
	)
	if err != nil {
		t.Fatalf("new PLAIN conversation: %v", err)
	}
	response, hasResponse, err := conversation.Initial()
	if err != nil {
		t.Fatalf("PLAIN initial response: %v", err)
	}
	wantPlain := []byte(
		"dn:cn=sync,dc=example,dc=com\x00replicator\x00secret",
	)
	if mechanism != "PLAIN" || !hasResponse ||
		!bytes.Equal(response, wantPlain) {
		t.Fatalf(
			"PLAIN initial response = %q/%t/%q",
			mechanism,
			hasResponse,
			response,
		)
	}

	cramConfig := syncConsumerConfig{
		saslMechanism:    "CRAM-MD5",
		authenticationID: "tim",
		credentials:      []byte("tanstaaftanstaaf"),
	}
	_, conversation, err = newSyncConsumerSASLConversation(cramConfig)
	if err != nil {
		t.Fatalf("new CRAM-MD5 conversation: %v", err)
	}
	response, hasResponse, err = conversation.Initial()
	if err != nil || hasResponse || response != nil {
		t.Fatalf(
			"CRAM-MD5 initial response = %q/%t/%v",
			response,
			hasResponse,
			err,
		)
	}
	response, err = conversation.Next(
		[]byte("<1896.697170952@postoffice.reston.mci.net>"),
	)
	if err != nil {
		t.Fatalf("CRAM-MD5 challenge: %v", err)
	}
	const wantCRAM = "tim b913a602c7eda7a495b4e6e7334d3890"
	if string(response) != wantCRAM ||
		!conversation.Done() ||
		!conversation.Valid() {
		t.Fatalf("CRAM-MD5 response = %q", response)
	}
}

func TestSyncConsumerSASLSecurityProperties(t *testing.T) {
	t.Parallel()

	defaults := defaultSyncConsumerSASLSecurityProperties()
	if err := validateSyncConsumerSASLSecurity(
		defaults,
		"PLAIN",
		0,
	); err == nil || !strings.Contains(err.Error(), "noplain") {
		t.Fatalf("plaintext PLAIN policy error = %v", err)
	}
	if err := validateSyncConsumerSASLSecurity(
		defaults,
		"PLAIN",
		128,
	); err != nil {
		t.Fatalf("TLS-protected PLAIN policy: %v", err)
	}

	properties, err := parseSyncConsumerSASLSecurityProperties(
		"none,noanonymous,minssf=128,maxssf=256,maxbufsize=0",
	)
	if err != nil {
		t.Fatalf("parse SASL security properties: %v", err)
	}
	if properties.noPlain ||
		!properties.noAnonymous ||
		properties.minSSF != 128 ||
		properties.maxSSF != 256 ||
		properties.maxBufferSize != 0 {
		t.Fatalf("SASL security properties = %#v", properties)
	}
	if err := validateSyncConsumerSASLSecurity(
		properties,
		"SCRAM-SHA-256",
		71,
	); err == nil || !strings.Contains(err.Error(), "minssf=128") {
		t.Fatalf("minimum SSF error = %v", err)
	}
}

func TestParseSyncConsumerLDAPResultRejectsMalformedResponses(t *testing.T) {
	t.Parallel()

	valid := encodeSyncConsumerTestBindResponse(
		7,
		ldap.LDAPResultSuccess,
		nil,
		false,
	)
	packet, err := ber.DecodePacketErr(valid)
	if err != nil {
		t.Fatalf("decode valid response: %v", err)
	}
	if _, err := parseSyncConsumerLDAPResult(
		packet,
		8,
		ldap.ApplicationBindResponse,
	); err == nil || !strings.Contains(err.Error(), "want 8") {
		t.Fatalf("message ID error = %v", err)
	}

	operation := packet.Children[1]
	operation.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		9,
		"unexpected",
		"unexpected",
	))
	if _, err := parseSyncConsumerLDAPResult(
		packet,
		7,
		ldap.ApplicationBindResponse,
	); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("unexpected result element error = %v", err)
	}
}

func TestReadSyncConsumerPacketRejectsOversizeFrame(t *testing.T) {
	t.Parallel()

	header := []byte{0x30, 0x84, 0x01, 0x00, 0x00, 0x01}
	if _, err := readSyncConsumerPacket(bytes.NewReader(header)); err == nil ||
		!strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("oversize frame error = %v", err)
	}
}

func TestParseSyncConsumerProviderURLLDAPI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		host  string
		path  string
	}{
		{
			value: "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi",
			host:  "/var/run/slapd/ldapi",
		},
		{
			value: "ldapi:///var/run/slapd/ldapi",
			path:  "/var/run/slapd/ldapi",
		},
	}
	for _, test := range tests {
		parsed, err := parseSyncConsumerProviderURL(test.value)
		if err != nil {
			t.Fatalf("parse %q: %v", test.value, err)
		}
		if parsed.Scheme != "ldapi" ||
			parsed.Host != test.host ||
			parsed.Path != test.path {
			t.Fatalf("parse %q = %#v", test.value, parsed)
		}
	}
}

func runSyncConsumerSCRAMTestServer(
	connection net.Conn,
	config syncConsumerConfig,
) error {
	credentialClient, err := scram.SHA256.NewClient(
		config.authenticationID,
		string(config.credentials),
		config.authorizationID,
	)
	if err != nil {
		return err
	}
	stored, err := credentialClient.GetStoredCredentialsWithError(
		scram.KeyFactors{
			Salt:  "fixed test salt",
			Iters: 4096,
		},
	)
	if err != nil {
		return err
	}
	server, err := scram.SHA256.NewServer(func(
		username string,
	) (scram.StoredCredentials, error) {
		if username != config.authenticationID {
			return scram.StoredCredentials{}, errors.New("unknown user")
		}
		return stored, nil
	})
	if err != nil {
		return err
	}
	conversation := server.NewConversation()

	first, err := ldapwire.ReadMessage(
		connection,
		ldapwire.DefaultMaxMessageSize,
	)
	if err != nil {
		return err
	}
	firstBind, ok := first.Request.(ldapwire.BindRequest)
	if !ok ||
		firstBind.Authentication.SASLMechanism != "SCRAM-SHA-256" {
		return fmt.Errorf("first request = %#v", first.Request)
	}
	serverFirst, err := conversation.Step(
		string(firstBind.Authentication.SASLCredentials),
	)
	if err != nil {
		return err
	}
	if conversation.AuthzID() == "" {
		return errors.New("SCRAM authzid was not sent")
	}
	if err := writeSyncConsumerPacket(
		connection,
		encodeSyncConsumerTestBindResponse(
			first.ID,
			ldap.LDAPResultSaslBindInProgress,
			[]byte(serverFirst),
			true,
		),
	); err != nil {
		return err
	}

	final, err := ldapwire.ReadMessage(
		connection,
		ldapwire.DefaultMaxMessageSize,
	)
	if err != nil {
		return err
	}
	finalBind, ok := final.Request.(ldapwire.BindRequest)
	if !ok ||
		finalBind.Authentication.SASLMechanism != "SCRAM-SHA-256" {
		return fmt.Errorf("final request = %#v", final.Request)
	}
	serverFinal, err := conversation.Step(
		string(finalBind.Authentication.SASLCredentials),
	)
	if err != nil {
		return err
	}
	if !conversation.Done() || !conversation.Valid() {
		return errors.New("SCRAM client proof is invalid")
	}
	return writeSyncConsumerPacket(
		connection,
		encodeSyncConsumerTestBindResponse(
			final.ID,
			ldap.LDAPResultSuccess,
			[]byte(serverFinal),
			true,
		),
	)
}

func encodeSyncConsumerTestBindResponse(
	messageID int64,
	resultCode uint16,
	credentials []byte,
	hasCredentials bool,
) []byte {
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	response := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldap.ApplicationBindResponse,
		nil,
		"BindResponse",
	)
	response.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(resultCode),
		"resultCode",
	))
	response.AppendChild(syncConsumerOctetString(nil, "matchedDN"))
	response.AppendChild(syncConsumerOctetString(nil, "diagnosticMessage"))
	if hasCredentials {
		credentialPacket := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			7,
			nil,
			"serverSaslCreds",
		)
		_, _ = credentialPacket.Data.Write(credentials)
		response.AppendChild(credentialPacket)
	}
	message.AppendChild(response)
	return message.Bytes()
}
