package saslkrb5

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	krbgssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestAcceptAPReqAndVerifyAPRep(t *testing.T) {
	const (
		realm            = "LDAP-GO.TEST"
		servicePrincipal = "ldap/ldap.test"
		servicePassword  = "service-password"
		clientPrincipal  = "alice"
	)
	kt := keytab.New()
	if err := kt.AddEntry(
		servicePrincipal,
		realm,
		servicePassword,
		time.Unix(1_700_000_000, 0).UTC(),
		1,
		etypeID.AES256_CTS_HMAC_SHA1_96,
	); err != nil {
		t.Fatalf("add keytab entry: %v", err)
	}
	cname := types.NewPrincipalName(1, clientPrincipal)
	sname, _ := types.ParseSPNString(servicePrincipal)
	now := time.Now().UTC().Truncate(time.Second)
	ticket, sessionKey, err := messages.NewTicket(
		cname,
		realm,
		sname,
		realm,
		types.NewKrbFlags(),
		kt,
		etypeID.AES256_CTS_HMAC_SHA1_96,
		1,
		now,
		now,
		now.Add(time.Hour),
		now.Add(2*time.Hour),
	)
	if err != nil {
		t.Fatalf("create service ticket: %v", err)
	}
	authenticator, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}
	authenticator.SeqNumber = 0x1020304
	authenticator.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  make([]byte, 24),
	}
	binary.LittleEndian.PutUint32(authenticator.Cksum.Checksum[:4], 16)
	binary.LittleEndian.PutUint32(
		authenticator.Cksum.Checksum[20:24],
		krbgssapi.ContextFlagMutual|krbgssapi.ContextFlagReplay|
			krbgssapi.ContextFlagSequence|krbgssapi.ContextFlagInteg,
	)
	request, err := messages.NewAPReq(ticket, sessionKey, authenticator)
	if err != nil {
		t.Fatalf("create AP-REQ: %v", err)
	}
	encoded := marshalTestAPReq(t, request)

	if _, err := AcceptAPReq(encoded, kt, "ldap/other.test", nil); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong service error = %v", err)
	}
	accepted, err := AcceptAPReq(encoded, kt, servicePrincipal+"@"+realm, nil)
	if err != nil {
		t.Fatalf("accept AP-REQ: %v", err)
	}
	defer clear(accepted.Key.KeyValue)
	defer clear(accepted.APRep)
	if accepted.Principal != clientPrincipal+"@"+realm ||
		accepted.User != clientPrincipal || accepted.Realm != realm {
		t.Fatalf("accepted identity = %#v", accepted)
	}
	if bytes.Equal(accepted.Key.KeyValue, sessionKey.KeyValue) ||
		!accepted.AcceptorSubkey {
		t.Fatal("acceptor did not establish an independent AP-REP subkey")
	}
	if accepted.ReceiveSequence != uint64(authenticator.SeqNumber) {
		t.Fatalf(
			"acceptor receive sequence = %d, want %d",
			accepted.ReceiveSequence,
			authenticator.SeqNumber,
		)
	}

	initiator := &Initiator{
		serviceKey:    cloneKey(sessionKey),
		authenticator: authenticator,
		sendSequence:  uint64(authenticator.SeqNumber),
	}
	defer initiator.Close()
	if err := initiator.AcceptAPRep(accepted.APRep); err != nil {
		t.Fatalf("verify AP-REP: %v", err)
	}
	contextKey, err := initiator.ContextKey()
	if err != nil {
		t.Fatalf("context key: %v", err)
	}
	defer clear(contextKey.KeyValue)
	if !bytes.Equal(contextKey.KeyValue, accepted.Key.KeyValue) {
		t.Fatal("initiator context key does not match AP-REP acceptor subkey")
	}
	state, err := initiator.SecurityState()
	if err != nil {
		t.Fatalf("context state: %v", err)
	}
	if state.SendSequence != uint64(authenticator.SeqNumber) ||
		state.ReceiveSequence != accepted.SendSequence ||
		!state.AcceptorSubkey {
		t.Fatalf("initiator security state = %#v, accepted = %#v", state, accepted)
	}

	mismatch := &Initiator{
		serviceKey:    cloneKey(sessionKey),
		authenticator: authenticator,
	}
	mismatch.authenticator.Cusec++
	defer mismatch.Close()
	if err := mismatch.AcceptAPRep(accepted.APRep); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched AP-REP error = %v", err)
	}
}

func marshalTestAPReq(t *testing.T, request messages.APReq) []byte {
	t.Helper()
	encodedRequest, err := request.Marshal()
	if err != nil {
		t.Fatalf("marshal AP-REQ: %v", err)
	}
	oid, err := asn1.Marshal(krbgssapi.OIDKRB5.OID())
	if err != nil {
		t.Fatalf("marshal Kerberos OID: %v", err)
	}
	body := append(append(append([]byte(nil), oid...), 0x01, 0x00), encodedRequest...)
	return asn1tools.AddASNAppTag(body, 0)
}
