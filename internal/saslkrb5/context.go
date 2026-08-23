package saslkrb5

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	krbgssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

const kerberosTokenIDAPRep = "\x02\x00"

type Initiator struct {
	client             *client.Client
	serviceKey         types.EncryptionKey
	contextKey         types.EncryptionKey
	authenticator      types.Authenticator
	sendSequence       uint64
	receiveSequence    uint64
	acceptorSubkeyUsed bool
}

func NewInitiatorWithPassword(username, realm, password, configuration string) (*Initiator, error) {
	cfg, err := config.Load(configuration)
	if err != nil {
		return nil, err
	}
	return &Initiator{client: client.NewWithPassword(username, realm, password, cfg)}, nil
}

func NewInitiatorWithKeytab(username, realm, path, configuration string) (*Initiator, error) {
	cfg, err := config.Load(configuration)
	if err != nil {
		return nil, err
	}
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, err
	}
	return &Initiator{client: client.NewWithKeytab(username, realm, kt, cfg)}, nil
}

func NewInitiatorFromCCache(path, configuration string) (*Initiator, error) {
	cfg, err := config.Load(configuration)
	if err != nil {
		return nil, err
	}
	cache, err := credentials.LoadCCache(path)
	if err != nil {
		return nil, err
	}
	cl, err := client.NewFromCCache(cache, cfg)
	if err != nil {
		return nil, err
	}
	return &Initiator{client: cl}, nil
}

func (initiator *Initiator) InitialToken(target string, channelBinding []byte) ([]byte, error) {
	if initiator == nil || initiator.client == nil {
		return nil, errors.New("GSSAPI initiator is not initialized")
	}
	ticket, key, err := initiator.client.GetServiceTicket(target)
	if err != nil {
		return nil, err
	}
	authenticator, err := types.NewAuthenticator(
		initiator.client.Credentials.Domain(),
		initiator.client.Credentials.CName(),
	)
	if err != nil {
		return nil, err
	}
	flags := uint32(krbgssapi.ContextFlagMutual | krbgssapi.ContextFlagReplay |
		krbgssapi.ContextFlagSequence | krbgssapi.ContextFlagConf |
		krbgssapi.ContextFlagInteg)
	authenticator.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  authenticatorChecksum(flags, channelBinding),
	}
	request, err := messages.NewAPReq(ticket, key, authenticator)
	if err != nil {
		clear(authenticator.Cksum.Checksum)
		return nil, err
	}
	initiator.serviceKey = cloneKey(key)
	initiator.authenticator = authenticator
	initiator.sendSequence = uint64(authenticator.SeqNumber)
	encoded, err := marshalAPReqToken(request)
	if err != nil {
		initiator.clearContext()
		return nil, err
	}
	return encoded, nil
}

func marshalAPReqToken(request messages.APReq) ([]byte, error) {
	encodedRequest, err := request.Marshal()
	if err != nil {
		return nil, err
	}
	oid, err := asn1.Marshal(krbgssapi.OIDKRB5.OID())
	if err != nil {
		clear(encodedRequest)
		return nil, err
	}
	body := make([]byte, 0, len(oid)+2+len(encodedRequest))
	body = append(body, oid...)
	body = append(body, 0x01, 0x00)
	body = append(body, encodedRequest...)
	clear(encodedRequest)
	return asn1tools.AddASNAppTag(body, 0), nil
}

func authenticatorChecksum(flags uint32, applicationData []byte) []byte {
	checksum := make([]byte, 24)
	binary.LittleEndian.PutUint32(checksum[:4], 16)
	binding := channelBindingChecksum(applicationData)
	copy(checksum[4:20], binding[:])
	binary.LittleEndian.PutUint32(checksum[20:24], flags)
	return checksum
}

func (initiator *Initiator) AcceptAPRep(encoded []byte) error {
	if len(initiator.serviceKey.KeyValue) == 0 {
		return errors.New("GSSAPI AP-REQ has not been created")
	}
	var token spnego.KRB5Token
	if err := token.Unmarshal(encoded); err != nil {
		return fmt.Errorf("decode GSSAPI AP-REP: %w", err)
	}
	if !token.IsAPRep() {
		return errors.New("GSSAPI acceptor did not return an AP-REP")
	}
	plaintext, err := krbcrypto.DecryptEncPart(
		token.APRep.EncPart,
		initiator.serviceKey,
		keyusage.AP_REP_ENCPART,
	)
	if err != nil {
		return fmt.Errorf("decrypt GSSAPI AP-REP: %w", err)
	}
	defer clear(plaintext)
	var part messages.EncAPRepPart
	if err := part.Unmarshal(plaintext); err != nil {
		return fmt.Errorf("decode GSSAPI AP-REP body: %w", err)
	}
	if part.CTime.Unix() != initiator.authenticator.CTime.Unix() ||
		part.Cusec != initiator.authenticator.Cusec {
		return errors.New("GSSAPI AP-REP does not match the initiator authenticator")
	}
	initiator.contextKey = cloneKey(initiator.serviceKey)
	initiator.receiveSequence = uint64(part.SequenceNumber)
	initiator.acceptorSubkeyUsed = false
	if len(part.Subkey.KeyValue) != 0 {
		clear(initiator.contextKey.KeyValue)
		initiator.contextKey = cloneKey(part.Subkey)
		initiator.acceptorSubkeyUsed = true
	}
	return nil
}

func (initiator *Initiator) ContextKey() (types.EncryptionKey, error) {
	if initiator == nil || len(initiator.contextKey.KeyValue) == 0 {
		return types.EncryptionKey{}, errors.New("GSSAPI context is not established")
	}
	return cloneKey(initiator.contextKey), nil
}

// SecurityState returns the RFC 4121 per-message state established by the
// AP-REQ/AP-REP exchange. The caller advances each sequence after a
// successful GSS_Wrap or GSS_Unwrap operation.
func (initiator *Initiator) SecurityState() (SecurityState, error) {
	if initiator == nil || len(initiator.contextKey.KeyValue) == 0 {
		return SecurityState{}, errors.New("GSSAPI context is not established")
	}
	return SecurityState{
		SendSequence:    initiator.sendSequence,
		ReceiveSequence: initiator.receiveSequence,
		AcceptorSubkey:  initiator.acceptorSubkeyUsed,
	}, nil
}

func (initiator *Initiator) Close() error {
	if initiator == nil {
		return nil
	}
	initiator.clearContext()
	if initiator.client != nil {
		initiator.client.Destroy()
		initiator.client = nil
	}
	return nil
}

func (initiator *Initiator) clearContext() {
	clear(initiator.serviceKey.KeyValue)
	clear(initiator.contextKey.KeyValue)
	clear(initiator.authenticator.SubKey.KeyValue)
	initiator.serviceKey = types.EncryptionKey{}
	initiator.contextKey = types.EncryptionKey{}
	initiator.authenticator = types.Authenticator{}
	initiator.sendSequence = 0
	initiator.receiveSequence = 0
	initiator.acceptorSubkeyUsed = false
}

type AcceptedContext struct {
	Principal       string
	User            string
	Realm           string
	Key             types.EncryptionKey
	APRep           []byte
	Flags           uint32
	SendSequence    uint64
	ReceiveSequence uint64
	AcceptorSubkey  bool
}

func AcceptAPReq(encoded []byte, kt *keytab.Keytab, servicePrincipal string, channelBinding []byte) (AcceptedContext, error) {
	if kt == nil {
		return AcceptedContext{}, errors.New("GSSAPI acceptor keytab is not configured")
	}
	var token spnego.KRB5Token
	if err := token.Unmarshal(encoded); err != nil {
		return AcceptedContext{}, fmt.Errorf("decode GSSAPI AP-REQ: %w", err)
	}
	if !token.IsAPReq() {
		return AcceptedContext{}, errors.New("GSSAPI initiator did not send an AP-REQ")
	}
	if err := validateServicePrincipal(token.APReq, servicePrincipal); err != nil {
		return AcceptedContext{}, err
	}
	settings := service.NewSettings(kt, service.DecodePAC(false))
	valid, _, err := service.VerifyAPREQ(&token.APReq, settings)
	if err != nil {
		return AcceptedContext{}, fmt.Errorf("verify GSSAPI AP-REQ: %w", err)
	}
	if !valid {
		return AcceptedContext{}, errors.New("GSSAPI AP-REQ is not valid")
	}
	flags, err := validateAuthenticatorChecksum(token.APReq.Authenticator.Cksum, channelBinding)
	if err != nil {
		return AcceptedContext{}, err
	}
	baseKey := token.APReq.Ticket.DecryptedEncPart.Key
	contextKey := baseKey
	if len(token.APReq.Authenticator.SubKey.KeyValue) != 0 {
		contextKey = token.APReq.Authenticator.SubKey
	}
	apRep, acceptorKey, sendSequence, err := marshalAPRep(
		token.APReq.Authenticator,
		baseKey,
		contextKey,
	)
	if err != nil {
		return AcceptedContext{}, err
	}
	if len(acceptorKey.KeyValue) != 0 {
		contextKey = acceptorKey
		defer clear(acceptorKey.KeyValue)
	}
	user := token.APReq.Authenticator.CName.PrincipalNameString()
	realm := token.APReq.Authenticator.CRealm
	return AcceptedContext{
		Principal:       user + "@" + realm,
		User:            user,
		Realm:           realm,
		Key:             cloneKey(contextKey),
		APRep:           apRep,
		Flags:           flags,
		SendSequence:    sendSequence,
		ReceiveSequence: uint64(token.APReq.Authenticator.SeqNumber),
		AcceptorSubkey:  len(acceptorKey.KeyValue) != 0,
	}, nil
}

func validateAuthenticatorChecksum(checksum types.Checksum, channelBinding []byte) (uint32, error) {
	if checksum.CksumType != chksumtype.GSSAPI || len(checksum.Checksum) < 24 {
		return 0, errors.New("GSSAPI authenticator checksum is invalid")
	}
	if binary.LittleEndian.Uint32(checksum.Checksum[:4]) != 16 {
		return 0, errors.New("GSSAPI authenticator channel binding length is invalid")
	}
	flags := binary.LittleEndian.Uint32(checksum.Checksum[20:24])
	if flags&uint32(krbgssapi.ContextFlagDeleg) != 0 {
		return 0, errors.New("GSSAPI credential delegation is not accepted")
	}
	want := channelBindingChecksum(channelBinding)
	if !bytes.Equal(checksum.Checksum[4:20], want[:]) {
		return 0, errors.New("GSSAPI channel binding mismatch")
	}
	return flags, nil
}

func validateServicePrincipal(request messages.APReq, configured string) error {
	components := request.Ticket.SName.NameString
	if len(components) != 2 || !strings.EqualFold(components[0], "ldap") {
		return fmt.Errorf("GSSAPI ticket is for service %q, not ldap", request.Ticket.SName.PrincipalNameString())
	}
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return nil
	}
	principal, realm := types.ParseSPNString(configured)
	if len(principal.NameString) != 2 || !strings.EqualFold(principal.NameString[0], "ldap") ||
		!strings.EqualFold(principal.NameString[1], components[1]) ||
		(realm != "" && !strings.EqualFold(realm, request.Ticket.Realm)) {
		return fmt.Errorf("GSSAPI ticket service %q@%s does not match %q", request.Ticket.SName.PrincipalNameString(), request.Ticket.Realm, configured)
	}
	return nil
}

func marshalAPRep(
	authenticator types.Authenticator,
	encryptionKey types.EncryptionKey,
	contextKey types.EncryptionKey,
) ([]byte, types.EncryptionKey, uint64, error) {
	etype, err := krbcrypto.GetEtype(contextKey.KeyType)
	if err != nil {
		return nil, types.EncryptionKey{}, 0, fmt.Errorf(
			"select GSSAPI acceptor subkey type: %w",
			err,
		)
	}
	subkey := types.EncryptionKey{
		KeyType:  contextKey.KeyType,
		KeyValue: make([]byte, etype.GetKeyByteSize()),
	}
	if _, err := io.ReadFull(rand.Reader, subkey.KeyValue); err != nil {
		clear(subkey.KeyValue)
		return nil, types.EncryptionKey{}, 0, fmt.Errorf(
			"generate GSSAPI acceptor subkey: %w",
			err,
		)
	}
	sequence, err := randomSequenceNumber()
	if err != nil {
		clear(subkey.KeyValue)
		return nil, types.EncryptionKey{}, 0, err
	}
	part := messages.EncAPRepPart{
		CTime:          authenticator.CTime,
		Cusec:          authenticator.Cusec,
		Subkey:         subkey,
		SequenceNumber: int64(sequence),
	}
	encodedPart, err := asn1.Marshal(part)
	if err != nil {
		clear(subkey.KeyValue)
		return nil, types.EncryptionKey{}, 0, fmt.Errorf("encode GSSAPI AP-REP body: %w", err)
	}
	encodedPart = asn1tools.AddASNAppTag(encodedPart, asnAppTag.EncAPRepPart)
	defer clear(encodedPart)
	encrypted, err := krbcrypto.GetEncryptedData(
		encodedPart,
		encryptionKey,
		keyusage.AP_REP_ENCPART,
		0,
	)
	if err != nil {
		clear(subkey.KeyValue)
		return nil, types.EncryptionKey{}, 0, fmt.Errorf("encrypt GSSAPI AP-REP: %w", err)
	}
	reply := messages.APRep{PVNO: 5, MsgType: msgtype.KRB_AP_REP, EncPart: encrypted}
	encodedReply, err := asn1.Marshal(reply)
	if err != nil {
		clear(subkey.KeyValue)
		return nil, types.EncryptionKey{}, 0, fmt.Errorf("encode GSSAPI AP-REP: %w", err)
	}
	encodedReply = asn1tools.AddASNAppTag(encodedReply, asnAppTag.APREP)
	oid, err := asn1.Marshal(krbgssapi.OIDKRB5.OID())
	if err != nil {
		clear(encodedReply)
		clear(subkey.KeyValue)
		return nil, types.EncryptionKey{}, 0, fmt.Errorf("encode Kerberos mechanism OID: %w", err)
	}
	body := make([]byte, 0, len(oid)+len(kerberosTokenIDAPRep)+len(encodedReply))
	body = append(body, oid...)
	body = append(body, kerberosTokenIDAPRep...)
	body = append(body, encodedReply...)
	clear(encodedReply)
	return asn1tools.AddASNAppTag(body, 0), subkey, sequence, nil
}

func randomSequenceNumber() (uint64, error) {
	var encoded [4]byte
	if _, err := io.ReadFull(rand.Reader, encoded[:]); err != nil {
		return 0, fmt.Errorf("generate GSSAPI acceptor sequence number: %w", err)
	}
	return uint64(binary.BigEndian.Uint32(encoded[:]) & 0x3fffffff), nil
}

func cloneKey(key types.EncryptionKey) types.EncryptionKey {
	return types.EncryptionKey{KeyType: key.KeyType, KeyValue: bytes.Clone(key.KeyValue)}
}
