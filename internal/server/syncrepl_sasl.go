package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/xdg-go/scram"
)

const syncConsumerMaxSASLRounds = 16

type saslSecurityProperties struct {
	noDictionary    bool
	noPlain         bool
	noActive        bool
	passCredentials bool
	forwardSecrecy  bool
	noAnonymous     bool
	minSSF          uint32
	maxSSF          uint32
	maxBufferSize   uint32
}

type syncConsumerSASLSecurityProperties = saslSecurityProperties

type syncConsumerSASLConversation interface {
	Initial() ([]byte, bool, error)
	Next([]byte) ([]byte, error)
	Done() bool
	Valid() bool
}

type syncConsumerOneStepSASL struct {
	response []byte
	started  bool
}

type syncConsumerCRAMMD5 struct {
	authenticationID string
	password         []byte
	started          bool
	done             bool
}

type syncConsumerSCRAM struct {
	conversation *scram.ClientConversation
	started      bool
	plus         bool
	clientNonce  string
	proofSent    bool
	hashSize     int
}

type syncConsumerDIGESTMD5 struct {
	authenticationID string
	authorizationID  string
	realm            string
	host             string
	password         []byte
	properties       syncConsumerSASLSecurityProperties
	externalSSF      uint32
	random           io.Reader

	started         bool
	done            bool
	valid           bool
	expectedRspauth string
	qop             string
	cipher          saslDigestMD5Cipher
	peerMaxBuffer   uint32
	sessionKey      []byte
}

func defaultSyncConsumerSASLSecurityProperties() syncConsumerSASLSecurityProperties {
	return defaultSASLSecurityProperties()
}

func defaultSASLSecurityProperties() saslSecurityProperties {
	return syncConsumerSASLSecurityProperties{
		noPlain:       true,
		noAnonymous:   true,
		maxSSF:        math.MaxInt32,
		maxBufferSize: 65536,
	}
}

func parseSyncConsumerSASLSecurityProperties(
	value string,
) (syncConsumerSASLSecurityProperties, error) {
	return parseSASLSecurityProperties(value)
}

func parseSASLSecurityProperties(
	value string,
) (saslSecurityProperties, error) {
	properties := defaultSyncConsumerSASLSecurityProperties()
	if value == "" {
		return syncConsumerSASLSecurityProperties{}, errors.New(
			"security property list is empty",
		)
	}

	var (
		flagsSeen       bool
		noDictionary    bool
		noPlain         bool
		noActive        bool
		passCredentials bool
		forwardSecrecy  bool
		noAnonymous     bool
	)
	for _, rawProperty := range strings.Split(value, ",") {
		property := strings.ToLower(strings.TrimSpace(rawProperty))
		switch property {
		case "none":
			flagsSeen = true
		case "nodict":
			flagsSeen = true
			noDictionary = true
		case "noplain":
			flagsSeen = true
			noPlain = true
		case "noactive":
			flagsSeen = true
			noActive = true
		case "passcred":
			flagsSeen = true
			passCredentials = true
		case "forwardsec":
			flagsSeen = true
			forwardSecrecy = true
		case "noanonymous":
			flagsSeen = true
			noAnonymous = true
		default:
			parsed, recognized, err := parseSyncConsumerSASLUintProperty(
				property,
				"minssf=",
			)
			if err != nil {
				return syncConsumerSASLSecurityProperties{}, err
			}
			if recognized {
				properties.minSSF = parsed
				continue
			}
			parsed, recognized, err = parseSyncConsumerSASLUintProperty(
				property,
				"maxssf=",
			)
			if err != nil {
				return syncConsumerSASLSecurityProperties{}, err
			}
			if recognized {
				properties.maxSSF = parsed
				continue
			}
			parsed, recognized, err = parseSyncConsumerSASLUintProperty(
				property,
				"maxbufsize=",
			)
			if err != nil {
				return syncConsumerSASLSecurityProperties{}, err
			}
			if recognized {
				properties.maxBufferSize = parsed
				continue
			}
			return syncConsumerSASLSecurityProperties{}, fmt.Errorf(
				"unknown SASL security property %q",
				rawProperty,
			)
		}
	}
	if flagsSeen {
		properties.noDictionary = noDictionary
		properties.noPlain = noPlain
		properties.noActive = noActive
		properties.passCredentials = passCredentials
		properties.forwardSecrecy = forwardSecrecy
		properties.noAnonymous = noAnonymous
	}
	return properties, nil
}

func parseSyncConsumerSASLUintProperty(
	property,
	prefix string,
) (uint32, bool, error) {
	if !strings.HasPrefix(property, prefix) {
		return 0, false, nil
	}
	rawValue := strings.TrimPrefix(property, prefix)
	value, err := strconv.ParseUint(rawValue, 10, 32)
	if err != nil {
		return 0, true, fmt.Errorf(
			"invalid SASL security property %q",
			property,
		)
	}
	return uint32(value), true, nil
}

func bindSyncConsumerSASL(
	transport *syncConsumerTransport,
	config syncConsumerConfig,
	provider ...string,
) error {
	providerURL := ""
	if len(provider) > 0 {
		providerURL = provider[0]
	}
	mechanism, conversation, err := newSyncConsumerSASLConversationForProvider(
		config,
		providerURL,
		transport,
	)
	if err != nil {
		return err
	}
	defer clearSyncConsumerSASLConversation(conversation)
	if digest, ok := conversation.(*syncConsumerDIGESTMD5); ok {
		digest.externalSSF = transport.ssf
	}
	if err := validateSyncConsumerSASLSecurity(
		config.securityProperties,
		mechanism,
		transport.ssf,
	); err != nil {
		return err
	}

	response, hasResponse, err := conversation.Initial()
	if err != nil {
		return fmt.Errorf("start SASL %s conversation: %w", mechanism, err)
	}
	defer func() { clear(response) }()
	for round := 0; round < syncConsumerMaxSASLRounds; round++ {
		result, err := sendSyncConsumerSASLBind(
			transport,
			mechanism,
			response,
			hasResponse,
		)
		clear(response)
		response = nil
		if err != nil {
			return fmt.Errorf("SASL %s bind: %w", mechanism, err)
		}
		switch result.code {
		case ldap.LDAPResultSaslBindInProgress:
			if conversation.Done() {
				clear(result.saslCredentials)
				return fmt.Errorf(
					"SASL %s server requested another response after client completion",
					mechanism,
				)
			}
			response, err = conversation.Next(result.saslCredentials)
			clear(result.saslCredentials)
			if err != nil {
				return fmt.Errorf(
					"process SASL %s challenge: %w",
					mechanism,
					err,
				)
			}
			hasResponse = true
		case ldap.LDAPResultSuccess:
			if conversation.Done() && len(result.saslCredentials) != 0 {
				clear(result.saslCredentials)
				return fmt.Errorf("SASL %s server returned unexpected completion data", mechanism)
			}
			if !conversation.Done() {
				response, err = conversation.Next(result.saslCredentials)
				clear(result.saslCredentials)
				if err != nil {
					return fmt.Errorf(
						"verify SASL %s completion: %w",
						mechanism,
						err,
					)
				}
				if !conversation.Done() || len(response) != 0 {
					return fmt.Errorf(
						"SASL %s server completed before the client",
						mechanism,
					)
				}
			}
			if !conversation.Valid() {
				return fmt.Errorf(
					"SASL %s server proof is invalid",
					mechanism,
				)
			}
			if digest, ok := conversation.(*syncConsumerDIGESTMD5); ok {
				if err := installSyncConsumerDIGESTMD5Security(
					transport,
					digest,
				); err != nil {
					return fmt.Errorf(
						"install SASL DIGEST-MD5 %s security layer: %w",
						digest.qop,
						err,
					)
				}
			}
			return nil
		default:
			clear(result.saslCredentials)
			return fmt.Errorf("SASL %s bind: %w", mechanism, result.err())
		}
	}
	return fmt.Errorf(
		"SASL %s bind exceeded %d challenge rounds",
		mechanism,
		syncConsumerMaxSASLRounds,
	)
}

func newSyncConsumerSASLConversation(
	config syncConsumerConfig,
) (string, syncConsumerSASLConversation, error) {
	return newSyncConsumerSASLConversationForProvider(config, "")
}

func newSyncConsumerSASLConversationForProvider(
	config syncConsumerConfig,
	provider string,
	transports ...*syncConsumerTransport,
) (string, syncConsumerSASLConversation, error) {
	mechanism := strings.ToUpper(config.saslMechanism)
	switch mechanism {
	case "EXTERNAL":
		return mechanism, &syncConsumerOneStepSASL{
			response: []byte(config.authorizationID),
		}, nil
	case "PLAIN":
		if config.authenticationID == "" {
			return "", nil, errors.New(
				"SASL PLAIN requires authcid",
			)
		}
		if strings.IndexByte(config.authenticationID, 0) >= 0 ||
			strings.IndexByte(config.authorizationID, 0) >= 0 ||
			bytes.IndexByte(config.credentials, 0) >= 0 {
			return "", nil, errors.New(
				"SASL PLAIN identities and password must not contain NUL",
			)
		}
		response := make(
			[]byte,
			0,
			len(config.authorizationID)+
				len(config.authenticationID)+
				len(config.credentials)+2,
		)
		response = append(response, config.authorizationID...)
		response = append(response, 0)
		response = append(response, config.authenticationID...)
		response = append(response, 0)
		response = append(response, config.credentials...)
		return mechanism, &syncConsumerOneStepSASL{
			response: response,
		}, nil
	case "CRAM-MD5":
		if config.authenticationID == "" {
			return "", nil, errors.New(
				"SASL CRAM-MD5 requires authcid",
			)
		}
		if strings.ContainsAny(config.authenticationID, " \t\r\n") {
			return "", nil, errors.New(
				"SASL CRAM-MD5 authcid must not contain whitespace",
			)
		}
		return mechanism, &syncConsumerCRAMMD5{
			authenticationID: config.authenticationID,
			password:         bytes.Clone(config.credentials),
		}, nil
	case "DIGEST-MD5":
		if config.authenticationID == "" {
			return "", nil, errors.New(
				"SASL DIGEST-MD5 requires authcid",
			)
		}
		for name, value := range map[string]string{
			"authcid": config.authenticationID,
			"authzid": config.authorizationID,
			"realm":   config.realm,
		} {
			if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
				return "", nil, fmt.Errorf(
					"SASL DIGEST-MD5 %s is not valid UTF-8",
					name,
				)
			}
		}
		host, err := syncConsumerDIGESTMD5Host(provider)
		if err != nil {
			return "", nil, err
		}
		return mechanism, &syncConsumerDIGESTMD5{
			authenticationID: config.authenticationID,
			authorizationID:  config.authorizationID,
			realm:            config.realm,
			host:             host,
			password:         bytes.Clone(config.credentials),
			properties:       config.securityProperties,
			random:           rand.Reader,
		}, nil
	case "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512",
		"SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-512-PLUS":
		if config.authenticationID == "" {
			return "", nil, fmt.Errorf(
				"SASL %s requires authcid",
				mechanism,
			)
		}
		plus := saslSCRAMIsPlus(mechanism)
		var binding scram.ChannelBinding
		if plus {
			var transport *syncConsumerTransport
			if len(transports) != 0 {
				transport = transports[0]
			}
			var err error
			binding, err = syncConsumerSCRAMChannelBinding(transport, config, provider)
			if err != nil {
				return "", nil, err
			}
		}
		generator, _ := saslSCRAMHashGenerator(mechanism)
		client, err := generator.NewClient(
			config.authenticationID,
			string(config.credentials),
			config.authorizationID,
		)
		if err != nil {
			return "", nil, fmt.Errorf(
				"SASL %s credentials are not valid SASLprep strings",
				mechanism,
			)
		}
		conversation := client.NewConversation()
		if plus {
			conversation = client.NewConversationWithChannelBinding(binding)
		}
		return mechanism, &syncConsumerSCRAM{
			conversation: conversation,
			plus:         plus,
			hashSize:     generator().Size(),
		}, nil
	default:
		return "", nil, fmt.Errorf(
			"SASL mechanism %q is not supported by the built-in syncrepl client",
			config.saslMechanism,
		)
	}
}

func syncConsumerDIGESTMD5Host(provider string) (string, error) {
	if provider == "" {
		return "localhost", nil
	}
	parsed, err := parseSyncConsumerProviderURL(provider)
	if err != nil {
		return "", fmt.Errorf("parse DIGEST-MD5 provider: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		host = "localhost"
	}
	return strings.ToLower(host), nil
}

func validateSyncConsumerSASLSecurity(
	properties syncConsumerSASLSecurityProperties,
	mechanism string,
	externalSSF uint32,
) error {
	if properties.minSSF > properties.maxSSF {
		return fmt.Errorf(
			"SASL minssf=%d exceeds maxssf=%d",
			properties.minSSF,
			properties.maxSSF,
		)
	}
	if properties.maxBufferSize > maxSASLDigestMD5BufferSize {
		return fmt.Errorf(
			"SASL maxbufsize=%d exceeds the RFC limit %d",
			properties.maxBufferSize,
			maxSASLDigestMD5BufferSize,
		)
	}
	switch {
	case properties.noDictionary && mechanism != "GSSAPI":
		return errors.New(
			"SASL secprops=nodict is not supported by the implemented mechanisms",
		)
	case properties.noActive && mechanism != "GSSAPI":
		return errors.New(
			"SASL secprops=noactive is not supported by the implemented mechanisms",
		)
	case properties.passCredentials:
		return errors.New(
			"SASL secprops=passcred requires credential delegation support",
		)
	case properties.forwardSecrecy:
		return errors.New(
			"SASL secprops=forwardsec requires a SASL security layer",
		)
	case properties.noAnonymous && mechanism == "ANONYMOUS":
		return errors.New("SASL ANONYMOUS is disabled by secprops")
	case properties.noPlain && mechanism == "PLAIN" && externalSSF == 0:
		return errors.New(
			"SASL PLAIN is disabled by secprops=noplain without TLS, TLCP, or ldapi",
		)
	case properties.minSSF > externalSSF && mechanism == "GSSAPI":
		return nil
	case properties.minSSF > externalSSF &&
		mechanism == "DIGEST-MD5" &&
		properties.maxBufferSize != 0 &&
		properties.minSSF-externalSSF <= saslDigestMD5RC4SSF &&
		properties.maxSSF > externalSSF &&
		properties.maxSSF-externalSSF >= properties.minSSF-externalSSF:
		return nil
	case properties.minSSF > externalSSF:
		return fmt.Errorf(
			"SASL minssf=%d cannot be satisfied by transport SSF %d and mechanism %s",
			properties.minSSF,
			externalSSF,
			mechanism,
		)
	default:
		return nil
	}
}

func sendSyncConsumerSASLBind(
	transport *syncConsumerTransport,
	mechanism string,
	credentials []byte,
	hasCredentials bool,
) (syncConsumerLDAPResult, error) {
	messageID := transport.nextMessageID()
	request := ber.NewSequence("LDAPMessage")
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	bind := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldap.ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	bind.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		3,
		"version",
	))
	bind.AppendChild(syncConsumerOctetString(nil, "name"))
	authentication := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		3,
		nil,
		"sasl",
	)
	authentication.AppendChild(syncConsumerOctetString(
		[]byte(mechanism),
		"mechanism",
	))
	if hasCredentials {
		authentication.AppendChild(syncConsumerOctetString(
			credentials,
			"credentials",
		))
	}
	bind.AppendChild(authentication)
	request.AppendChild(bind)
	return transport.exchangeLDAPResult(
		messageID,
		request,
		ldap.ApplicationBindResponse,
	)
}

func (conversation *syncConsumerOneStepSASL) Initial() ([]byte, bool, error) {
	if conversation.started {
		return nil, false, errors.New("conversation already started")
	}
	conversation.started = true
	return bytes.Clone(conversation.response), true, nil
}

func (*syncConsumerOneStepSASL) Next([]byte) ([]byte, error) {
	return nil, errors.New("one-step SASL mechanism received a challenge")
}

func (conversation *syncConsumerOneStepSASL) Done() bool {
	return conversation.started
}

func (conversation *syncConsumerOneStepSASL) Valid() bool {
	return conversation.started
}

func (conversation *syncConsumerCRAMMD5) Initial() ([]byte, bool, error) {
	if conversation.started {
		return nil, false, errors.New("conversation already started")
	}
	conversation.started = true
	return nil, false, nil
}

func (conversation *syncConsumerCRAMMD5) Next(
	challenge []byte,
) ([]byte, error) {
	if !conversation.started || conversation.done {
		return nil, errors.New("unexpected CRAM-MD5 challenge")
	}
	mac := hmac.New(md5.New, conversation.password)
	_, _ = mac.Write(challenge)
	digest := make([]byte, hex.EncodedLen(mac.Size()))
	hex.Encode(digest, mac.Sum(nil))
	response := make(
		[]byte,
		0,
		len(conversation.authenticationID)+1+len(digest),
	)
	response = append(response, conversation.authenticationID...)
	response = append(response, ' ')
	response = append(response, digest...)
	conversation.done = true
	return response, nil
}

func (conversation *syncConsumerCRAMMD5) Done() bool {
	return conversation.done
}

func (conversation *syncConsumerCRAMMD5) Valid() bool {
	return conversation.done
}

func (conversation *syncConsumerDIGESTMD5) Initial() ([]byte, bool, error) {
	if conversation.started {
		return nil, false, errors.New("DIGEST-MD5 conversation already started")
	}
	conversation.started = true
	return nil, false, nil
}

func (conversation *syncConsumerDIGESTMD5) Next(
	challenge []byte,
) ([]byte, error) {
	if !conversation.started || conversation.done {
		return nil, errors.New("unexpected DIGEST-MD5 challenge")
	}
	if conversation.expectedRspauth != "" {
		return conversation.verifyServer(challenge)
	}
	return conversation.respond(challenge)
}

func (conversation *syncConsumerDIGESTMD5) respond(
	challenge []byte,
) ([]byte, error) {
	directives, realms, err := parseSyncConsumerDIGESTMD5Challenge(challenge)
	if err != nil {
		return nil, err
	}
	nonce := directives["nonce"]
	if nonce == "" {
		return nil, errors.New("DIGEST-MD5 challenge has no nonce")
	}
	if algorithm := directives["algorithm"]; !strings.EqualFold(
		algorithm,
		"md5-sess",
	) {
		return nil, fmt.Errorf(
			"DIGEST-MD5 challenge algorithm is %q, want md5-sess",
			algorithm,
		)
	}
	charset, charsetOffered := directives["charset"]
	if charsetOffered &&
		!strings.EqualFold(charset, "utf-8") {
		return nil, fmt.Errorf(
			"DIGEST-MD5 challenge charset is %q, want utf-8",
			charset,
		)
	}
	if stale, present := directives["stale"]; present &&
		strings.EqualFold(stale, "true") {
		return nil, errors.New("DIGEST-MD5 server marked the nonce stale")
	}
	offeredQOP := directives["qop"]
	if offeredQOP == "" {
		offeredQOP = saslDigestMD5AuthenticationQOP
	}
	qop, selectedCipher, err := selectSyncConsumerDIGESTMD5Security(
		offeredQOP,
		directives["cipher"],
		conversation.properties,
		conversation.externalSSF,
	)
	if err != nil {
		return nil, err
	}
	peerMaxBuffer := uint32(saslDigestMD5DefaultMaxBuffer)
	if rawMax, present := directives["maxbuf"]; present {
		maximum, err := strconv.ParseUint(rawMax, 10, 32)
		if err != nil || maximum <= 16 || maximum > maxSASLDigestMD5BufferSize {
			return nil, fmt.Errorf(
				"DIGEST-MD5 challenge maxbuf %q is invalid",
				rawMax,
			)
		}
		peerMaxBuffer = uint32(maximum)
	}
	if conversation.properties.maxBufferSize != 0 &&
		(conversation.properties.maxBufferSize <= 16 ||
			conversation.properties.maxBufferSize > maxSASLDigestMD5BufferSize) {
		return nil, fmt.Errorf(
			"DIGEST-MD5 maxbuf %d is outside [17..%d]",
			conversation.properties.maxBufferSize,
			maxSASLDigestMD5BufferSize,
		)
	}
	if qop != saslDigestMD5AuthenticationQOP {
		minimumPeer, minimumLocal := uint32(saslDigestMD5IntegrityOverhead+1), uint32(saslDigestMD5IntegrityOverhead+1)
		if qop == saslDigestMD5ConfidentialityQOP {
			minimumPeer = 26
			if selectedCipher.mode != saslDigestMD5CipherModeRC4 {
				minimumPeer, minimumLocal = 30, 26
			}
		}
		if peerMaxBuffer < minimumPeer || conversation.properties.maxBufferSize < minimumLocal {
			return nil, fmt.Errorf("DIGEST-MD5 maxbuf is too small for %s %s", qop, selectedCipher.name)
		}
	}

	realm := conversation.realm
	if realm == "" && len(realms) > 0 {
		realm = realms[0]
	}
	if conversation.realm != "" && len(realms) > 0 &&
		!slicesContainsExact(realms, conversation.realm) {
		return nil, fmt.Errorf(
			"DIGEST-MD5 realm %q was not offered by the server",
			conversation.realm,
		)
	}

	entropy := make([]byte, 24)
	if _, err := io.ReadFull(conversation.random, entropy); err != nil {
		return nil, fmt.Errorf("generate DIGEST-MD5 cnonce: %w", err)
	}
	cnonce := base64.RawStdEncoding.EncodeToString(entropy)
	clear(entropy)
	response := saslDigestMD5Response{
		username:         conversation.authenticationID,
		realm:            realm,
		nonce:            nonce,
		cnonce:           cnonce,
		nonceCount:       1,
		qop:              qop,
		digestURI:        "ldap/" + conversation.host,
		authorization:    conversation.authorizationID,
		hasAuthorization: conversation.authorizationID != "",
		cipher:           selectedCipher.name,
	}
	secret := calculateSASLDigestMD5Secret(
		response.username,
		response.realm,
		conversation.password,
		true,
	)
	digest, rspauth := calculateSASLDigestMD5Exchange(secret, response)
	if qop != saslDigestMD5AuthenticationQOP {
		conversation.sessionKey = calculateSASLDigestMD5SessionKey(
			secret,
			response,
		)
	}
	clear(secret)
	conversation.expectedRspauth = rspauth
	conversation.qop = qop
	conversation.cipher = selectedCipher
	conversation.peerMaxBuffer = peerMaxBuffer
	return formatSyncConsumerDIGESTMD5Response(
		response,
		digest,
		conversation.properties.maxBufferSize,
		charsetOffered,
	), nil
}

func (conversation *syncConsumerDIGESTMD5) verifyServer(
	challenge []byte,
) ([]byte, error) {
	if len(challenge) == 0 || len(challenge) >= maxSASLDigestMD5ChallengeSize {
		return nil, errors.New("DIGEST-MD5 rspauth size is invalid")
	}
	directives, err := parseSASLDigestMD5Directives(challenge)
	if err != nil {
		return nil, fmt.Errorf("parse DIGEST-MD5 rspauth: %w", err)
	}
	if len(directives) != 1 {
		return nil, errors.New("DIGEST-MD5 final challenge must only contain rspauth")
	}
	rspauth, present := directives["rspauth"]
	if !present || len(rspauth) != len(conversation.expectedRspauth) ||
		subtle.ConstantTimeCompare(
			[]byte(rspauth),
			[]byte(conversation.expectedRspauth),
		) != 1 {
		return nil, errors.New("DIGEST-MD5 server rspauth is invalid")
	}
	conversation.done = true
	conversation.valid = true
	clear(conversation.password)
	return nil, nil
}

func (conversation *syncConsumerDIGESTMD5) Done() bool {
	return conversation.done
}

func (conversation *syncConsumerDIGESTMD5) Valid() bool {
	return conversation.valid
}

func parseSyncConsumerDIGESTMD5Challenge(
	challenge []byte,
) (map[string]string, []string, error) {
	if len(challenge) == 0 || len(challenge) >= maxSASLDigestMD5ChallengeSize {
		return nil, nil, errors.New("DIGEST-MD5 challenge size is invalid")
	}
	parsed, err := parseSASLDigestMD5DirectiveList(challenge)
	if err != nil {
		return nil, nil, err
	}
	directives := make(map[string]string, len(parsed))
	var realms []string
	for _, directive := range parsed {
		if directive.name == "realm" {
			realms = append(realms, directive.value)
			continue
		}
		if _, exists := directives[directive.name]; exists {
			return nil, nil, fmt.Errorf(
				"DIGEST-MD5 challenge directive %q is duplicated",
				directive.name,
			)
		}
		directives[directive.name] = directive.value
	}
	return directives, realms, nil
}

func syncConsumerDIGESTMD5QOPContains(values, wanted string) bool {
	for _, value := range strings.Split(values, ",") {
		if strings.EqualFold(strings.TrimSpace(value), wanted) {
			return true
		}
	}
	return false
}

func slicesContainsExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func formatSyncConsumerDIGESTMD5Response(
	response saslDigestMD5Response,
	digest string,
	maxBufferSize uint32,
	charsetUTF8 bool,
) []byte {
	var value strings.Builder
	fmt.Fprintf(
		&value,
		`username="%s",realm="%s",nonce="%s",cnonce="%s",`+
			`nc=%08x,qop=%s,digest-uri="%s",response=%s`,
		quoteSASLDigestMD5Value(response.username),
		quoteSASLDigestMD5Value(response.realm),
		quoteSASLDigestMD5Value(response.nonce),
		quoteSASLDigestMD5Value(response.cnonce),
		response.nonceCount,
		response.qop,
		quoteSASLDigestMD5Value(response.digestURI),
		digest,
	)
	if response.hasAuthorization {
		fmt.Fprintf(
			&value,
			`,authzid="%s"`,
			quoteSASLDigestMD5Value(response.authorization),
		)
	}
	if response.cipher != "" {
		fmt.Fprintf(&value, ",cipher=%s", response.cipher)
	}
	if maxBufferSize != 0 {
		fmt.Fprintf(&value, ",maxbuf=%d", maxBufferSize)
	}
	if charsetUTF8 {
		value.WriteString(",charset=utf-8")
	}
	return []byte(value.String())
}

func (conversation *syncConsumerSCRAM) Initial() ([]byte, bool, error) {
	if conversation.started {
		return nil, false, errors.New("conversation already started")
	}
	conversation.started = true
	response, err := conversation.conversation.Step("")
	if conversation.plus && err == nil {
		_, conversation.clientNonce, _ = strings.Cut(response, ",r=")
	}
	return []byte(response), true, err
}

func (conversation *syncConsumerSCRAM) Next(
	challenge []byte,
) ([]byte, error) {
	if !conversation.started {
		return nil, errors.New("conversation has not started")
	}
	if conversation.plus {
		if err := conversation.validateChallenge(challenge); err != nil {
			return nil, err
		}
	}
	response, err := conversation.conversation.Step(string(challenge))
	if err == nil {
		conversation.proofSent = true
	}
	return []byte(response), err
}

func (conversation *syncConsumerSCRAM) Done() bool {
	return conversation.conversation.Done()
}

func (conversation *syncConsumerSCRAM) Valid() bool {
	return conversation.conversation.Valid()
}
