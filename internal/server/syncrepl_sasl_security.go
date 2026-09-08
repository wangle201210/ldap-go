package server

import (
	"errors"
	"fmt"
	"net"
)

func selectSyncConsumerDIGESTMD5Security(
	offeredQOP,
	offeredCiphers string,
	properties syncConsumerSASLSecurityProperties,
	externalSSF uint32,
) (string, saslDigestMD5Cipher, error) {
	requiredSSF := uint32(0)
	if properties.minSSF > externalSSF {
		requiredSSF = properties.minSSF - externalSSF
	}
	maximumSSF := uint32(0)
	if properties.maxSSF > externalSSF {
		maximumSSF = properties.maxSSF - externalSSF
	}
	if requiredSSF == 0 && syncConsumerDIGESTMD5QOPContains(
		offeredQOP,
		saslDigestMD5AuthenticationQOP,
	) {
		return saslDigestMD5AuthenticationQOP, saslDigestMD5Cipher{}, nil
	}
	if properties.maxBufferSize != 0 &&
		requiredSSF <= 1 && maximumSSF >= 1 &&
		syncConsumerDIGESTMD5QOPContains(
			offeredQOP,
			saslDigestMD5IntegrityQOP,
		) {
		return saslDigestMD5IntegrityQOP, saslDigestMD5Cipher{}, nil
	}

	var selected saslDigestMD5Cipher
	if properties.maxBufferSize != 0 &&
		syncConsumerDIGESTMD5QOPContains(
			offeredQOP,
			saslDigestMD5ConfidentialityQOP,
		) {
		for _, candidate := range orderedSASLDigestMD5Ciphers() {
			if candidate.ssf < requiredSSF ||
				candidate.ssf > maximumSSF ||
				!syncConsumerDIGESTMD5QOPContains(
					offeredCiphers,
					candidate.name,
				) {
				continue
			}
			if selected.name == "" || candidate.ssf > selected.ssf {
				selected = candidate
			}
		}
		if selected.name != "" {
			return saslDigestMD5ConfidentialityQOP, selected, nil
		}
	}
	return "", saslDigestMD5Cipher{}, fmt.Errorf(
		"DIGEST-MD5 challenge offers no qop or cipher satisfying minssf=%d, maxssf=%d, externalssf=%d",
		properties.minSSF,
		properties.maxSSF,
		externalSSF,
	)
}

func installSyncConsumerDIGESTMD5Security(
	transport *syncConsumerTransport,
	conversation *syncConsumerDIGESTMD5,
) error {
	if transport == nil || conversation == nil {
		return errors.New("DIGEST-MD5 security negotiation is unavailable")
	}
	if conversation.qop == saslDigestMD5AuthenticationQOP {
		return nil
	}
	if !conversation.valid {
		return errors.New("DIGEST-MD5 server proof was not verified")
	}
	connection := transport.currentConnection()
	var (
		secured net.Conn
		ssf     uint32
		err     error
	)
	switch conversation.qop {
	case saslDigestMD5IntegrityQOP:
		secured, err = newSASLDigestMD5IntegrityConnection(
			connection,
			saslDigestMD5SigningClientServer,
			saslDigestMD5SigningServerClient,
			conversation.sessionKey,
			conversation.peerMaxBuffer,
			conversation.properties.maxBufferSize,
		)
		ssf = 1
	case saslDigestMD5ConfidentialityQOP:
		secured, err = newSASLDigestMD5PrivacyConnection(
			connection,
			saslDigestMD5SigningClientServer,
			saslDigestMD5SigningServerClient,
			saslDigestMD5SealingClientServer,
			saslDigestMD5SealingServerClient,
			conversation.sessionKey,
			conversation.cipher,
			conversation.peerMaxBuffer,
			conversation.properties.maxBufferSize,
		)
		ssf = conversation.cipher.ssf
	default:
		return fmt.Errorf(
			"DIGEST-MD5 negotiated unsupported qop %q",
			conversation.qop,
		)
	}
	if err != nil {
		return err
	}
	transport.installSASLSecurityLayer(secured, ssf)
	return nil
}

func clearSyncConsumerSASLConversation(
	conversation syncConsumerSASLConversation,
) {
	switch value := conversation.(type) {
	case *syncConsumerOneStepSASL:
		clear(value.response)
		value.response = nil
	case *syncConsumerCRAMMD5:
		clear(value.password)
		value.password = nil
	case *syncConsumerDIGESTMD5:
		clear(value.password)
		value.password = nil
		clear(value.sessionKey)
		value.sessionKey = nil
		value.expectedRspauth = ""
	}
}
