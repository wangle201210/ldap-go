package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/xdg-go/stringprep"
)

const maxSASLCRAMMD5InputSize = 1024

func newSASLCRAMMD5Challenge(
	host string,
	now time.Time,
	random io.Reader,
) ([]byte, error) {
	var entropy [4]byte
	if _, err := io.ReadFull(random, entropy[:]); err != nil {
		return nil, err
	}
	randomValue := binary.BigEndian.Uint32(entropy[:])
	timestamp := now.Unix() % 0xFFFFFF
	return []byte(fmt.Sprintf(
		"<%d.%d@%s>",
		randomValue,
		timestamp,
		host,
	)), nil
}

func (server *Server) handleSASLCRAMMD5Step(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	session *serverSASLSession,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
	response := request.Authentication.SASLCredentials
	if len(response) > maxSASLCRAMMD5InputSize {
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	separator := bytes.LastIndexByte(response, ' ')
	if separator <= 0 ||
		len(response)-separator-1 < hex.EncodedLen(md5.Size) ||
		!utf8.Valid(response[:separator]) {
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	authenticationID, err := stringprep.SASLprep.Prepare(
		string(response[:separator]),
	)
	if err != nil || authenticationID == "" {
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}

	authenticationDN, err := server.saslAuthenticationDN(
		ctx,
		session.runtime,
		session.mechanism,
		authenticationID,
	)
	if err != nil {
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	password, err := server.lookupSASLCleartextPassword(
		ctx,
		session.runtime,
		authenticationDN,
	)
	if err != nil {
		clearSASLSession(state)
		if !errors.Is(err, errSASLCleartextPasswordUnavailable) {
			return err
		}
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	defer clear(password)

	mac := hmac.New(md5.New, password)
	_, _ = mac.Write(session.cramMD5Challenge)
	expected := make([]byte, hex.EncodedLen(md5.Size))
	hex.Encode(expected, mac.Sum(nil))
	digest := response[separator+1 : separator+1+len(expected)]
	if !hmac.Equal(expected, digest) {
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}

	state.boundDN = authenticationDN.String()
	clearSASLSession(state)
	return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	))
}

func startSASLCRAMMD5Session(
	runtime *runtimeState,
) (*serverSASLSession, error) {
	challenge, err := newSASLCRAMMD5Challenge(
		runtime.sasl.host,
		time.Now(),
		rand.Reader,
	)
	if err != nil {
		return nil, err
	}
	return &serverSASLSession{
		mechanism:        "CRAM-MD5",
		runtime:          runtime,
		cramMD5Challenge: challenge,
	}, nil
}
