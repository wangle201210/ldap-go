package server

import (
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
	"github.com/xdg-go/scram"
)

type serverSASLSession struct {
	mechanism             string
	runtime               *runtimeState
	scramConversation     *scram.ServerConversation
	scramSecrets          *saslSCRAMSecrets
	cramMD5Challenge      []byte
	digestMD5Session      *serverSASLDigestMD5Session
	gssapiSession         *serverGSSAPISession
	authenticationDN      directory.DN
	authorizationDN       directory.DN
	authorizationResolved bool
	credentialLookupErr   error
}

type serverGSSAPISession struct {
	stage            uint8
	context          saslkrb5.AcceptedContext
	authenticationDN directory.DN
	offeredLayers    byte
	maximumBuffer    uint32
}

func (session *serverGSSAPISession) clear() {
	if session == nil {
		return
	}
	clear(session.context.Key.KeyValue)
	clear(session.context.APRep)
	*session = serverGSSAPISession{}
}
