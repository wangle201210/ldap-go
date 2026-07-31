package server

import (
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/xdg-go/scram"
)

type serverSASLSession struct {
	mechanism             string
	runtime               *runtimeState
	scramConversation     *scram.ServerConversation
	cramMD5Challenge      []byte
	digestMD5Session      *serverSASLDigestMD5Session
	authenticationDN      directory.DN
	authorizationDN       directory.DN
	authorizationResolved bool
	credentialLookupErr   error
}
