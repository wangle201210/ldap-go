package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
	"github.com/xdg-go/scram"
)

const (
	defaultSASLSCRAMIterations = 4096
	maxSASLSCRAMIterations     = 10_000_000
	saslSCRAMSaltSize          = 16
	maxSASLSCRAMSecretSize     = 4096
)

var errSASLSCRAMCredentialsUnavailable = errors.New(
	"SCRAM credentials are unavailable",
)

func (server *Server) handleSASLSCRAMStep(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	session *serverSASLSession,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
	if session.scramConversation == nil {
		if err := server.initializeSASLSCRAMConversation(
			ctx,
			session,
		); err != nil {
			clearSASLSession(state)
			return err
		}
	}

	response, err := session.scramConversation.Step(
		string(request.Authentication.SASLCredentials),
	)
	if err != nil {
		lookupErr := session.credentialLookupErr
		clearSASLSession(state)
		if lookupErr != nil &&
			!errors.Is(
				lookupErr,
				errSASLSCRAMCredentialsUnavailable,
			) {
			return lookupErr
		}
		return writeSASLInvalidCredentials(connection, message.ID)
	}

	if !session.authorizationResolved {
		authorizationDN, err := server.resolveSASLAuthorizationDN(
			ctx,
			session.runtime,
			session.mechanism,
			session.scramConversation.Username(),
			session.authenticationDN,
			session.scramConversation.AuthzID(),
		)
		if err != nil {
			clearSASLSession(state)
			return ldapwire.Write(
				connection,
				ldapwire.EncodeBindResponse(
					message.ID,
					ldapwire.ResultError(
						ldapwire.ResultInappropriateAuthentication,
						"",
					),
					nil,
				),
			)
		}
		session.authorizationDN = authorizationDN
		session.authorizationResolved = true
	}

	if !session.scramConversation.Done() {
		return writeSASLChallenge(
			connection,
			message.ID,
			[]byte(response),
		)
	}
	if !session.scramConversation.Valid() {
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}

	state.boundDN = session.authorizationDN.String()
	clearSASLSession(state)
	return ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		[]byte(response),
		true,
		nil,
	))
}

func (server *Server) initializeSASLSCRAMConversation(
	ctx context.Context,
	session *serverSASLSession,
) error {
	generator, ok := saslSCRAMHashGenerator(session.mechanism)
	if !ok {
		return errSASLSCRAMCredentialsUnavailable
	}
	scramServer, err := generator.NewServer(func(
		username string,
	) (scram.StoredCredentials, error) {
		authenticationDN, credentials, lookupErr :=
			server.lookupSASLSCRAMCredentials(
				ctx,
				session.runtime,
				session.mechanism,
				username,
				generator,
			)
		session.credentialLookupErr = lookupErr
		if lookupErr == nil {
			session.authenticationDN = authenticationDN
		}
		return credentials, lookupErr
	})
	if err != nil {
		return err
	}
	session.scramConversation = scramServer.NewConversation()
	return nil
}

func (server *Server) lookupSASLSCRAMCredentials(
	ctx context.Context,
	runtime *runtimeState,
	mechanism string,
	username string,
	generator scram.HashGeneratorFcn,
) (directory.DN, scram.StoredCredentials, error) {
	authenticationDN, err := server.saslAuthenticationDN(
		ctx,
		runtime,
		mechanism,
		username,
	)
	if err != nil {
		return directory.DN{}, scram.StoredCredentials{},
			errSASLSCRAMCredentialsUnavailable
	}
	database := databaseForDN(runtime, authenticationDN)
	if database == nil {
		return directory.DN{}, scram.StoredCredentials{},
			errSASLSCRAMCredentialsUnavailable
	}
	if database.rootDN != nil &&
		database.rootDN.Equal(authenticationDN) &&
		database.rootPasswordSet {
		password, ok := auth.ExtractCleartextPassword(
			database.rootPassword,
		)
		if !ok {
			return directory.DN{}, scram.StoredCredentials{},
				errSASLSCRAMCredentialsUnavailable
		}
		defer clear(password)
		credentials, err := deriveSASLSCRAMCredentials(
			generator,
			username,
			password,
		)
		if err != nil {
			return directory.DN{}, scram.StoredCredentials{}, err
		}
		return authenticationDN, credentials, nil
	}

	var (
		credentials scram.StoredCredentials
		found       bool
	)
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := storage.ReaderInPartition(reader, database.partition)
		entry, err := tx.Get(authenticationDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}

		if server.allowed(
			runtime,
			tx,
			"",
			entry,
			"userPassword",
			nil,
			acl.Auth,
		) {
			for _, stored := range entry.Values("userPassword") {
				password, ok := auth.ExtractCleartextPassword(stored)
				if !ok {
					continue
				}
				derived, deriveErr := deriveSASLSCRAMCredentials(
					generator,
					username,
					password,
				)
				clear(password)
				if deriveErr != nil {
					return deriveErr
				}
				credentials = derived
				found = true
				return nil
			}
		}

		if !server.allowed(
			runtime,
			tx,
			"",
			entry,
			"authPassword",
			nil,
			acl.Auth,
		) {
			return nil
		}
		for _, stored := range entry.Values("authPassword") {
			parsed, ok := parseCyrusSASLSCRAMSecret(
				stored,
				mechanism,
				generator().Size(),
			)
			if !ok {
				continue
			}
			credentials = parsed
			found = true
			return nil
		}
		return nil
	})
	if err != nil {
		return directory.DN{}, scram.StoredCredentials{}, err
	}
	if !found {
		return directory.DN{}, scram.StoredCredentials{},
			errSASLSCRAMCredentialsUnavailable
	}
	return authenticationDN, credentials, nil
}

func deriveSASLSCRAMCredentials(
	generator scram.HashGeneratorFcn,
	username string,
	password []byte,
) (scram.StoredCredentials, error) {
	salt := make([]byte, saslSCRAMSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return scram.StoredCredentials{}, err
	}
	client, err := generator.NewClient(username, string(password), "")
	if err != nil {
		return scram.StoredCredentials{}, err
	}
	return client.GetStoredCredentialsWithError(scram.KeyFactors{
		Salt:  string(salt),
		Iters: defaultSASLSCRAMIterations,
	})
}

func parseCyrusSASLSCRAMSecret(
	value []byte,
	mechanism string,
	keySize int,
) (scram.StoredCredentials, bool) {
	if len(value) == 0 || len(value) > maxSASLSCRAMSecretSize {
		return scram.StoredCredentials{}, false
	}
	text := strings.TrimSpace(string(value))
	if len(text) < len(mechanism) ||
		!strings.EqualFold(text[:len(mechanism)], mechanism) {
		return scram.StoredCredentials{}, false
	}
	remainder := strings.TrimSpace(text[len(mechanism):])
	if !strings.HasPrefix(remainder, "$") {
		return scram.StoredCredentials{}, false
	}
	sections := strings.SplitN(remainder[1:], "$", 2)
	if len(sections) != 2 {
		return scram.StoredCredentials{}, false
	}
	factors := strings.SplitN(sections[0], ":", 2)
	keys := strings.SplitN(sections[1], ":", 2)
	if len(factors) != 2 || len(keys) != 2 {
		return scram.StoredCredentials{}, false
	}

	iterations, err := strconv.ParseUint(
		strings.TrimSpace(factors[0]),
		10,
		32,
	)
	if err != nil ||
		iterations == 0 ||
		iterations > maxSASLSCRAMIterations {
		return scram.StoredCredentials{}, false
	}
	salt, ok := decodeSASLBase64(strings.TrimSpace(factors[1]))
	if !ok || len(salt) == 0 {
		return scram.StoredCredentials{}, false
	}
	storedKey, ok := decodeSASLBase64(strings.TrimSpace(keys[0]))
	if !ok || len(storedKey) != keySize {
		return scram.StoredCredentials{}, false
	}
	serverKey, ok := decodeSASLBase64(strings.TrimSpace(keys[1]))
	if !ok || len(serverKey) != keySize {
		return scram.StoredCredentials{}, false
	}
	return scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{
			Salt:  string(salt),
			Iters: int(iterations),
		},
		StoredKey: storedKey,
		ServerKey: serverKey,
	}, true
}

func decodeSASLBase64(value string) ([]byte, bool) {
	if value == "" {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	return decoded, err == nil
}

func saslSCRAMHashGenerator(
	mechanism string,
) (scram.HashGeneratorFcn, bool) {
	switch mechanism {
	case "SCRAM-SHA-1":
		return scram.SHA1, true
	case "SCRAM-SHA-256":
		return scram.SHA256, true
	case "SCRAM-SHA-512":
		return scram.SHA512, true
	default:
		return nil, false
	}
}
