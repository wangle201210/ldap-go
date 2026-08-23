package server

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSASLDigestMD5DigestURIHostValidation(t *testing.T) {
	runtime := &runtimeState{sasl: saslRuntimeConfiguration{
		host:  "ldap.example.test",
		realm: "example.test",
		securityProperties: saslSecurityProperties{
			maxBufferSize: saslDigestMD5DefaultMaxBuffer,
		},
	}}
	session, err := newSASLDigestMD5SessionWithSSF(
		runtime,
		0,
		bytes.NewReader(make([]byte, saslDigestMD5NonceSize)),
		"127.0.0.1",
		"::1",
	)
	if err != nil {
		t.Fatalf("new DIGEST-MD5 session: %v", err)
	}
	for _, valid := range []string{
		"ldap/ldap.example.test",
		"LDAP/LDAP.EXAMPLE.TEST.",
		"ldap/127.0.0.1",
		"ldap/[::1]",
		"ldap/ldap.example.test/ldap",
	} {
		if err := validateSASLDigestMD5URI(valid, session.expectedHosts); err != nil {
			t.Errorf("valid digest-uri %q: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"ldap/attacker.example",
		"ldap/",
		"http/ldap.example.test",
		"ldap/ldap.example.test/other",
		"ldap/ldap.example.test/ldap/extra",
	} {
		if err := validateSASLDigestMD5URI(invalid, session.expectedHosts); err == nil {
			t.Errorf("invalid digest-uri %q was accepted", invalid)
		}
	}

	response := []byte(
		`username="alice",realm="example.test",nonce="` + session.nonce +
			`",cnonce="client",nc=00000001,qop=auth,` +
			`digest-uri="ldap/attacker.example",` +
			`response=00000000000000000000000000000000`,
	)
	if _, err := parseSASLDigestMD5Response(response, session); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong-host DIGEST-MD5 response error = %v", err)
	}
}

func TestSASLDigestMD5SecurityCloseRaceClearsSecrets(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		name := "integrity"
		if confidential {
			name = "privacy"
		}
		t.Run(name, func(t *testing.T) {
			transport := newServerSASLBlockingConnection()
			sessionKey := []byte("0123456789abcdef")
			var layer net.Conn
			var err error
			if confidential {
				cipher := availableSASLDigestMD5Ciphers(0, saslDigestMD5RC4SSF)[saslDigestMD5RC4Cipher]
				layer, err = newSASLDigestMD5ServerPrivacyConnection(
					transport, sessionKey, cipher, 128, 128,
				)
			} else {
				layer, err = newSASLDigestMD5ServerIntegrityConnection(
					transport, sessionKey, 128, 128,
				)
			}
			if err != nil {
				t.Fatalf("new DIGEST-MD5 layer: %v", err)
			}
			assertServerSASLConcurrentClose(t, transport, layer)

			if confidential {
				privacy := layer.(*saslDigestMD5PrivacyConnection)
				if !serverSASLAllZero(privacy.sendKey[:]) ||
					!serverSASLAllZero(privacy.receiveKey[:]) ||
					privacy.sendCipher != nil || privacy.recvCipher != nil ||
					privacy.readPending != nil {
					t.Fatal("privacy Close retained DIGEST-MD5 secrets")
				}
			} else {
				integrity := layer.(*saslDigestMD5IntegrityConnection)
				if !serverSASLAllZero(integrity.sendKey[:]) ||
					!serverSASLAllZero(integrity.receiveKey[:]) ||
					integrity.readPending != nil {
					t.Fatal("integrity Close retained DIGEST-MD5 secrets")
				}
			}
		})
	}
}

func assertServerSASLConcurrentClose(
	t *testing.T,
	transport *serverSASLBlockingConnection,
	layer net.Conn,
) {
	t.Helper()
	readDone := make(chan error, 1)
	writeDone := make(chan error, 1)
	go func() {
		_, err := layer.Read(make([]byte, 1))
		readDone <- err
	}()
	go func() {
		_, err := layer.Write([]byte("blocked-write"))
		writeDone <- err
	}()
	<-transport.readStarted
	<-transport.writeStarted

	var closers sync.WaitGroup
	closers.Add(4)
	for range 4 {
		go func() {
			defer closers.Done()
			_ = layer.Close()
		}()
	}
	closers.Wait()
	if err := <-readDone; err == nil {
		t.Fatal("blocked Read succeeded after Close")
	}
	if err := <-writeDone; err == nil {
		t.Fatal("blocked Write succeeded after Close")
	}
}

func serverSASLAllZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

type serverSASLBlockingConnection struct {
	closed       chan struct{}
	readStarted  chan struct{}
	writeStarted chan struct{}
	closeOnce    sync.Once
	readOnce     sync.Once
	writeOnce    sync.Once
}

func newServerSASLBlockingConnection() *serverSASLBlockingConnection {
	return &serverSASLBlockingConnection{
		closed:       make(chan struct{}),
		readStarted:  make(chan struct{}),
		writeStarted: make(chan struct{}),
	}
}

func (connection *serverSASLBlockingConnection) Read([]byte) (int, error) {
	connection.readOnce.Do(func() { close(connection.readStarted) })
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *serverSASLBlockingConnection) Write([]byte) (int, error) {
	connection.writeOnce.Do(func() { close(connection.writeStarted) })
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *serverSASLBlockingConnection) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*serverSASLBlockingConnection) LocalAddr() net.Addr              { return nil }
func (*serverSASLBlockingConnection) RemoteAddr() net.Addr             { return nil }
func (*serverSASLBlockingConnection) SetDeadline(time.Time) error      { return nil }
func (*serverSASLBlockingConnection) SetReadDeadline(time.Time) error  { return nil }
func (*serverSASLBlockingConnection) SetWriteDeadline(time.Time) error { return nil }
