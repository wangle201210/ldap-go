package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/saslkrb5"
)

func TestLDAPClientGSSAPIChannelBindingDefaultsToNULL(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "RFC4752 default", args: []string{"-Y", "GSSAPI"}},
		{
			name: "explicit TLS extension",
			args: []string{
				"-Y", "GSSAPI",
				"-gssapi-channel-binding", "tls-server-end-point",
			},
			want: saslkrb5.ChannelBindingTLSServerEndpoint,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			flags := flag.NewFlagSet("ldapwhoami", flag.ContinueOnError)
			flags.SetOutput(&bytes.Buffer{})
			var options ldapClientOptions
			options.register(flags)
			t.Cleanup(options.clear)
			if err := flags.Parse(test.args); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			if err := options.validateForWrite(flags, true); err != nil {
				t.Fatalf("validate GSSAPI flags: %v", err)
			}
			if options.gssapiChannelBinding != test.want {
				t.Fatalf(
					"channel binding = %q, want %q",
					options.gssapiChannelBinding,
					test.want,
				)
			}
		})
	}

	certificate := &x509.Certificate{
		Raw:                []byte("client-gssapi-channel-binding-certificate"),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	switching := &ldapClientSASLSwitchConnection{
		connection: &ldapClientTLSStateConnection{
			state: tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{certificate},
			},
		},
	}
	binding, err := switching.gssapiChannelBinding()
	if err != nil {
		t.Fatalf("TLS channel binding: %v", err)
	}
	want, err := saslkrb5.TLSServerEndpoint(certificate)
	if err != nil {
		t.Fatalf("expected TLS channel binding: %v", err)
	}
	if !bytes.Equal(binding, want) {
		t.Fatalf("TLS channel binding = %x, want %x", binding, want)
	}
}

func TestLDAPClientDigestMD5Latin1FixedVector(t *testing.T) {
	values := ldapClientDigestMD5Values{
		username:      "Jerome",
		realm:         "realm",
		nonce:         "nonce",
		cnonce:        "cnonce",
		qop:           "auth",
		convertLatin1: true,
	}
	values.username = "J\u00e9r\u00f4me"
	values.realm = "r\u00e9alm"
	password := []byte("s\u00e9cret")
	key := ldapClientDigestMD5SessionKey(values, password)
	defer clear(key)
	if got, want := hex.EncodeToString(key), "19577270ae93ee866d638b21cae28e3e"; got != want {
		t.Fatalf("Latin-1 DIGEST-MD5 session key = %s, want %s", got, want)
	}
	values.convertLatin1 = false
	utf8Key := ldapClientDigestMD5SessionKey(values, password)
	defer clear(utf8Key)
	if bytes.Equal(key, utf8Key) {
		t.Fatal("Latin-1 and UTF-8 DIGEST-MD5 session keys unexpectedly match")
	}
	if ldapClientDigestMD5CanUseLatin1([]byte("\u0100")) {
		t.Fatal("non-Latin-1 credential was accepted for conversion")
	}
}

func TestLDAPClientDigestMD5SecurityCloseRaceClearsSecrets(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		name := "integrity"
		if confidential {
			name = "privacy"
		}
		t.Run(name, func(t *testing.T) {
			transport := newLDAPClientBlockingConnection()
			sessionKey := []byte("0123456789abcdef")
			var layer net.Conn
			var err error
			if confidential {
				cipher, _ := ldapClientDigestMD5CipherByName(ldapClientDigestMD5RC4Cipher)
				layer, err = newLDAPClientDigestMD5PrivacyConnection(
					transport, sessionKey, cipher, 128, 128,
				)
			} else {
				layer, err = newLDAPClientDigestMD5IntegrityConnection(
					transport, sessionKey, 128, 128,
				)
			}
			if err != nil {
				t.Fatalf("new DIGEST-MD5 layer: %v", err)
			}
			assertLDAPClientConcurrentClose(t, transport, layer)

			if confidential {
				privacy := layer.(*ldapClientDigestMD5PrivacyConnection)
				if !allZeroBytes(privacy.sendKey[:]) ||
					!allZeroBytes(privacy.receiveKey[:]) ||
					privacy.sendCipher != nil || privacy.recvCipher != nil ||
					privacy.readPending != nil {
					t.Fatal("privacy Close retained DIGEST-MD5 secrets")
				}
			} else {
				integrity := layer.(*ldapClientDigestMD5IntegrityConnection)
				if !allZeroBytes(integrity.sendKey[:]) ||
					!allZeroBytes(integrity.receiveKey[:]) ||
					integrity.readPending != nil {
					t.Fatal("integrity Close retained DIGEST-MD5 secrets")
				}
			}
		})
	}
}

func assertLDAPClientConcurrentClose(
	t *testing.T,
	transport *ldapClientBlockingConnection,
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

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

type ldapClientTLSStateConnection struct {
	net.Conn
	state tls.ConnectionState
}

func (connection *ldapClientTLSStateConnection) ConnectionState() tls.ConnectionState {
	return connection.state
}

type ldapClientBlockingConnection struct {
	closed       chan struct{}
	readStarted  chan struct{}
	writeStarted chan struct{}
	closeOnce    sync.Once
	readOnce     sync.Once
	writeOnce    sync.Once
}

func newLDAPClientBlockingConnection() *ldapClientBlockingConnection {
	return &ldapClientBlockingConnection{
		closed:       make(chan struct{}),
		readStarted:  make(chan struct{}),
		writeStarted: make(chan struct{}),
	}
}

func (connection *ldapClientBlockingConnection) Read([]byte) (int, error) {
	connection.readOnce.Do(func() { close(connection.readStarted) })
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *ldapClientBlockingConnection) Write([]byte) (int, error) {
	connection.writeOnce.Do(func() { close(connection.writeStarted) })
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *ldapClientBlockingConnection) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*ldapClientBlockingConnection) LocalAddr() net.Addr              { return nil }
func (*ldapClientBlockingConnection) RemoteAddr() net.Addr             { return nil }
func (*ldapClientBlockingConnection) SetDeadline(time.Time) error      { return nil }
func (*ldapClientBlockingConnection) SetReadDeadline(time.Time) error  { return nil }
func (*ldapClientBlockingConnection) SetWriteDeadline(time.Time) error { return nil }
