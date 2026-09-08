package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncConsumerDIGESTMD5SecuritySelection(t *testing.T) {
	for _, test := range []struct {
		name, qops, ciphers, wantQOP, wantCipher string
		minimum, maximum, external, buffer       uint32
		wantError                                bool
	}{
		{name: "auth", qops: "auth,auth-int,auth-conf", maximum: 128, buffer: 64, wantQOP: "auth"},
		{name: "integrity", qops: "auth,auth-int,auth-conf", minimum: 1, maximum: 128, buffer: 64, wantQOP: "auth-int"},
		{name: "strongest offered cipher", qops: "auth,auth-conf", ciphers: "des,3des,rc4-40,rc4", minimum: 2, maximum: 128, buffer: 64, wantQOP: "auth-conf", wantCipher: "rc4"},
		{name: "cipher ceiling", qops: "auth-conf", ciphers: "des,3des,rc4", minimum: 2, maximum: 112, buffer: 64, wantQOP: "auth-conf", wantCipher: "3des"},
		{name: "TLS satisfies minimum", qops: "auth,auth-int", minimum: 128, maximum: 256, external: 256, buffer: 64, wantQOP: "auth"},
		{name: "TLS plus integrity", qops: "auth,auth-int", minimum: 129, maximum: 129, external: 128, buffer: 64, wantQOP: "auth-int"},
		{name: "disabled layers", qops: "auth-int", maximum: 128, wantError: true},
		{name: "no downgrade", qops: "auth,auth-int", minimum: 2, maximum: 128, buffer: 64, wantError: true},
		{name: "unknown cipher", qops: "auth-conf", ciphers: "unknown", minimum: 2, maximum: 128, buffer: 64, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			qop, cipher, err := selectSyncConsumerDIGESTMD5Security(test.qops, test.ciphers,
				syncConsumerSASLSecurityProperties{minSSF: test.minimum, maxSSF: test.maximum, maxBufferSize: test.buffer}, test.external)
			if (err != nil) != test.wantError || qop != test.wantQOP || cipher.name != test.wantCipher {
				t.Fatalf("selection = %q/%q, %v", qop, cipher.name, err)
			}
		})
	}
}

func TestSyncConsumerDIGESTMD5SecurityBuffersAndProof(t *testing.T) {
	for _, test := range []struct {
		name, qop, cipher string
		peer, local, ssf  uint32
	}{
		{"integrity peer", "auth-int", "", 20, 64, 1},
		{"integrity local", "auth-int", "", 64, 20, 1},
		{"RC4 peer", "auth-conf", "rc4", 25, 64, 128},
		{"CBC peer", "auth-conf", "3des", 29, 64, 112},
		{"CBC local", "auth-conf", "3des", 64, 25, 112},
		{"oversized peer", "auth-int", "", 1 << 24, 64, 1},
		{"oversized local", "auth-int", "", 64, 1 << 24, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			conversation := newStartedSyncConsumerDIGESTMD5TestConversation(t, syncConsumerConfig{
				saslMechanism: "DIGEST-MD5", authenticationID: "alice", credentials: []byte("secret"),
				securityProperties: syncConsumerSASLSecurityProperties{minSSF: test.ssf, maxSSF: test.ssf, maxBufferSize: test.local},
			})
			defer clearSyncConsumerSASLConversation(conversation)
			challenge := fmt.Sprintf(`nonce="one",algorithm=md5-sess,qop="%s",cipher="%s",maxbuf=%d`, test.qop, test.cipher, test.peer)
			if _, err := conversation.Next([]byte(challenge)); err == nil || !strings.Contains(err.Error(), "maxbuf") {
				t.Fatalf("buffer negotiation error = %v", err)
			}
		})
	}
	conversation := newStartedSyncConsumerDIGESTMD5TestConversation(t, syncConsumerConfig{
		saslMechanism: "DIGEST-MD5", authenticationID: "alice", credentials: []byte("secret"),
		securityProperties: syncConsumerSASLSecurityProperties{minSSF: 1, maxSSF: 1, maxBufferSize: 64},
	})
	if _, err := conversation.Next([]byte(`nonce="one",algorithm=md5-sess,qop="auth-int"`)); err != nil {
		t.Fatal(err)
	}
	key, password := conversation.sessionKey, conversation.password
	if _, err := conversation.Next(bytes.Repeat([]byte("x"), maxSASLDigestMD5ChallengeSize)); err == nil || !strings.Contains(err.Error(), "size is invalid") {
		t.Fatalf("oversized server proof error = %v", err)
	}
	if _, err := conversation.Next([]byte("rspauth=" + strings.Repeat("0", 32))); err == nil {
		t.Fatal("accepted invalid server proof")
	}
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	transport := &syncConsumerTransport{connection: raw}
	if err := installSyncConsumerDIGESTMD5Security(transport, conversation); err == nil || transport.currentConnection() != raw {
		t.Fatal("installed a layer without a verified server proof")
	}
	clearSyncConsumerSASLConversation(conversation)
	if !allZeroSASLDigestMD5Bytes(key) || !allZeroSASLDigestMD5Bytes(password) {
		t.Fatal("conversation cleanup retained secrets")
	}
}

func TestBindSyncConsumerDIGESTMD5SecurityLayers(t *testing.T) {
	for _, ssf := range []uint32{1, 40, 55, 56, 112, 128} {
		t.Run(fmt.Sprint(ssf), func(t *testing.T) {
			store := storage.NewMemory()
			defer store.Close()
			seedDirectory(t, store)
			seedSASLDigestMD5Configuration(t, store)
			setSyncConsumerSecurityTestGlobal(t, store, "olcSaslSecProps", "noplain,noanonymous,maxbufsize=64")
			address, stop := startServer(t, store, Config{})
			defer stop()
			raw, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			transport := &syncConsumerTransport{connection: raw, context: t.Context(), operationTimeout: 3 * time.Second}
			defer transport.close()
			config := syncConsumerConfig{
				saslMechanism: "DIGEST-MD5", authenticationID: "alice", realm: "example.com", credentials: []byte("secret"),
				securityProperties: syncConsumerSASLSecurityProperties{minSSF: ssf, maxSSF: ssf, maxBufferSize: 64},
			}
			if err := bindSyncConsumerSASL(transport, config, "ldap://ldap.example.test"); err != nil {
				t.Fatal(err)
			}
			if transport.ssf != ssf || transport.currentConnection() == raw || string(config.credentials) != "secret" {
				t.Fatal("security installation or credential ownership is incorrect")
			}
			if err := transport.clearDeadline(); err != nil {
				t.Fatal(err)
			}
			client := ldap.NewConn(&syncConsumerResponseConn{Conn: transport.currentConnection()}, false)
			client.Start()
			client.SetTimeout(3 * time.Second)
			defer client.Close()
			var group sync.WaitGroup
			for range 8 {
				group.Go(func() {
					identity, err := client.WhoAmI(nil)
					if err != nil {
						t.Error(err)
						return
					}
					if identity.AuthzID != "dn:uid=alice,ou=people,dc=example,dc=com" {
						t.Errorf("identity = %q", identity.AuthzID)
					}
				})
			}
			group.Wait()
		})
	}
}

func setSyncConsumerSecurityTestGlobal(t *testing.T, store storage.Store, attribute, value string) {
	t.Helper()
	dn, err := directory.ParseDN("cn=config")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(attribute, stringValues(value))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
}

// These factories exercise the actual client-direction wrappers used by syncrepl.
func syncConsumerSecurityTestFactories() map[string]func(net.Conn) (net.Conn, error) {
	factories := make(map[string]func(net.Conn) (net.Conn, error))
	for _, ssf := range []uint32{1, 40, 55, 56, 112, 128} {
		factories[fmt.Sprintf("DIGEST-MD5/%d", ssf)] = func(raw net.Conn) (net.Conn, error) {
			qop, cipher, err := selectSyncConsumerDIGESTMD5Security("auth-int,auth-conf", "rc4,rc4-40,rc4-56,des,3des",
				syncConsumerSASLSecurityProperties{minSSF: ssf, maxSSF: ssf, maxBufferSize: 64}, 0)
			if err != nil {
				return nil, err
			}
			transport := &syncConsumerTransport{connection: raw}
			err = installSyncConsumerDIGESTMD5Security(transport, &syncConsumerDIGESTMD5{
				qop: qop, cipher: cipher, valid: true, sessionKey: []byte("0123456789abcdef"), peerMaxBuffer: 64,
				properties: syncConsumerSASLSecurityProperties{maxBufferSize: 64},
			})
			return transport.currentConnection(), err
		}
	}
	for _, confidential := range []bool{false, true} {
		factories[fmt.Sprintf("GSSAPI/confidential=%t", confidential)] = func(raw net.Conn) (net.Conn, error) {
			if confidential {
				return saslkrb5.NewConfidentialityConnection(raw, ldapBackendGSSAPITestKey(), false, saslkrb5.SecurityState{}, 128, 128)
			}
			return saslkrb5.NewIntegrityConnection(raw, ldapBackendGSSAPITestKey(), false, saslkrb5.SecurityState{}, 128, 128)
		}
	}
	return factories
}

func TestSyncConsumerSASLSecurityFramingFailures(t *testing.T) {
	for name, factory := range syncConsumerSecurityTestFactories() {
		t.Run(name, func(t *testing.T) {
			for _, input := range [][]byte{{0, 0, 0, 0}, {255, 255, 255, 255}, {0, 0}, {0, 0, 0, 40, 1}} {
				raw := &syncConsumerSecurityTestConn{reader: bytes.NewReader(input)}
				secured, err := factory(raw)
				if err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 4)
				if n, err := secured.Read(buffer); n != 0 || err == nil {
					t.Fatalf("bad frame accepted: %x", input)
				}
				reads := raw.reads
				if n, err := secured.Read(buffer); n != 0 || err == nil || raw.reads != reads {
					t.Fatal("resumed failed frame stream")
				}
				secured.Close()
			}
			raw := &syncConsumerSecurityTestConn{reader: bytes.NewReader(nil), writeFailure: true}
			secured, err := factory(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := secured.Write([]byte("protected")); err == nil {
				t.Fatal("write failure lost")
			}
			writes := raw.writes
			if _, err := secured.Write([]byte("retry")); err == nil || raw.writes != writes {
				t.Fatal("retried a partial frame")
			}
			secured.Close()
		})
	}
}

func TestSyncConsumerSASLSecurityConcurrentClose(t *testing.T) {
	for name, factory := range syncConsumerSecurityTestFactories() {
		t.Run(name, func(t *testing.T) {
			raw, peer := net.Pipe()
			defer peer.Close()
			secured, err := factory(raw)
			if err != nil {
				t.Fatal(err)
			}
			var group sync.WaitGroup
			for range 8 {
				group.Go(func() { _, _ = secured.Read(make([]byte, 1)) })
				group.Go(func() { _, _ = secured.Write([]byte("x")) })
				group.Go(func() { _ = secured.Close() })
			}
			group.Wait()
			if _, err := secured.Write([]byte("after close")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after close = %v", err)
			}
			if _, err := secured.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read after close = %v", err)
			}
		})
	}
}

type syncConsumerSecurityTestConn struct {
	net.Conn
	reader        *bytes.Reader
	written       bytes.Buffer
	reads, writes int
	writeFailure  bool
}

func (c *syncConsumerSecurityTestConn) Read(b []byte) (int, error) {
	c.reads++
	return c.reader.Read(b[:min(1, len(b))])
}
func (c *syncConsumerSecurityTestConn) Write(b []byte) (int, error) {
	c.writes++
	if c.writeFailure {
		return 1, io.ErrUnexpectedEOF
	}
	return c.written.Write(b[:min(3, len(b))])
}
func (c *syncConsumerSecurityTestConn) Close() error { return nil }

func TestSyncConsumerSASLSecurityFragmentationAndTampering(t *testing.T) {
	for name, factory := range syncConsumerSecurityTestFactories() {
		t.Run(name, func(t *testing.T) {
			wire := &syncConsumerSecurityTestConn{}
			sender, err := factory(wire)
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			message := bytes.Repeat([]byte("protected LDAP message"), 15)
			if n, err := sender.Write(message); n != len(message) || err != nil {
				t.Fatalf("write = %d, %v", n, err)
			}
			encoded := bytes.Clone(wire.written.Bytes())
			if name != "DIGEST-MD5/1" && name != "GSSAPI/confidential=false" && bytes.Contains(encoded, []byte("protected LDAP message")) {
				t.Fatal("confidential layer exposed plaintext")
			}
			// Reverse directions using the independently constructed server wrappers.
			newReceiver := func(input []byte) net.Conn {
				raw := &syncConsumerSecurityTestConn{reader: bytes.NewReader(input)}
				var receiver net.Conn
				var err error
				switch sender.(type) {
				case *saslDigestMD5IntegrityConnection:
					receiver, err = newSASLDigestMD5ServerIntegrityConnection(raw, []byte("0123456789abcdef"), 64, 64)
				case *saslDigestMD5PrivacyConnection:
					var ssf uint32
					fmt.Sscanf(name, "DIGEST-MD5/%d", &ssf)
					for _, cipher := range orderedSASLDigestMD5Ciphers() {
						if cipher.ssf == ssf {
							receiver, err = newSASLDigestMD5ServerPrivacyConnection(raw, []byte("0123456789abcdef"), cipher, 64, 64)
						}
					}
				default:
					if strings.HasSuffix(name, "true") {
						receiver, err = saslkrb5.NewConfidentialityConnection(raw, ldapBackendGSSAPITestKey(), true, saslkrb5.SecurityState{}, 128, 128)
					} else {
						receiver, err = saslkrb5.NewIntegrityConnection(raw, ldapBackendGSSAPITestKey(), true, saslkrb5.SecurityState{}, 128, 128)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				return receiver
			}
			receiver := newReceiver(encoded)
			decoded := make([]byte, len(message))
			if _, err := io.ReadFull(receiver, decoded); err != nil || !bytes.Equal(decoded, message) {
				t.Fatalf("fragmented roundtrip: %v", err)
			}
			receiver.Close()
			frameEnd := 4 + int(binary.BigEndian.Uint32(encoded[:4]))
			for _, damage := range []string{"tamper", "replay"} {
				input := bytes.Clone(encoded[:frameEnd])
				if damage == "tamper" {
					input[frameEnd-7] ^= 0x80
				} else {
					input = append(input, input...)
				}
				receiver := newReceiver(input)
				_, err := io.ReadAll(receiver)
				if err == nil {
					t.Fatalf("accepted %s", damage)
				}
				receiver.Close()
			}
		})
	}
}
