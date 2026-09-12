package server

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/xdg-go/scram"
	"golang.org/x/crypto/pbkdf2"
)

func newSyncSCRAMValidationConversation(t *testing.T, mechanism string) (*syncConsumerSCRAM, string, func() hash.Hash) {
	t.Helper()
	generator, ok := saslSCRAMHashGenerator(mechanism)
	if !ok {
		t.Fatal(mechanism)
	}
	var conversation *syncConsumerSCRAM
	if !saslSCRAMIsPlus(mechanism) {
		_, value, err := newSyncConsumerSASLConversation(syncConsumerConfig{
			saslMechanism: mechanism, authenticationID: "alice", credentials: []byte("secret"),
		})
		if err != nil {
			t.Fatal(err)
		}
		conversation = value.(*syncConsumerSCRAM)
	} else {
		// Isolate proof-transcript handling; real TLS admission is covered by
		// TestSyncConsumerSCRAMPlusRequiresVerifiedTLS and the transport matrix.
		client, err := generator.NewClient("alice", "secret", "")
		if err != nil {
			t.Fatal(err)
		}
		conversation = &syncConsumerSCRAM{conversation: client.NewConversationWithChannelBinding(
			scram.ChannelBinding{Type: "ldap", Data: []byte("tls-server-end-point:test")}), hashSize: generator().Size()}
	}
	first, _, err := conversation.Initial()
	if err != nil {
		t.Fatal(err)
	}
	return conversation, string(first), generator
}

func syncSCRAMTestHMAC(h func() hash.Hash, key []byte, value string) []byte {
	mac := hmac.New(h, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func TestSyncConsumerSCRAMOptionalExtensionsTranscript(t *testing.T) {
	for _, mechanism := range []string{"SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-512-PLUS"} {
		t.Run(mechanism, func(t *testing.T) {
			conversation, first, h := newSyncSCRAMValidationConversation(t, mechanism)
			serverFirst := "r=" + conversation.clientNonce + "server,s=c2FsdA==,i=4096,x=optional=metadata,z=\u6d4b\u8bd5"
			final, err := conversation.Next([]byte(serverFirst))
			if err != nil {
				t.Fatal(err)
			}
			bare := strings.SplitN(first, ",", 3)[2]
			withoutProof, encodedProof, ok := strings.Cut(string(final), ",p=")
			if !ok {
				t.Fatalf("no client proof: %q", final)
			}
			transcript := bare + "," + serverFirst + "," + withoutProof
			salted := pbkdf2.Key([]byte("secret"), []byte("salt"), 4096, h().Size(), h)
			defer clear(salted)
			clientKey := syncSCRAMTestHMAC(h, salted, "Client Key")
			defer clear(clientKey)
			stored := h()
			_, _ = stored.Write(clientKey)
			signature := syncSCRAMTestHMAC(h, stored.Sum(nil), transcript)
			defer clear(signature)
			proof, err := base64.StdEncoding.DecodeString(encodedProof)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(proof)
			for i := range signature {
				signature[i] ^= clientKey[i]
			}
			if !hmac.Equal(proof, signature) {
				t.Fatal("client proof omitted or changed optional extension bytes")
			}
			serverKey := syncSCRAMTestHMAC(h, salted, "Server Key")
			defer clear(serverKey)
			serverSignature := syncSCRAMTestHMAC(h, serverKey, transcript)
			defer clear(serverSignature)
			response, err := conversation.Next([]byte("v=" + base64.StdEncoding.EncodeToString(serverSignature) + ",x=final-extension"))
			if err != nil || len(response) != 0 || !conversation.Valid() || !conversation.Done() {
				t.Fatalf("server proof valid=%v done=%v err=%v", conversation.Valid(), conversation.Done(), err)
			}
		})
	}
}

func TestSyncConsumerSCRAMRejectsInvalidChallenges(t *testing.T) {
	for _, mechanism := range []string{"SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512"} {
		for _, test := range []struct {
			name      string
			challenge func(string) string
		}{
			{"unchanged nonce", func(n string) string { return "r=" + n + ",s=c2FsdA==,i=4096" }},
			{"huge work", func(n string) string { return "r=" + n + "server,s=c2FsdA==,i=2147483647" }},
			{"over budget", func(n string) string { return fmt.Sprintf("r=%sserver,s=c2FsdA==,i=%d", n, maxSASLSCRAMIterations+1) }},
			{"duplicate iteration", func(n string) string { return "r=" + n + "server,s=c2FsdA==,i=4096,i=100000000" }},
			{"mandatory extension", func(n string) string { return "m=required,r=" + n + "server,s=c2FsdA==,i=4096" }},
			{"trailing mandatory extension", func(n string) string { return "r=" + n + "server,s=c2FsdA==,i=4096,m=required" }},
			{"empty extension", func(n string) string { return "r=" + n + "server,s=c2FsdA==,i=4096,x=" }},
			{"duplicate extension", func(n string) string { return "r=" + n + "server,s=c2FsdA==,i=4096,x=a,x=b" }},
			{"invalid UTF8", func(n string) string { return "r=" + n + "server,s=c2FsdA==,i=4096,x=\xff" }},
			{"NUL extension", func(n string) string { return "r=" + n + "server,s=c2FsdA==,i=4096,x=a\x00b" }},
			{"oversized salt", func(n string) string {
				return "r=" + n + "server,s=" + base64.StdEncoding.EncodeToString(make([]byte, 1025)) + ",i=4096"
			}},
			{"oversized message", func(n string) string {
				return "r=" + n + "server,s=c2FsdA==,i=4096,x=" + strings.Repeat("x", maxSASLSCRAMSecretSize)
			}},
		} {
			t.Run(mechanism+"/"+test.name, func(t *testing.T) {
				conversation, _, _ := newSyncSCRAMValidationConversation(t, mechanism)
				response, err := conversation.Next([]byte(test.challenge(conversation.clientNonce)))
				if err == nil || len(response) != 0 || conversation.proofSent || conversation.Valid() {
					t.Fatalf("invalid challenge produced proof: err=%v proofSent=%v", err, conversation.proofSent)
				}
			})
		}
	}
}

func TestSyncConsumerSCRAMReservedFinalExtensions(t *testing.T) {
	conversation := &syncConsumerSCRAM{proofSent: true, hashSize: 32}
	proof := "v=" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, suffix := range []string{",e=invalid-proof", ",v=second", ",m=required", ",x=", ",xyz=value", ",x=a,x=b", ",x=a\x00b"} {
		if err := conversation.validateChallenge([]byte(proof + suffix)); err == nil {
			t.Fatalf("accepted conflicting server-final %q", suffix)
		}
	}
}
