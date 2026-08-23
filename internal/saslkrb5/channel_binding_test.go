package saslkrb5

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestTLSServerEndpointAndAuthenticatorChecksum(t *testing.T) {
	certificate := &x509.Certificate{
		Raw:                []byte("test-certificate-der"),
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	binding, err := TLSServerEndpoint(certificate)
	if err != nil {
		t.Fatalf("TLSServerEndpoint: %v", err)
	}
	wantDigest := sha256.Sum256(certificate.Raw)
	want := append([]byte(tlsServerEndpointPrefix), wantDigest[:]...)
	if !bytes.Equal(binding, want) {
		t.Fatalf("TLS channel binding = %x, want %x", binding, want)
	}
	checksum := authenticatorChecksum(0x3e, binding)
	if binary.LittleEndian.Uint32(checksum[:4]) != 16 ||
		binary.LittleEndian.Uint32(checksum[20:]) != 0x3e {
		t.Fatalf("authenticator checksum framing = %x", checksum)
	}
	if _, err := validateAuthenticatorChecksum(
		structChecksum(checksum), binding,
	); err != nil {
		t.Fatalf("validate matching channel binding: %v", err)
	}
	wrong := append([]byte(nil), binding...)
	wrong[len(wrong)-1] ^= 1
	if _, err := validateAuthenticatorChecksum(
		structChecksum(checksum), wrong,
	); err == nil {
		t.Fatal("mismatched channel binding was accepted")
	}
}

func TestAuthenticatorChecksumRejectsDelegation(t *testing.T) {
	checksum := authenticatorChecksum(1, nil)
	if _, err := validateAuthenticatorChecksum(structChecksum(checksum), nil); err == nil {
		t.Fatal("delegated GSSAPI context was accepted")
	}
}

func TestGSSAPIChannelBindingDefaultsToNULLAndRequiresExplicitExtension(t *testing.T) {
	defaultBinding, err := NormalizeChannelBinding("")
	if err != nil || defaultBinding != ChannelBindingNone {
		t.Fatalf("default channel binding = %q, %v", defaultBinding, err)
	}
	none, err := NormalizeChannelBinding("none")
	if err != nil || none != ChannelBindingNone {
		t.Fatalf("explicit none channel binding = %q, %v", none, err)
	}
	extension, err := NormalizeChannelBinding("TLS-SERVER-END-POINT")
	if err != nil || extension != ChannelBindingTLSServerEndpoint {
		t.Fatalf("TLS channel binding extension = %q, %v", extension, err)
	}
	if _, err := NormalizeChannelBinding("tls-unique"); err == nil {
		t.Fatal("unsupported channel binding was accepted")
	}

	nullChecksum := authenticatorChecksum(0, nil)
	if !bytes.Equal(nullChecksum[4:20], make([]byte, 16)) {
		t.Fatalf("NULL channel binding checksum = %x", nullChecksum[4:20])
	}
	explicitChecksum := authenticatorChecksum(0, []byte("tls-server-end-point:value"))
	if bytes.Equal(explicitChecksum[4:20], nullChecksum[4:20]) {
		t.Fatal("explicit TLS channel binding was encoded as NULL")
	}
}

func structChecksum(value []byte) types.Checksum {
	return types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: value}
}
