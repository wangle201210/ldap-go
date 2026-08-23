package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
)

func TestLDAPClientSCRAMPlusChannelBindingCertificateHashRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm x509.SignatureAlgorithm
		digest    func([]byte) []byte
	}{
		{
			name:      "SHA-1 certificate upgrades to SHA-256",
			algorithm: x509.SHA1WithRSA,
			digest: func(value []byte) []byte {
				sum := sha256.Sum256(value)
				return sum[:]
			},
		},
		{
			name:      "SHA-256 certificate",
			algorithm: x509.ECDSAWithSHA256,
			digest: func(value []byte) []byte {
				sum := sha256.Sum256(value)
				return sum[:]
			},
		},
		{
			name:      "SHA-384 certificate",
			algorithm: x509.ECDSAWithSHA384,
			digest: func(value []byte) []byte {
				sum := sha512.Sum384(value)
				return sum[:]
			},
		},
		{
			name:      "SHA-512 certificate",
			algorithm: x509.ECDSAWithSHA512,
			digest: func(value []byte) []byte {
				sum := sha512.Sum512(value)
				return sum[:]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificate := &x509.Certificate{
				Raw:                []byte("SCRAM-PLUS certificate vector " + test.name),
				SignatureAlgorithm: test.algorithm,
			}
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			connection := &ldapClientSASLSwitchConnection{connection: &ldapClientTLSStateConnection{
				Conn: local,
				state: tls.ConnectionState{
					HandshakeComplete: true,
					PeerCertificates:  []*x509.Certificate{certificate},
					VerifiedChains:    [][]*x509.Certificate{{certificate}},
				},
			}}
			binding, err := connection.scramChannelBinding()
			if err != nil {
				t.Fatalf("SCRAM channel binding: %v", err)
			}
			defer clear(binding.Data)
			if binding.Type != "tls-server-end-point" ||
				!bytes.Equal(binding.Data, test.digest(certificate.Raw)) {
				t.Fatalf("channel binding = %q %x", binding.Type, binding.Data)
			}
		})
	}
}

func TestLDAPClientSCRAMPlusRejectsUnverifiedOrNonTLSConnection(t *testing.T) {
	t.Parallel()

	certificate := &x509.Certificate{
		Raw:                []byte("unverified SCRAM-PLUS certificate"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	tests := []struct {
		name       string
		connection func(net.Conn) net.Conn
	}{
		{
			name: "non TLS",
			connection: func(connection net.Conn) net.Conn {
				return connection
			},
		},
		{
			name: "TLS handshake incomplete",
			connection: func(connection net.Conn) net.Conn {
				return &ldapClientTLSStateConnection{
					Conn: connection,
					state: tls.ConnectionState{
						PeerCertificates: []*x509.Certificate{certificate},
						VerifiedChains:   [][]*x509.Certificate{{certificate}},
					},
				}
			},
		},
		{
			name: "TLS certificate unverified",
			connection: func(connection net.Conn) net.Conn {
				return &ldapClientTLSStateConnection{
					Conn: connection,
					state: tls.ConnectionState{
						HandshakeComplete: true,
						PeerCertificates:  []*x509.Certificate{certificate},
					},
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			connection := &ldapClientSASLSwitchConnection{
				connection: test.connection(local),
			}
			if _, err := connection.scramChannelBinding(); err == nil ||
				!strings.Contains(err.Error(), "verified server certificate") {
				t.Fatalf("SCRAM channel binding error = %v", err)
			}
		})
	}
}
