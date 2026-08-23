package saslkrb5

import (
	"crypto"
	"crypto/md5" //nolint:gosec // RFC 4121 mandates MD5 for the GSS channel-binding structure.
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const tlsServerEndpointPrefix = "tls-server-end-point:"

const (
	ChannelBindingNone              = ""
	ChannelBindingTLSServerEndpoint = "tls-server-end-point"
)

func NormalizeChannelBinding(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none":
		return ChannelBindingNone, nil
	case ChannelBindingTLSServerEndpoint:
		return ChannelBindingTLSServerEndpoint, nil
	default:
		return "", fmt.Errorf("unsupported GSSAPI channel binding %q", value)
	}
}

// TLSServerEndpoint returns the RFC 5929 application data for a certificate.
func TLSServerEndpoint(certificate *x509.Certificate) ([]byte, error) {
	if certificate == nil || len(certificate.Raw) == 0 {
		return nil, errors.New("TLS server certificate is unavailable")
	}
	hash, err := tlsServerEndpointHash(certificate.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	if !hash.Available() {
		return nil, errors.New("TLS server certificate hash is unavailable")
	}
	digest := hash.New()
	_, _ = digest.Write(certificate.Raw)
	applicationData := make([]byte, 0, len(tlsServerEndpointPrefix)+digest.Size())
	applicationData = append(applicationData, tlsServerEndpointPrefix...)
	applicationData = append(applicationData, digest.Sum(nil)...)
	return applicationData, nil
}

func tlsServerEndpointHash(algorithm x509.SignatureAlgorithm) (crypto.Hash, error) {
	switch algorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1,
		x509.ECDSAWithSHA1:
		return crypto.SHA256, nil
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256,
		x509.ECDSAWithSHA256:
		return crypto.SHA256, nil
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return crypto.SHA384, nil
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return crypto.SHA512, nil
	default:
		return 0, errors.New("TLS server certificate signature has no single expressible hash")
	}
}

func channelBindingChecksum(applicationData []byte) [md5.Size]byte {
	if applicationData == nil {
		return [md5.Size]byte{}
	}
	value := make([]byte, 20, 20+len(applicationData))
	// initiator addrtype/address and acceptor addrtype/address are all empty.
	binary.LittleEndian.PutUint32(value[16:20], uint32(len(applicationData)))
	value = append(value, applicationData...)
	checksum := md5.Sum(value) //nolint:gosec // RFC 4121 wire compatibility.
	clear(value)
	return checksum
}
