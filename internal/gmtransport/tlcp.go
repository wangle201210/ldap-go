package gmtransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

type TLCP struct {
	config *tlcp.Config
}

type identityConnection struct {
	*tlcp.Conn
}

func (secured *identityConnection) ExternalIdentity() (string, bool) {
	state := secured.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return "", false
	}
	return state.PeerCertificates[0].Subject.String(), true
}

func (*identityConnection) SecurityStrengthFactor() uint32 {
	return 128
}

func NewTLCP(config *tlcp.Config) (*TLCP, error) {
	if config == nil {
		return nil, errors.New("TLCP config is required")
	}
	if len(config.Certificates) == 0 &&
		config.GetCertificate == nil &&
		config.GetConfigForClient == nil {
		return nil, errors.New("TLCP signing certificate is required")
	}
	if len(config.Certificates) < 2 &&
		config.GetKECertificate == nil &&
		config.GetConfigForClient == nil {
		return nil, errors.New("TLCP encryption certificate is required")
	}
	return &TLCP{config: config.Clone()}, nil
}

func LoadTLCP(
	signCertificateFile,
	signPrivateKeyFile,
	encryptionCertificateFile,
	encryptionPrivateKeyFile string,
) (*TLCP, error) {
	return LoadTLCPWithClientAuth(
		signCertificateFile,
		signPrivateKeyFile,
		encryptionCertificateFile,
		encryptionPrivateKeyFile,
		"",
		false,
	)
}

func LoadTLCPWithClientAuth(
	signCertificateFile,
	signPrivateKeyFile,
	encryptionCertificateFile,
	encryptionPrivateKeyFile,
	clientCAFile string,
	requireClientCertificate bool,
) (*TLCP, error) {
	files := []string{
		signCertificateFile,
		signPrivateKeyFile,
		encryptionCertificateFile,
		encryptionPrivateKeyFile,
	}
	for _, file := range files {
		if file == "" {
			return nil, errors.New(
				"TLCP signing and encryption certificate/key files are required",
			)
		}
	}
	signing, err := tlcp.LoadX509KeyPair(
		signCertificateFile,
		signPrivateKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("load TLCP signing certificate: %w", err)
	}
	encryption, err := tlcp.LoadX509KeyPair(
		encryptionCertificateFile,
		encryptionPrivateKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("load TLCP encryption certificate: %w", err)
	}
	config := &tlcp.Config{
		Certificates: []tlcp.Certificate{signing, encryption},
	}
	if requireClientCertificate && clientCAFile == "" {
		return nil, errors.New(
			"requiring a TLCP client certificate needs a client CA file",
		)
	}
	if clientCAFile != "" {
		pemData, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read TLCP client CA: %w", err)
		}
		clientCAs := smx509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(pemData) {
			return nil, errors.New("TLCP client CA file contains no certificates")
		}
		config.ClientCAs = clientCAs
		config.ClientAuth = tlcp.VerifyClientCertIfGiven
		if requireClientCertificate {
			config.ClientAuth = tlcp.RequireAndVerifyClientCert
		}
	}
	return NewTLCP(config)
}

func (transport *TLCP) ServerHandshake(
	ctx context.Context,
	connection net.Conn,
) (net.Conn, error) {
	secured := tlcp.Server(connection, transport.config.Clone())
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return &identityConnection{Conn: secured}, nil
}
