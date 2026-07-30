package gmtransport

import (
	"context"
	"errors"
	"fmt"
	"net"

	"gitee.com/Trisia/gotlcp/tlcp"
)

type TLCP struct {
	config *tlcp.Config
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
	return NewTLCP(&tlcp.Config{
		Certificates: []tlcp.Certificate{signing, encryption},
	})
}

func (transport *TLCP) ServerHandshake(
	ctx context.Context,
	connection net.Conn,
) (net.Conn, error) {
	secured := tlcp.Server(connection, transport.config.Clone())
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return secured, nil
}
