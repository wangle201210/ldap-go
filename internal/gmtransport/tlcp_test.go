package gmtransport_test

import (
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/wangle201210/ldap-go/internal/gmtransport"
)

func TestTLCPServerHandshake(t *testing.T) {
	t.Parallel()

	serverConfig, clientConfig := testTLCPConfigs(t)
	transport, err := gmtransport.NewTLCP(serverConfig)
	if err != nil {
		t.Fatalf("NewTLCP(): %v", err)
	}
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverResult := make(chan struct {
		connection net.Conn
		err        error
	}, 1)
	go func() {
		connection, err := transport.ServerHandshake(ctx, serverSide)
		serverResult <- struct {
			connection net.Conn
			err        error
		}{connection: connection, err: err}
	}()

	client := tlcp.Client(clientSide, clientConfig)
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("client HandshakeContext(): %v", err)
	}
	if state := client.ConnectionState(); state.CipherSuite != tlcp.ECC_SM4_GCM_SM3 {
		t.Fatalf("TLCP cipher suite = %#x", state.CipherSuite)
	}
	result := <-serverResult
	if result.err != nil {
		t.Fatalf("server ServerHandshake(): %v", result.err)
	}
	identityProvider, ok := result.connection.(interface {
		ExternalIdentity() (string, bool)
	})
	if !ok {
		t.Fatal("TLCP connection does not expose an external identity")
	}
	if identity, ok := identityProvider.ExternalIdentity(); !ok ||
		identity != "CN=ldap-go TLCP client" {
		t.Fatalf("TLCP external identity = %q, %v", identity, ok)
	}

	payload := []byte("ldap over tlcp")
	writeResult := make(chan error, 1)
	go func() {
		_, err := result.connection.Write(payload)
		writeResult <- err
	}()
	read := make([]byte, len(payload))
	if _, err := io.ReadFull(client, read); err != nil {
		t.Fatalf("ReadFull(): %v", err)
	}
	if err := <-writeResult; err != nil {
		t.Fatalf("Write(): %v", err)
	}
	if string(read) != string(payload) {
		t.Fatalf("TLCP payload = %q, want %q", read, payload)
	}
	_ = clientSide.Close()
	_ = result.connection.Close()
}

func TestNewTLCPRequiresDualCertificates(t *testing.T) {
	t.Parallel()

	if _, err := gmtransport.NewTLCP(nil); err == nil {
		t.Fatal("nil TLCP config was accepted")
	}
	if _, err := gmtransport.NewTLCP(&tlcp.Config{}); err == nil {
		t.Fatal("TLCP config without certificates was accepted")
	}
	serverConfig, _ := testTLCPConfigs(t)
	serverConfig.Certificates = serverConfig.Certificates[:1]
	if _, err := gmtransport.NewTLCP(serverConfig); err == nil {
		t.Fatal("TLCP config without encryption certificate was accepted")
	}
}

func TestLoadTLCPDualCertificateFiles(t *testing.T) {
	t.Parallel()

	serverConfig, _ := testTLCPConfigs(t)
	directory := t.TempDir()
	files := make([]string, 0, 4)
	for index, certificate := range serverConfig.Certificates {
		privateKey, ok := certificate.PrivateKey.(*sm2.PrivateKey)
		if !ok {
			t.Fatalf("certificate %d private key type = %T", index, certificate.PrivateKey)
		}
		privateKeyDER, err := smx509.MarshalSM2PrivateKey(privateKey)
		if err != nil {
			t.Fatalf("MarshalSM2PrivateKey(%d): %v", index, err)
		}
		certificateFile := filepath.Join(
			directory,
			fmt.Sprintf("certificate-%d.pem", index),
		)
		privateKeyFile := filepath.Join(
			directory,
			fmt.Sprintf("private-key-%d.pem", index),
		)
		if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Certificate[0],
		}), 0o600); err != nil {
			t.Fatalf("WriteFile(certificate %d): %v", index, err)
		}
		if err := os.WriteFile(privateKeyFile, pem.EncodeToMemory(&pem.Block{
			Type:  "SM2 PRIVATE KEY",
			Bytes: privateKeyDER,
		}), 0o600); err != nil {
			t.Fatalf("WriteFile(private key %d): %v", index, err)
		}
		files = append(files, certificateFile, privateKeyFile)
	}
	if _, err := gmtransport.LoadTLCP(
		files[0],
		files[1],
		files[2],
		files[3],
	); err != nil {
		t.Fatalf("LoadTLCP(): %v", err)
	}
	if _, err := gmtransport.LoadTLCPWithClientAuth(
		files[0],
		files[1],
		files[2],
		files[3],
		"",
		true,
	); err == nil {
		t.Fatal("required TLCP client certificate without CA was accepted")
	}
	if _, err := gmtransport.LoadTLCPWithClientAuth(
		files[0],
		files[1],
		files[2],
		files[3],
		files[0],
		true,
	); err != nil {
		t.Fatalf("LoadTLCPWithClientAuth(): %v", err)
	}
}

func testTLCPConfigs(t *testing.T) (*tlcp.Config, *tlcp.Config) {
	t.Helper()

	rootKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	now := time.Now()
	rootTemplate := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ldap-go TLCP test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := smx509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		rootKey.Public(),
		rootKey,
	)
	if err != nil {
		t.Fatalf("CreateCertificate(root): %v", err)
	}
	rootCertificate, err := smx509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate(root): %v", err)
	}

	leaf := func(
		serial int64,
		commonName string,
		usage smx509.KeyUsage,
		extendedUsage smx509.ExtKeyUsage,
	) tlcp.Certificate {
		t.Helper()
		key, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", commonName, err)
		}
		template := &smx509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     usage,
			ExtKeyUsage:  []smx509.ExtKeyUsage{extendedUsage},
			DNSNames:     []string{"localhost"},
		}
		der, err := smx509.CreateCertificate(
			rand.Reader,
			template,
			rootCertificate,
			key.Public(),
			rootKey,
		)
		if err != nil {
			t.Fatalf("CreateCertificate(%s): %v", commonName, err)
		}
		parsed, err := smx509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate(%s): %v", commonName, err)
		}
		return tlcp.Certificate{
			Certificate: [][]byte{der, rootDER},
			PrivateKey:  key,
			Leaf:        parsed,
		}
	}

	signing := leaf(
		2,
		"ldap-go TLCP signing",
		smx509.KeyUsageDigitalSignature,
		smx509.ExtKeyUsageServerAuth,
	)
	encryption := leaf(
		3,
		"ldap-go TLCP encryption",
		smx509.KeyUsageKeyEncipherment|
			smx509.KeyUsageDataEncipherment|
			smx509.KeyUsageKeyAgreement,
		smx509.ExtKeyUsageServerAuth,
	)
	client := leaf(
		4,
		"ldap-go TLCP client",
		smx509.KeyUsageDigitalSignature,
		smx509.ExtKeyUsageClientAuth,
	)
	clientEncryption := leaf(
		5,
		"ldap-go TLCP client encryption",
		smx509.KeyUsageKeyEncipherment|
			smx509.KeyUsageDataEncipherment|
			smx509.KeyUsageKeyAgreement,
		smx509.ExtKeyUsageClientAuth,
	)
	rootPool := smx509.NewCertPool()
	rootPool.AddCert(rootCertificate)
	return &tlcp.Config{
			Certificates: []tlcp.Certificate{signing, encryption},
			CipherSuites: []uint16{tlcp.ECC_SM4_GCM_SM3},
			ClientAuth:   tlcp.RequireAndVerifyClientCert,
			ClientCAs:    rootPool,
		}, &tlcp.Config{
			Certificates:       []tlcp.Certificate{client, clientEncryption},
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{tlcp.ECC_SM4_GCM_SM3},
		}
}
