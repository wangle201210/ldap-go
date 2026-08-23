package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	lloaddruntime "github.com/wangle201210/ldap-go/internal/lloadd"
)

func TestLloaddProxyProtocolV2AddressesAndMetadata(t *testing.T) {
	tests := []struct {
		name        string
		packet      []byte
		wantSource  string
		wantTarget  string
		wantLocal   bool
		wantTLVType byte
		wantTLV     string
	}{
		{
			name: "TCP4",
			packet: lloaddProxyProtocolTCP4Packet(
				t, "192.0.2.10", "198.51.100.20", 42310, 389,
				lloaddProxyProtocolTLV(0x01, []byte("ldap")),
			),
			wantSource:  "192.0.2.10:42310",
			wantTarget:  "198.51.100.20:389",
			wantTLVType: 0x01,
			wantTLV:     "ldap",
		},
		{
			name: "TCP6",
			packet: lloaddProxyProtocolTCP6Packet(
				t, "2001:db8::10", "2001:db8::20", 42311, 636,
				lloaddProxyProtocolTLV(0x05, []byte("connection-id")),
			),
			wantSource:  "[2001:db8::10]:42311",
			wantTarget:  "[2001:db8::20]:636",
			wantTLVType: 0x05,
			wantTLV:     "connection-id",
		},
		{
			name: "LOCAL ignores family and opaque options",
			packet: lloaddProxyProtocolPacket(
				0x20,
				0x11,
				[]byte{0xff, 0x00, 0x04, 0xde, 0xad},
			),
			wantLocal: true,
		},
		{
			name: "LOCAL accepts maximum opaque options",
			packet: lloaddProxyProtocolPacket(
				0x20,
				0x21,
				bytes.Repeat([]byte{0xff}, lloaddProxyProtocolMaxOptionBytes),
			),
			wantLocal: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			listener := newProxyProtocolListener(source, time.Second)
			defer listener.Close()
			accepted := make(chan proxyProtocolAcceptResult, 1)
			go acceptProxyProtocolTestConnection(listener, accepted)

			client, err := net.DialTimeout("tcp", source.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer client.Close()
			physicalSource := client.LocalAddr().String()
			physicalTarget := client.RemoteAddr().String()
			if _, err := client.Write(append(test.packet, []byte("ldap-payload")...)); err != nil {
				t.Fatalf("write PROXY packet: %v", err)
			}

			server := awaitProxyProtocolAccept(t, accepted)
			defer server.Close()
			wantSource, wantTarget := test.wantSource, test.wantTarget
			if test.wantLocal {
				wantSource, wantTarget = physicalSource, physicalTarget
			}
			if server.RemoteAddr().String() != wantSource || server.LocalAddr().String() != wantTarget {
				t.Fatalf(
					"logical addresses = %s -> %s, want %s -> %s",
					server.RemoteAddr(), server.LocalAddr(), wantSource, wantTarget,
				)
			}
			metadata, ok := lloaddruntime.MetadataFromConnection(server)
			if !ok || !metadata.ProxyProtocol || metadata.ProxyProtocolLocal != test.wantLocal {
				t.Fatalf("connection metadata = %#v, present=%t", metadata, ok)
			}
			if metadata.TransportSourceAddress.String() != physicalSource ||
				metadata.TransportDestinationAddress.String() != physicalTarget {
				t.Fatalf(
					"transport addresses = %s -> %s, want %s -> %s",
					metadata.TransportSourceAddress,
					metadata.TransportDestinationAddress,
					physicalSource,
					physicalTarget,
				)
			}
			if test.wantLocal && len(metadata.TLVs) != 0 {
				t.Fatalf("LOCAL opaque options were exposed as TLVs: %#v", metadata.TLVs)
			}
			if test.wantTLV != "" {
				if len(metadata.TLVs) != 1 || metadata.TLVs[0].Type != test.wantTLVType ||
					string(metadata.TLVs[0].Value) != test.wantTLV {
					t.Fatalf("TLVs = %#v", metadata.TLVs)
				}
				metadata.TLVs[0].Value[0] = 'X'
				again, _ := lloaddruntime.MetadataFromConnection(server)
				if string(again.TLVs[0].Value) != test.wantTLV {
					t.Fatalf("connection metadata was mutated through snapshot: %#v", again.TLVs)
				}
			}
			payload := make([]byte, len("ldap-payload"))
			if _, err := io.ReadFull(server, payload); err != nil || string(payload) != "ldap-payload" {
				t.Fatalf("LDAP payload = %q, %v", payload, err)
			}
		})
	}
}

func TestLloaddProxyProtocolV2RejectsMalformedAndRecovers(t *testing.T) {
	source, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	listener := newProxyProtocolListener(source, 100*time.Millisecond)
	defer listener.Close()
	accepted := make(chan proxyProtocolAcceptResult, 1)
	go acceptProxyProtocolTestConnection(listener, accepted)

	validSignature := append([]byte(nil), lloaddProxyProtocolV2Signature...)
	badSignature := append([]byte(nil), validSignature...)
	badSignature[0] = 0
	oversizedOptions := make([]byte, lloaddProxyProtocolMaxOptionBytes+1)
	malformed := []struct {
		name   string
		packet []byte
	}{
		{name: "short fixed header", packet: validSignature[:8]},
		{name: "bad signature", packet: append(badSignature, 0x20, 0x00, 0x00, 0x00)},
		{name: "version one", packet: lloaddProxyProtocolPacket(0x10, 0x00, nil)},
		{name: "unknown command", packet: lloaddProxyProtocolPacket(0x22, 0x00, nil)},
		{name: "PROXY unspecified family", packet: lloaddProxyProtocolPacket(0x21, 0x00, nil)},
		{name: "TCP4 short address", packet: lloaddProxyProtocolPacket(0x21, 0x11, make([]byte, 11))},
		{
			name:   "LOCAL oversized opaque options",
			packet: lloaddProxyProtocolPacket(0x20, 0x11, oversizedOptions),
		},
		{
			name: "PROXY oversized opaque options",
			packet: lloaddProxyProtocolTCP4Packet(
				t, "192.0.2.1", "198.51.100.1", 41000, 389, oversizedOptions,
			),
		},
	}
	for _, test := range malformed {
		t.Run(test.name, func(t *testing.T) {
			connection, err := net.DialTimeout("tcp", source.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			if _, err := connection.Write(test.packet); err != nil {
				_ = connection.Close()
				t.Fatalf("write malformed packet: %v", err)
			}
			if tcp, ok := connection.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			expectProxyProtocolConnectionClosed(t, connection)
		})
	}

	timedOut, err := net.DialTimeout("tcp", source.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial timeout case: %v", err)
	}
	expectProxyProtocolConnectionClosed(t, timedOut)

	valid, err := net.DialTimeout("tcp", source.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial recovery case: %v", err)
	}
	defer valid.Close()
	if _, err := valid.Write(lloaddProxyProtocolTCP4Packet(
		t, "192.0.2.30", "198.51.100.30", 43000, 389, nil,
	)); err != nil {
		t.Fatalf("write recovery header: %v", err)
	}
	server := awaitProxyProtocolAccept(t, accepted)
	defer server.Close()
	if server.RemoteAddr().String() != "192.0.2.30:43000" {
		t.Fatalf("recovered source address = %s", server.RemoteAddr())
	}
}

func TestLloaddProxyProtocolV2AcceptsOpaqueProxyOptions(t *testing.T) {
	tests := []struct {
		name    string
		options []byte
	}{
		{name: "truncated TLV header", options: []byte{0x01}},
		{name: "truncated TLV value", options: []byte{0x01, 0x00, 0x02, 0x42}},
		{
			name: "valid TLV followed by malformed option",
			options: append(
				lloaddProxyProtocolTLV(0x01, []byte("ldap")),
				0xff,
			),
		},
		{
			name:    "more than metadata TLV limit",
			options: bytes.Repeat([]byte{0x04, 0x00, 0x00}, lloaddProxyProtocolMaxTLVs+1),
		},
		{
			name:    "maximum opaque options",
			options: bytes.Repeat([]byte{0xff}, lloaddProxyProtocolMaxOptionBytes),
		},
	}
	ldapPayload := []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			listener := newProxyProtocolListener(source, time.Second)
			defer listener.Close()
			accepted := make(chan proxyProtocolAcceptResult, 1)
			go acceptProxyProtocolTestConnection(listener, accepted)

			client, err := net.DialTimeout("tcp", source.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer client.Close()
			packet := lloaddProxyProtocolTCP4Packet(
				t, "192.0.2.1", "198.51.100.1", 41000, 389, test.options,
			)
			if _, err := client.Write(append(packet, ldapPayload...)); err != nil {
				t.Fatalf("write PROXY packet and LDAP payload: %v", err)
			}

			server := awaitProxyProtocolAccept(t, accepted)
			defer server.Close()
			metadata, ok := lloaddruntime.MetadataFromConnection(server)
			if !ok {
				t.Fatal("PROXY connection metadata is missing")
			}
			if len(metadata.TLVs) != 0 {
				t.Fatalf("malformed opaque options were exposed as TLVs: %#v", metadata.TLVs)
			}
			gotPayload := make([]byte, len(ldapPayload))
			if _, err := io.ReadFull(server, gotPayload); err != nil {
				t.Fatalf("read LDAP payload after opaque options: %v", err)
			}
			if !bytes.Equal(gotPayload, ldapPayload) {
				t.Fatalf("LDAP payload = %x, want %x", gotPayload, ldapPayload)
			}
		})
	}
}

func TestOpenLDAPLloaddProxyProtocolOpaqueOptionsSourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPClientToolsCommit {
		t.Fatalf("OpenLDAP source commit = %q, want %q", got, openLDAPClientToolsCommit)
	}
	assertOpenLDAPClientSourceAnchors(t, source, "servers/slapd/proxyp.c", []string{
		"case 0x01: /* PROXY command */",
		"pph_len -= addr_len;",
		"case 0x00: /* LOCAL command */",
		"local connection, ignoring proxy data",
		"/* Clear out any options left in proxy packet */",
		"tcp_read( SLAP_FD2SOCK (sfd), &proxyp_options, pph_len )",
	})
}

func TestLloaddPLDAPSReadsProxyHeaderBeforeTLS(t *testing.T) {
	files := newLloaddTLSFiles(t)
	serverTLS, err := loadLloaddClientTLS(files.certificate, files.key)
	if err != nil {
		t.Fatalf("load listener TLS: %v", err)
	}
	listener, description, err := listenLloaddURL("pldaps://127.0.0.1:0/", serverTLS)
	if err != nil {
		t.Fatalf("listen PLDAPS: %v", err)
	}
	defer listener.Close()
	if !strings.HasPrefix(description, "pldaps://127.0.0.1:") {
		t.Fatalf("description = %q", description)
	}
	accepted := make(chan proxyProtocolAcceptResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			secured, ok := connection.(*tls.Conn)
			if !ok {
				acceptErr = fmt.Errorf("accepted PLDAPS connection has type %T", connection)
			} else {
				acceptErr = secured.Handshake()
			}
		}
		accepted <- proxyProtocolAcceptResult{connection: connection, err: acceptErr}
	}()

	withoutHeader, err := tls.Dial("tcp", listener.Addr().String(), lloaddTLSClientConfig(t, files.ca))
	if err == nil {
		_ = withoutHeader.Close()
		t.Fatal("PLDAPS accepted TLS before a PROXY v2 header")
	}

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial PLDAPS: %v", err)
	}
	if _, err := raw.Write(lloaddProxyProtocolTCP4Packet(
		t, "192.0.2.40", "198.51.100.40", 44000, 636, nil,
	)); err != nil {
		_ = raw.Close()
		t.Fatalf("write PROXY header: %v", err)
	}
	secured := tls.Client(raw, lloaddTLSClientConfig(t, files.ca))
	if err := secured.Handshake(); err != nil {
		_ = secured.Close()
		t.Fatalf("TLS after PROXY header: %v", err)
	}
	defer secured.Close()
	server := awaitProxyProtocolAccept(t, accepted)
	defer server.Close()
	metadata, ok := lloaddruntime.MetadataFromConnection(server)
	if !ok || server.RemoteAddr().String() != "192.0.2.40:44000" ||
		server.LocalAddr().String() != "198.51.100.40:636" ||
		metadata.TransportSourceAddress.String() == metadata.SourceAddress.String() {
		t.Fatalf("PLDAPS metadata = %#v, logical=%s -> %s", metadata, server.RemoteAddr(), server.LocalAddr())
	}
}

func TestLloaddProxyProtocolRealTopologyAndConnectionSnapshot(t *testing.T) {
	upstreamURI := startLDAPClientToolServer(t, nil)
	upstreamAddress := strings.TrimPrefix(upstreamURI, "ldap://")
	files := newLloaddTLSFiles(t)
	serverTLS, err := loadLloaddClientTLS(files.certificate, files.key)
	if err != nil {
		t.Fatalf("load listener TLS: %v", err)
	}
	for _, test := range []struct {
		name      string
		scheme    string
		serverTLS *tls.Config
		clientTLS *tls.Config
	}{
		{name: "PLDAP", scheme: "pldap"},
		{
			name:      "PLDAPS",
			scheme:    "pldaps",
			serverTLS: serverTLS,
			clientTLS: lloaddTLSClientConfig(t, files.ca),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, _, err := listenLloaddURL(test.scheme+"://127.0.0.1:0/", test.serverTLS)
			if err != nil {
				t.Fatalf("listen %s: %v", test.scheme, err)
			}
			proxy, err := lloaddruntime.NewProxy(lloaddruntime.RuntimeConfig{
				ProxyAuthz: true,
				Tiers: []lloaddruntime.RuntimeTierConfig{{
					Strategy: "roundrobin",
					Backends: []lloaddruntime.RuntimeBackendConfig{{
						URI:                  "ldap://" + upstreamAddress,
						RegularConnections:   1,
						BindConnections:      1,
						Retry:                10 * time.Millisecond,
						MaxPendingOperations: 16,
						ConnectionMaxPending: 16,
						Weight:               1,
					}},
				}},
			})
			if err != nil {
				_ = listener.Close()
				t.Fatalf("new lloadd proxy: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- proxy.Serve(ctx, listener) }()
			defer func() {
				cancel()
				_ = proxy.Close()
				select {
				case serveErr := <-done:
					if serveErr != nil {
						t.Errorf("lloadd Serve: %v", serveErr)
					}
				case <-time.After(5 * time.Second):
					t.Error("lloadd proxy did not stop")
				}
			}()

			raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("dial %s: %v", test.scheme, err)
			}
			if _, err := raw.Write(lloaddProxyProtocolTCP4Packet(
				t, "192.0.2.50", "198.51.100.50", 45000, 636, nil,
			)); err != nil {
				_ = raw.Close()
				t.Fatalf("write PROXY header: %v", err)
			}
			connection := net.Conn(raw)
			isTLS := test.clientTLS != nil
			if isTLS {
				secured := tls.Client(raw, test.clientTLS.Clone())
				if err := secured.Handshake(); err != nil {
					_ = raw.Close()
					t.Fatalf("PLDAPS handshake: %v", err)
				}
				connection = secured
			}
			client := ldap.NewConn(connection, isTLS)
			client.Start()
			defer client.Close()
			deadline := time.Now().Add(3 * time.Second)
			for {
				err = client.Bind(clientToolRootDN, clientToolRootPassword)
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("Bind through %s: %v", test.scheme, err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			var snapshot lloaddruntime.ClientConnectionSnapshot
			for time.Now().Before(deadline) {
				for _, candidate := range proxy.ClientConnectionSnapshots() {
					if candidate.Metadata.ProxyProtocol {
						snapshot = candidate
						break
					}
				}
				if snapshot.AuthorizationIdentity == "dn:"+clientToolRootDN {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if snapshot.Metadata.SourceAddress == nil ||
				snapshot.Metadata.SourceAddress.String() != "192.0.2.50:45000" ||
				snapshot.Metadata.DestinationAddress.String() != "198.51.100.50:636" ||
				snapshot.AuthorizationIdentity != "dn:"+clientToolRootDN ||
				snapshot.TLS != isTLS {
				t.Fatalf("client metadata snapshot = %#v", snapshot)
			}
		})
	}
}

func TestOrdinaryLloaddListenersRejectProxyProtocolHeader(t *testing.T) {
	files := newLloaddTLSFiles(t)
	serverTLS, err := loadLloaddClientTLS(files.certificate, files.key)
	if err != nil {
		t.Fatalf("load listener TLS: %v", err)
	}
	for _, test := range []struct {
		scheme string
		tls    *tls.Config
	}{
		{scheme: "ldap"},
		{scheme: "ldaps", tls: serverTLS},
	} {
		t.Run(strings.ToUpper(test.scheme), func(t *testing.T) {
			listener, _, err := listenLloaddURL(test.scheme+"://127.0.0.1:0/", test.tls)
			if err != nil {
				t.Fatalf("listen %s: %v", test.scheme, err)
			}
			proxy, err := lloaddruntime.NewProxy(lloaddruntime.RuntimeConfig{})
			if err != nil {
				_ = listener.Close()
				t.Fatalf("new proxy: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- proxy.Serve(ctx, listener) }()
			defer func() {
				cancel()
				_ = proxy.Close()
				<-done
			}()
			connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("dial %s: %v", test.scheme, err)
			}
			if _, err := connection.Write(lloaddProxyProtocolPacket(0x20, 0x00, nil)); err != nil {
				_ = connection.Close()
				t.Fatalf("write PROXY header: %v", err)
			}
			expectProxyProtocolConnectionClosed(t, connection)
		})
	}
}

type proxyProtocolAcceptResult struct {
	connection net.Conn
	err        error
}

func acceptProxyProtocolTestConnection(
	listener net.Listener,
	result chan<- proxyProtocolAcceptResult,
) {
	connection, err := listener.Accept()
	result <- proxyProtocolAcceptResult{connection: connection, err: err}
}

func awaitProxyProtocolAccept(
	t *testing.T,
	accepted <-chan proxyProtocolAcceptResult,
) net.Conn {
	t.Helper()
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("accept PROXY connection: %v", result.err)
		}
		return result.connection
	case <-time.After(3 * time.Second):
		t.Fatal("timed out accepting PROXY connection")
		return nil
	}
}

func expectProxyProtocolConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("malformed PROXY connection remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("malformed PROXY connection was not closed: %v", err)
	}
}

func lloaddProxyProtocolTCP4Packet(
	t *testing.T,
	source, destination string,
	sourcePort, destinationPort int,
	tlvs []byte,
) []byte {
	t.Helper()
	sourceIP := net.ParseIP(source).To4()
	destinationIP := net.ParseIP(destination).To4()
	if sourceIP == nil || destinationIP == nil {
		t.Fatalf("invalid TCP4 addresses %q -> %q", source, destination)
	}
	address := make([]byte, 12)
	copy(address[:4], sourceIP)
	copy(address[4:8], destinationIP)
	binary.BigEndian.PutUint16(address[8:10], uint16(sourcePort))
	binary.BigEndian.PutUint16(address[10:12], uint16(destinationPort))
	return lloaddProxyProtocolPacket(0x21, 0x11, append(address, tlvs...))
}

func lloaddProxyProtocolTCP6Packet(
	t *testing.T,
	source, destination string,
	sourcePort, destinationPort int,
	tlvs []byte,
) []byte {
	t.Helper()
	sourceIP := net.ParseIP(source).To16()
	destinationIP := net.ParseIP(destination).To16()
	if sourceIP == nil || destinationIP == nil {
		t.Fatalf("invalid TCP6 addresses %q -> %q", source, destination)
	}
	address := make([]byte, 36)
	copy(address[:16], sourceIP)
	copy(address[16:32], destinationIP)
	binary.BigEndian.PutUint16(address[32:34], uint16(sourcePort))
	binary.BigEndian.PutUint16(address[34:36], uint16(destinationPort))
	return lloaddProxyProtocolPacket(0x21, 0x21, append(address, tlvs...))
}

func lloaddProxyProtocolTLV(tlvType byte, value []byte) []byte {
	encoded := make([]byte, 3+len(value))
	encoded[0] = tlvType
	binary.BigEndian.PutUint16(encoded[1:3], uint16(len(value)))
	copy(encoded[3:], value)
	return encoded
}

func lloaddProxyProtocolPacket(versionCommand, familyProtocol byte, body []byte) []byte {
	packet := make([]byte, 16+len(body))
	copy(packet[:12], lloaddProxyProtocolV2Signature)
	packet[12] = versionCommand
	packet[13] = familyProtocol
	binary.BigEndian.PutUint16(packet[14:16], uint16(len(body)))
	copy(packet[16:], body)
	return packet
}
