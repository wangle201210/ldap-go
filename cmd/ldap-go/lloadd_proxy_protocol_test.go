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
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	lloaddruntime "github.com/wangle201210/ldap-go/internal/lloadd"
)

const haproxyProxyProtocolCommit = "23cc52d34b89fa1f2ec2c4b3ac1526bae84aff93"

func TestLloaddProxyTrustedSourcesNormalizeAndAuthorize(t *testing.T) {
	trusted, err := parseLloaddProxyTrustedSources([]string{
		"127.0.0.1",
		"127.0.0.1/32",
		"::ffff:127.0.0.0/120",
		"2001:db8::/32",
	})
	if err != nil {
		t.Fatalf("parse trusted sources: %v", err)
	}
	if len(trusted) != 3 {
		t.Fatalf("normalized trusted sources = %#v, want 3 unique prefixes", trusted)
	}
	for _, test := range []struct {
		name    string
		remote  net.Addr
		allowed bool
	}{
		{
			name:    "IPv4",
			remote:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000},
			allowed: true,
		},
		{
			name:    "IPv4 mapped IPv6",
			remote:  &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.2"), Port: 41001},
			allowed: true,
		},
		{
			name:    "IPv6",
			remote:  &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 41002},
			allowed: true,
		},
		{
			name:   "untrusted IPv4",
			remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 41003},
		},
		{
			name:   "untrusted IPv6",
			remote: &net.TCPAddr{IP: net.ParseIP("2001:db9::10"), Port: 41004},
		},
		{
			name:   "non TCP",
			remote: &net.UnixAddr{Name: "/run/untrusted.sock", Net: "unix"},
		},
		{
			name:   "invalid TCP IP",
			remote: &net.TCPAddr{Port: 41005},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := trusted.authorize(test.remote)
			if test.allowed && err != nil {
				t.Fatalf("authorize(%s): %v", test.remote, err)
			}
			if !test.allowed && err == nil {
				t.Fatalf("authorize(%s) succeeded", test.remote)
			}
		})
	}
	if err := (lloaddProxyTrustedSources(nil)).authorize(
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41006},
	); err == nil || !strings.Contains(err.Error(), "no trusted sources") {
		t.Fatalf("authorize without allowlist = %v", err)
	}
}

func TestLloaddProxyTrustedSourcesRejectBeforeReadingHeaderAndRecover(t *testing.T) {
	source, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := source.Addr().(*net.TCPAddr).Port
	untrustedIP := lloaddTestNonLoopbackIPv4(t)
	trusted, err := parseLloaddProxyTrustedSources([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("parse trusted sources: %v", err)
	}
	listener := newProxyProtocolListener(source, 5*time.Second, trusted)
	defer listener.Close()
	accepted := make(chan proxyProtocolAcceptResult, 1)
	go acceptProxyProtocolTestConnection(listener, accepted)

	untrustedDialer := net.Dialer{
		Timeout:   time.Second,
		LocalAddr: &net.TCPAddr{IP: untrustedIP},
	}
	untrustedAddress := net.JoinHostPort(untrustedIP.String(), fmt.Sprint(port))
	untrusted, err := untrustedDialer.Dial("tcp4", untrustedAddress)
	if err != nil {
		t.Fatalf("dial from non-loopback source %s: %v", untrustedIP, err)
	}
	if got := untrusted.LocalAddr().(*net.TCPAddr).IP.String(); got != untrustedIP.String() {
		_ = untrusted.Close()
		t.Fatalf("untrusted physical source = %s", got)
	}
	started := time.Now()
	expectProxyProtocolConnectionClosed(t, untrusted)
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("untrusted peer was not rejected before the 5s PROXY header timeout: %s", elapsed)
	}

	trustedAddress := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	trustedClient, err := net.DialTimeout("tcp4", trustedAddress, time.Second)
	if err != nil {
		t.Fatalf("dial trusted source: %v", err)
	}
	defer trustedClient.Close()
	if _, err := trustedClient.Write([]byte(
		"PROXY TCP4 192.0.2.80 198.51.100.80 48000 389\r\nldap-payload",
	)); err != nil {
		t.Fatalf("write trusted PROXY header: %v", err)
	}
	server := awaitProxyProtocolAccept(t, accepted)
	defer server.Close()
	if server.RemoteAddr().String() != "192.0.2.80:48000" {
		t.Fatalf("trusted logical source = %s", server.RemoteAddr())
	}
	payload := make([]byte, len("ldap-payload"))
	if _, err := io.ReadFull(server, payload); err != nil || string(payload) != "ldap-payload" {
		t.Fatalf("trusted LDAP payload = %q, %v", payload, err)
	}
}

func TestPrepareLloaddProxyConnectionRejectsUntrustedSourceWithoutReading(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	connection := &lloaddReadTrackingConn{
		Conn:   server,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.90"), Port: 49000},
	}
	trusted, err := parseLloaddProxyTrustedSources([]string{"198.51.100.0/24"})
	if err != nil {
		t.Fatalf("parse trusted sources: %v", err)
	}
	if _, err := prepareLloaddAcceptedConnectionWithTrustedSources(
		"pldap://127.0.0.1:389/",
		lloaddruntime.RuntimeConfig{},
		connection,
		trusted,
	); err == nil || !strings.Contains(err.Error(), "untrusted physical source") {
		t.Fatalf("prepare untrusted connection = %v", err)
	}
	if connection.reads != 0 {
		t.Fatalf("prepare read %d times before rejecting the physical source", connection.reads)
	}
}

func TestLloaddProxyProtocolV1AddressesAndMetadata(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		wantSource  string
		wantTarget  string
		wantUnknown bool
	}{
		{
			name:       "TCP4",
			header:     "PROXY TCP4 192.0.2.10 198.51.100.20 42310 389\r\n",
			wantSource: "192.0.2.10:42310",
			wantTarget: "198.51.100.20:389",
		},
		{
			name:       "zero ports",
			header:     "PROXY TCP4 0.0.0.0 255.255.255.255 0 0\r\n",
			wantSource: "0.0.0.0:0",
			wantTarget: "255.255.255.255:0",
		},
		{
			name:       "TCP6",
			header:     "PROXY TCP6 2001:db8::10 2001:db8::20 42311 636\r\n",
			wantSource: "[2001:db8::10]:42311",
			wantTarget: "[2001:db8::20]:636",
		},
		{
			name: "maximum TCP6 fields",
			header: "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff " +
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n",
			wantSource: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
			wantTarget: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
		},
		{
			name:        "UNKNOWN",
			header:      "PROXY UNKNOWN\r\n",
			wantUnknown: true,
		},
		{
			name:        "UNKNOWN ignores fields",
			header:      "PROXY UNKNOWN ignored address fields\r\n",
			wantUnknown: true,
		},
		{
			name:        "maximum UNKNOWN line",
			header:      "PROXY UNKNOWN " + strings.Repeat("A", 91) + "\r\n",
			wantUnknown: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			listener := newProxyProtocolListener(source, time.Second, loopbackProxyTrustedSources(t))
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
			if _, err := client.Write([]byte(test.header + "ldap-payload")); err != nil {
				t.Fatalf("write PROXY v1 header: %v", err)
			}

			server := awaitProxyProtocolAccept(t, accepted)
			defer server.Close()
			wantSource, wantTarget := test.wantSource, test.wantTarget
			if test.wantUnknown {
				wantSource, wantTarget = physicalSource, physicalTarget
			}
			if server.RemoteAddr().String() != wantSource || server.LocalAddr().String() != wantTarget {
				t.Fatalf(
					"logical addresses = %s -> %s, want %s -> %s",
					server.RemoteAddr(), server.LocalAddr(), wantSource, wantTarget,
				)
			}
			metadata, ok := lloaddruntime.MetadataFromConnection(server)
			if !ok || !metadata.ProxyProtocol || metadata.ProxyProtocolLocal != test.wantUnknown {
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
			if len(metadata.TLVs) != 0 {
				t.Fatalf("PROXY v1 exposed TLVs: %#v", metadata.TLVs)
			}
			payload := make([]byte, len("ldap-payload"))
			if _, err := io.ReadFull(server, payload); err != nil || string(payload) != "ldap-payload" {
				t.Fatalf("LDAP payload = %q, %v", payload, err)
			}
		})
	}
}

func TestLloaddProxyProtocolV1RejectsMalformedAndRecovers(t *testing.T) {
	source, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	listener := newProxyProtocolListener(source, 100*time.Millisecond, loopbackProxyTrustedSources(t))
	defer listener.Close()
	accepted := make(chan proxyProtocolAcceptResult, 1)
	go acceptProxyProtocolTestConnection(listener, accepted)

	malformed := []struct {
		name   string
		header []byte
	}{
		{name: "bad signature", header: []byte("proxy TCP4 192.0.2.1 198.51.100.1 40000 389\r\n")},
		{name: "unsupported family", header: []byte("PROXY UDP4 192.0.2.1 198.51.100.1 40000 389\r\n")},
		{name: "missing field", header: []byte("PROXY TCP4 192.0.2.1 198.51.100.1 40000\r\n")},
		{name: "extra field", header: []byte("PROXY TCP4 192.0.2.1 198.51.100.1 40000 389 extra\r\n")},
		{name: "double space", header: []byte("PROXY TCP4 192.0.2.1  198.51.100.1 40000 389\r\n")},
		{name: "tab separator", header: []byte("PROXY\tTCP4 192.0.2.1 198.51.100.1 40000 389\r\n")},
		{name: "non ASCII", header: append([]byte("PROXY TCP4 192.0.2."), append([]byte{0x80}, []byte(" 198.51.100.1 40000 389\r\n")...)...)},
		{name: "UNKNOWN non ASCII", header: append([]byte("PROXY UNKNOWN "), []byte{0x80, '\r', '\n'}...)},
		{name: "IPv4 too few octets", header: []byte("PROXY TCP4 192.0.2 198.51.100.1 40000 389\r\n")},
		{name: "IPv4 leading zero", header: []byte("PROXY TCP4 192.0.02.1 198.51.100.1 40000 389\r\n")},
		{name: "IPv4 overflow", header: []byte("PROXY TCP4 192.0.2.256 198.51.100.1 40000 389\r\n")},
		{name: "TCP4 gets IPv6", header: []byte("PROXY TCP4 2001:db8::1 198.51.100.1 40000 389\r\n")},
		{name: "IPv6 invalid compression", header: []byte("PROXY TCP6 2001::db8::1 2001:db8::2 40000 389\r\n")},
		{name: "IPv6 zone", header: []byte("PROXY TCP6 fe80::1%lo0 2001:db8::2 40000 389\r\n")},
		{name: "IPv6 mixed suffix", header: []byte("PROXY TCP6 ::ffff:192.0.2.1 2001:db8::2 40000 389\r\n")},
		{name: "TCP6 gets IPv4", header: []byte("PROXY TCP6 192.0.2.1 2001:db8::2 40000 389\r\n")},
		{name: "source port leading zero", header: []byte("PROXY TCP4 192.0.2.1 198.51.100.1 04000 389\r\n")},
		{name: "source port signed", header: []byte("PROXY TCP4 192.0.2.1 198.51.100.1 +40000 389\r\n")},
		{name: "destination port overflow", header: []byte("PROXY TCP4 192.0.2.1 198.51.100.1 40000 65536\r\n")},
		{name: "destination port integer overflow", header: []byte("PROXY TCP4 192.0.2.1 198.51.100.1 40000 999999999999999999999999999999999999999999999999999999\r\n")},
		{name: "destination port non decimal", header: []byte("PROXY TCP4 192.0.2.1 198.51.100.1 40000 0x185\r\n")},
		{name: "LF terminator", header: []byte("PROXY UNKNOWN\n")},
		{name: "embedded CR", header: []byte("PROXY UNKNOWN\rX\r\n")},
		{name: "overlong", header: []byte("PROXY UNKNOWN " + strings.Repeat("A", lloaddProxyProtocolV1MaxHeader) + "\r\n")},
	}
	for _, test := range malformed {
		t.Run(test.name, func(t *testing.T) {
			connection, err := net.DialTimeout("tcp", source.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			if _, err := connection.Write(test.header); err != nil {
				_ = connection.Close()
				t.Fatalf("write malformed v1 header: %v", err)
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
	if _, err := timedOut.Write([]byte("PROXY TCP4 192.0.2.1")); err != nil {
		t.Fatalf("write partial v1 header: %v", err)
	}
	expectProxyProtocolConnectionClosed(t, timedOut)

	valid, err := net.DialTimeout("tcp", source.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial recovery case: %v", err)
	}
	defer valid.Close()
	if _, err := valid.Write([]byte("PROXY TCP4 192.0.2.30 198.51.100.30 43000 389\r\n")); err != nil {
		t.Fatalf("write recovery header: %v", err)
	}
	server := awaitProxyProtocolAccept(t, accepted)
	defer server.Close()
	if server.RemoteAddr().String() != "192.0.2.30:43000" {
		t.Fatalf("recovered source address = %s", server.RemoteAddr())
	}
}

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
		{
			name: "LOCAL ignores UNIX DGRAM family and malformed opaque address",
			packet: lloaddProxyProtocolPacket(
				0x20,
				0x32,
				bytes.Repeat([]byte{0x01}, lloaddProxyProtocolUnixAddrBytes),
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
			listener := newProxyProtocolListener(source, time.Second, loopbackProxyTrustedSources(t))
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

func TestLloaddProxyProtocolV2UnixStreamAddressesAndTLVs(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		destination string
	}{
		{
			name:        "filesystem paths",
			source:      "/run/haproxy/client.sock",
			destination: "/run/ldap-go/lloadd.sock",
		},
		{
			name:        "maximum path lengths",
			source:      "/" + strings.Repeat("s", lloaddProxyProtocolUnixPathBytes-2),
			destination: "/" + strings.Repeat("d", lloaddProxyProtocolUnixPathBytes-2),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			listener := newProxyProtocolListener(source, time.Second, loopbackProxyTrustedSources(t))
			defer listener.Close()
			accepted := make(chan proxyProtocolAcceptResult, 1)
			go acceptProxyProtocolTestConnection(listener, accepted)

			client, err := net.DialTimeout("tcp", source.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer client.Close()
			physicalSource := client.LocalAddr().String()
			physicalDestination := client.RemoteAddr().String()
			tlv := lloaddProxyProtocolTLV(0x05, []byte("unix-connection"))
			packet := lloaddProxyProtocolUnixPacket(t, test.source, test.destination, tlv)
			if _, err := client.Write(append(packet, []byte("ldap-payload")...)); err != nil {
				t.Fatalf("write PROXY UNIX stream packet: %v", err)
			}

			server := awaitProxyProtocolAccept(t, accepted)
			defer server.Close()
			if server.RemoteAddr().Network() != "unix" || server.RemoteAddr().String() != test.source ||
				server.LocalAddr().Network() != "unix" || server.LocalAddr().String() != test.destination {
				t.Fatalf("logical UNIX addresses = %s -> %s", server.RemoteAddr(), server.LocalAddr())
			}
			metadata, ok := lloaddruntime.MetadataFromConnection(server)
			if !ok || !metadata.ProxyProtocol || metadata.ProxyProtocolLocal {
				t.Fatalf("connection metadata = %#v, present=%t", metadata, ok)
			}
			if metadata.TransportSourceAddress.Network() != "tcp" ||
				metadata.TransportSourceAddress.String() != physicalSource ||
				metadata.TransportDestinationAddress.Network() != "tcp" ||
				metadata.TransportDestinationAddress.String() != physicalDestination {
				t.Fatalf("transport metadata = %#v", metadata)
			}
			if len(metadata.TLVs) != 1 || metadata.TLVs[0].Type != 0x05 ||
				string(metadata.TLVs[0].Value) != "unix-connection" {
				t.Fatalf("UNIX stream TLVs = %#v", metadata.TLVs)
			}
			snapshotSource, ok := metadata.SourceAddress.(*net.UnixAddr)
			if !ok {
				t.Fatalf("UNIX stream source metadata has type %T", metadata.SourceAddress)
			}
			snapshotSource.Name = "/mutated"
			metadata.TLVs[0].Value[0] = 'X'
			again, _ := lloaddruntime.MetadataFromConnection(server)
			if again.SourceAddress.String() != test.source ||
				string(again.TLVs[0].Value) != "unix-connection" {
				t.Fatalf("UNIX stream metadata was mutated through snapshot: %#v", again)
			}
			payload := make([]byte, len("ldap-payload"))
			if _, err := io.ReadFull(server, payload); err != nil || string(payload) != "ldap-payload" {
				t.Fatalf("LDAP payload = %q, %v", payload, err)
			}
		})
	}
}

func TestLloaddProxyProtocolV2UnixFullAndAbstractPaths(t *testing.T) {
	full := bytes.Repeat([]byte{'x'}, lloaddProxyProtocolUnixPathBytes)
	if got, err := parseLloaddProxyProtocolUnixPath(full); err != nil || got != string(full) {
		t.Fatalf("full UNIX path = %q, %v", got, err)
	}
	abstract := make([]byte, lloaddProxyProtocolUnixPathBytes)
	copy(abstract[1:], "ldap-go-abstract")
	if got, err := parseLloaddProxyProtocolUnixPath(abstract); err != nil || got != "@ldap-go-abstract" {
		t.Fatalf("abstract UNIX path = %q, %v", got, err)
	}
	abstract[len("ldap-go-abstract")+2] = 'x'
	if _, err := parseLloaddProxyProtocolUnixPath(abstract); err == nil {
		t.Fatal("abstract UNIX path accepted data after zero padding")
	}
}

func TestLloaddProxyProtocolV2UnixPathRejectsEveryControlByte(t *testing.T) {
	controls := make([]byte, 0, 0x20)
	for value := byte(1); value < 0x20; value++ {
		controls = append(controls, value)
	}
	controls = append(controls, 0x7f)
	for _, control := range controls {
		t.Run(fmt.Sprintf("0x%02x", control), func(t *testing.T) {
			encoded := lloaddProxyProtocolUnixPath(t, "/run/source.sock")
			encoded[4] = control
			if _, err := parseLloaddProxyProtocolUnixPath(encoded); err == nil {
				t.Fatalf("accepted UNIX path containing control byte 0x%02x", control)
			}
		})
	}
}

func TestLloaddProxyProtocolV2RejectsMalformedAndRecovers(t *testing.T) {
	source, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	listener := newProxyProtocolListener(source, 100*time.Millisecond, loopbackProxyTrustedSources(t))
	defer listener.Close()
	accepted := make(chan proxyProtocolAcceptResult, 1)
	go acceptProxyProtocolTestConnection(listener, accepted)

	validSignature := append([]byte(nil), lloaddProxyProtocolV2Signature...)
	badSignature := append([]byte(nil), validSignature...)
	badSignature[0] = 0
	oversizedOptions := make([]byte, lloaddProxyProtocolMaxOptionBytes+1)
	validUnixAddress := lloaddProxyProtocolUnixAddress(t, "/run/source.sock", "/run/destination.sock")
	validUnixPath := lloaddProxyProtocolUnixPath(t, "/run/source.sock")
	unixSourceControl := append([]byte(nil), validUnixPath...)
	unixSourceControl[4] = '\n'
	unixSourceDEL := append([]byte(nil), validUnixPath...)
	unixSourceDEL[4] = 0x7f
	unixSourceAfterNUL := append([]byte(nil), validUnixPath...)
	unixSourceAfterNUL[len("/run/source.sock")+1] = 'x'
	unixEmptySource := append(make([]byte, lloaddProxyProtocolUnixPathBytes), validUnixPath...)
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
		{name: "TCP4 DGRAM", packet: lloaddProxyProtocolPacket(0x21, 0x12, make([]byte, 12))},
		{name: "TCP6 DGRAM", packet: lloaddProxyProtocolPacket(0x21, 0x22, make([]byte, 36))},
		{name: "UNIX DGRAM", packet: lloaddProxyProtocolPacket(0x21, 0x32, validUnixAddress)},
		{name: "UNIX short address", packet: lloaddProxyProtocolPacket(0x21, 0x31, validUnixAddress[:len(validUnixAddress)-1])},
		{name: "UNIX source control byte", packet: lloaddProxyProtocolPacket(0x21, 0x31, append(unixSourceControl, validUnixPath...))},
		{name: "UNIX source DEL byte", packet: lloaddProxyProtocolPacket(0x21, 0x31, append(unixSourceDEL, validUnixPath...))},
		{name: "UNIX source data after NUL", packet: lloaddProxyProtocolPacket(0x21, 0x31, append(unixSourceAfterNUL, validUnixPath...))},
		{name: "UNIX empty source", packet: lloaddProxyProtocolPacket(0x21, 0x31, unixEmptySource)},
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
			listener := newProxyProtocolListener(source, time.Second, loopbackProxyTrustedSources(t))
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
		"static const uint8_t proxyp_sig[12]",
		"memcmp( pph.sig, proxyp_sig, 12 )",
		"case 0x01: /* PROXY command */",
		"pph_len -= addr_len;",
		"case 0x00: /* LOCAL command */",
		"local connection, ignoring proxy data",
		"/* Clear out any options left in proxy packet */",
		"tcp_read( SLAP_FD2SOCK (sfd), &proxyp_options, pph_len )",
	})
}

func TestOpenLDAPLloaddProxyProtocolUnixLayoutSourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPClientToolsCommit {
		t.Fatalf("OpenLDAP source commit = %q, want %q", got, openLDAPClientToolsCommit)
	}
	path := filepath.Join(source, "servers", "slapd", "proxyp.c")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read OpenLDAP PROXY protocol source: %v", err)
	}
	for _, anchor := range []string{
		"struct {\t/* for AF_UNIX sockets, len = 216 */",
		"uint8_t src_addr[108];",
		"uint8_t dst_addr[108];",
		"case 0x11: /* TCPv4 */",
		"case 0x21: /* TCPv6 */",
		"unsupported protocol %x",
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("OpenLDAP PROXY protocol source lacks %q", anchor)
		}
	}
	if bytes.Contains(data, []byte("case 0x31:")) {
		t.Fatal("pinned OpenLDAP source unexpectedly dispatches PROXY v2 UNIX stream")
	}
}

func TestHAProxyProtocolV2UnixStreamSourceContract(t *testing.T) {
	source := os.Getenv("HAPROXY_SOURCE")
	if source == "" {
		t.Skip("HAPROXY_SOURCE is not set")
	}
	if got := os.Getenv("HAPROXY_COMMIT"); got != haproxyProxyProtocolCommit {
		t.Fatalf("HAProxy source commit = %q, want %q", got, haproxyProxyProtocolCommit)
	}
	data, err := os.ReadFile(filepath.Join(source, "doc", "proxy-protocol.txt"))
	if err != nil {
		t.Fatalf("read HAProxy PROXY protocol specification: %v", err)
	}
	for _, anchor := range []string{
		"0x3 : AF_UNIX",
		"The addresses are exactly 108 bytes each.",
		"0x1 : STREAM",
		"TCP or UNIX_STREAM",
		"0x2 : DGRAM",
		"UDP or UNIX_DGRAM",
		"struct {        /* for AF_UNIX sockets, len = 216 */",
		"uint8_t src_addr[108];",
		"uint8_t dst_addr[108];",
		"bytes are part of the header beyond the address information",
		"Type-Length-Value (TLV",
		"vectors) in the following format",
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("HAProxy PROXY protocol specification lacks %q", anchor)
		}
	}
}

func TestHAProxyProtocolV1FramingSourceContract(t *testing.T) {
	source := os.Getenv("HAPROXY_SOURCE")
	if source == "" {
		t.Skip("HAPROXY_SOURCE is not set")
	}
	if got := os.Getenv("HAPROXY_COMMIT"); got != haproxyProxyProtocolCommit {
		t.Fatalf("HAProxy source commit = %q, want %q", got, haproxyProxyProtocolCommit)
	}
	data, err := os.ReadFile(filepath.Join(source, "doc", "proxy-protocol.txt"))
	if err != nil {
		t.Fatalf("read HAProxy PROXY protocol specification: %v", err)
	}
	for _, anchor := range []string{
		"2.1. Human-readable header format (Version 1)",
		"only \"TCP4\"",
		"and \"TCP6\"",
		"receiver must ignore anything",
		"Heading zeroes are not permitted",
		"the CRLF sequence",
		"first 107 characters",
		"not tolerate a single CR or LF character",
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("HAProxy PROXY protocol specification lacks %q", anchor)
		}
	}
}

func TestLloaddPLDAPSReadsProxyHeaderBeforeTLS(t *testing.T) {
	files := newLloaddTLSFiles(t)
	serverTLS, err := loadLloaddClientTLS(files.certificate, files.key)
	if err != nil {
		t.Fatalf("load listener TLS: %v", err)
	}
	listener, description, err := listenLloaddURL(
		"pldaps://127.0.0.1:0/",
		serverTLS,
		loopbackProxyTrustedSources(t),
	)
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

func TestLloaddPLDAPSReadsProxyV1HeaderBeforeTLS(t *testing.T) {
	files := newLloaddTLSFiles(t)
	serverTLS, err := loadLloaddClientTLS(files.certificate, files.key)
	if err != nil {
		t.Fatalf("load listener TLS: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen PLDAPS: %v", err)
	}
	defer listener.Close()
	trustedSources := loopbackProxyTrustedSources(t)
	accepted := make(chan proxyProtocolAcceptResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			connection, acceptErr = prepareLloaddAcceptedConnectionWithTrustedSources(
				"pldaps://127.0.0.1:0/",
				lloaddruntime.RuntimeConfig{ClientTLS: serverTLS, IOTimeout: time.Second},
				connection,
				trustedSources,
			)
		}
		accepted <- proxyProtocolAcceptResult{connection: connection, err: acceptErr}
	}()

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial PLDAPS: %v", err)
	}
	if _, err := raw.Write([]byte("PROXY TCP6 2001:db8::40 ")); err != nil {
		_ = raw.Close()
		t.Fatalf("write fragmented PROXY v1 prefix: %v", err)
	}
	if _, err := raw.Write([]byte("2001:db8::41 44000 636\r\n")); err != nil {
		_ = raw.Close()
		t.Fatalf("write fragmented PROXY v1 suffix: %v", err)
	}
	secured := tls.Client(raw, lloaddTLSClientConfig(t, files.ca))
	if err := secured.Handshake(); err != nil {
		_ = secured.Close()
		t.Fatalf("TLS after PROXY v1 header: %v", err)
	}
	defer secured.Close()
	server := awaitProxyProtocolAccept(t, accepted)
	defer server.Close()
	metadata, ok := lloaddruntime.MetadataFromConnection(server)
	if !ok || server.RemoteAddr().String() != "[2001:db8::40]:44000" ||
		server.LocalAddr().String() != "[2001:db8::41]:636" ||
		metadata.TransportSourceAddress.String() == metadata.SourceAddress.String() {
		t.Fatalf("PLDAPS v1 metadata = %#v, logical=%s -> %s", metadata, server.RemoteAddr(), server.LocalAddr())
	}
}

func TestLloaddPLDAPSReadsProxyUnixStreamBeforeTLS(t *testing.T) {
	files := newLloaddTLSFiles(t)
	serverTLS, err := loadLloaddClientTLS(files.certificate, files.key)
	if err != nil {
		t.Fatalf("load listener TLS: %v", err)
	}
	listener, _, err := listenLloaddURL(
		"pldaps://127.0.0.1:0/",
		serverTLS,
		loopbackProxyTrustedSources(t),
	)
	if err != nil {
		t.Fatalf("listen PLDAPS: %v", err)
	}
	defer listener.Close()
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

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial PLDAPS: %v", err)
	}
	physicalSource := raw.LocalAddr().String()
	physicalDestination := raw.RemoteAddr().String()
	packet := lloaddProxyProtocolUnixPacket(
		t,
		"/run/haproxy/client.sock",
		"/run/ldap-go/ldaps.sock",
		lloaddProxyProtocolTLV(0x01, []byte("ldap")),
	)
	if _, err := raw.Write(packet); err != nil {
		_ = raw.Close()
		t.Fatalf("write PROXY UNIX stream header: %v", err)
	}
	secured := tls.Client(raw, lloaddTLSClientConfig(t, files.ca))
	if err := secured.Handshake(); err != nil {
		_ = secured.Close()
		t.Fatalf("TLS after PROXY UNIX stream header: %v", err)
	}
	defer secured.Close()

	server := awaitProxyProtocolAccept(t, accepted)
	defer server.Close()
	metadata, ok := lloaddruntime.MetadataFromConnection(server)
	if !ok || server.RemoteAddr().Network() != "unix" ||
		server.RemoteAddr().String() != "/run/haproxy/client.sock" ||
		server.LocalAddr().Network() != "unix" ||
		server.LocalAddr().String() != "/run/ldap-go/ldaps.sock" {
		t.Fatalf("PLDAPS UNIX stream metadata = %#v, logical=%s -> %s", metadata, server.RemoteAddr(), server.LocalAddr())
	}
	if metadata.TransportSourceAddress.String() != physicalSource ||
		metadata.TransportDestinationAddress.String() != physicalDestination ||
		len(metadata.TLVs) != 1 || string(metadata.TLVs[0].Value) != "ldap" {
		t.Fatalf("PLDAPS UNIX stream transport metadata = %#v", metadata)
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
			listener, _, err := listenLloaddURL(
				test.scheme+"://127.0.0.1:0/",
				test.serverTLS,
				loopbackProxyTrustedSources(t),
			)
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
			for _, header := range [][]byte{
				[]byte("PROXY UNKNOWN\r\n"),
				lloaddProxyProtocolPacket(0x20, 0x00, nil),
			} {
				connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatalf("dial %s: %v", test.scheme, err)
				}
				if _, err := connection.Write(header); err != nil {
					_ = connection.Close()
					t.Fatalf("write PROXY header: %v", err)
				}
				expectProxyProtocolConnectionClosed(t, connection)
			}
		})
	}
}

type proxyProtocolAcceptResult struct {
	connection net.Conn
	err        error
}

type lloaddReadTrackingConn struct {
	net.Conn
	remote net.Addr
	reads  int
}

func (connection *lloaddReadTrackingConn) Read(buffer []byte) (int, error) {
	connection.reads++
	return connection.Conn.Read(buffer)
}

func (connection *lloaddReadTrackingConn) RemoteAddr() net.Addr {
	return connection.remote
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

func loopbackProxyTrustedSources(t *testing.T) lloaddProxyTrustedSources {
	t.Helper()
	trusted, err := parseLloaddProxyTrustedSources([]string{"127.0.0.0/8", "::1/128"})
	if err != nil {
		t.Fatalf("parse loopback trusted sources: %v", err)
	}
	return trusted
}

func lloaddTestNonLoopbackIPv4(t *testing.T) net.IP {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("list interface addresses: %v", err)
	}
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		ipv4 := ip.To4()
		if ipv4 == nil || ipv4.IsLoopback() || ipv4.IsUnspecified() || ipv4.IsMulticast() {
			continue
		}
		return append(net.IP(nil), ipv4...)
	}
	t.Skip("host has no non-loopback IPv4 address for the real untrusted-source topology")
	return nil
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

func lloaddProxyProtocolUnixPacket(t *testing.T, source, destination string, tlvs []byte) []byte {
	t.Helper()
	address := lloaddProxyProtocolUnixAddress(t, source, destination)
	return lloaddProxyProtocolPacket(0x21, 0x31, append(address, tlvs...))
}

func lloaddProxyProtocolUnixAddress(t *testing.T, source, destination string) []byte {
	t.Helper()
	address := make([]byte, lloaddProxyProtocolUnixAddrBytes)
	copy(address[:lloaddProxyProtocolUnixPathBytes], lloaddProxyProtocolUnixPath(t, source))
	copy(address[lloaddProxyProtocolUnixPathBytes:], lloaddProxyProtocolUnixPath(t, destination))
	return address
}

func lloaddProxyProtocolUnixPath(t *testing.T, path string) []byte {
	t.Helper()
	if len(path) == 0 || len(path) >= lloaddProxyProtocolUnixPathBytes {
		t.Fatalf("invalid PROXY protocol UNIX test path length %d", len(path))
	}
	encoded := make([]byte, lloaddProxyProtocolUnixPathBytes)
	copy(encoded, path)
	return encoded
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
