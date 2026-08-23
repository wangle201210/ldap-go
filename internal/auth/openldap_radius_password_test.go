package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestLoadOpenLDAPRADIUSConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "radius.conf")
	longSecret := strings.Repeat("x", 300)
	contents := "# comment\n" +
		"acct 127.0.0.1 ignored\n" +
		"auth 127.0.0.1:18120 \"secret with spaces\" 4 5 # primary\n" +
		"radius.example.test $X*#..38947ax-+=\n" +
		"auth 127.0.0.2:18121 " + longSecret + " 1 1 30 127.0.0.1\n" +
		"auth radius-zero.example.test:0 zero-port\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write radius.conf: %v", err)
	}
	servers, err := LoadOpenLDAPRADIUSConfig(path)
	if err != nil {
		t.Fatalf("LoadOpenLDAPRADIUSConfig(): %v", err)
	}
	if len(servers) != 4 {
		t.Fatalf("authentication servers = %d, want 4", len(servers))
	}
	if servers[0].Address != "127.0.0.1:18120" ||
		string(servers[0].Secret) != "secret with spaces" ||
		servers[0].Timeout != 4*time.Second || servers[0].Attempts != 5 {
		t.Fatalf("first RADIUS server = %#v", servers[0])
	}
	if servers[1].Address != "radius.example.test:1812" ||
		string(servers[1].Secret) != "$X*#..38947ax-+=" ||
		servers[1].Timeout != openLDAPRADIUSDefaultTimeout ||
		servers[1].Attempts != openLDAPRADIUSDefaultAttempts {
		t.Fatalf("legacy RADIUS server = %#v", servers[1])
	}
	if servers[2].Address != "127.0.0.2:18121" ||
		string(servers[2].Secret) != longSecret ||
		servers[2].DeadTime != 30*time.Second ||
		!servers[2].BindIP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("extended RADIUS server = %#v", servers[2])
	}
	if servers[3].Address != "radius-zero.example.test:1812" {
		t.Fatalf("zero-port RADIUS server = %#v", servers[3])
	}
}

func TestLoadOpenLDAPRADIUSConfigRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, contents := range []string{
		"auth host\n",
		"auth host secret zero\n",
		"auth host \"unterminated\n",
		"auth host \"bad\\nescape\"\n",
		"auth host \"\"\n",
		"auth [::1]:1812 secret\n",
		"auth host secret",
		"auth host " + strings.Repeat("x", openLDAPRADIUSMaxConfigLineSize) + "\n",
		"acct host secret\n",
	} {
		path := filepath.Join(t.TempDir(), "radius.conf")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write radius.conf: %v", err)
		}
		if _, err := LoadOpenLDAPRADIUSConfig(path); err == nil {
			t.Fatalf("LoadOpenLDAPRADIUSConfig(%q) succeeded", contents)
		}
	}
}

func TestVerifyOpenLDAPRADIUSPasswordTruncatesAt128Bytes(t *testing.T) {
	t.Parallel()

	const sharedSecret = "radius-truncation-secret"
	password := []byte(strings.Repeat("p", openLDAPRADIUSMaxPasswordSize+17))
	seen := make(chan string, 1)
	address, stop := startOpenLDAPRADIUSTestServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			seen <- rfc2865.UserPassword_GetString(packet)
			return radius.CodeAccessAccept
		},
	)
	defer stop()

	ok, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		[]OpenLDAPRADIUSServer{{
			Address: address, Secret: []byte(sharedSecret), Timeout: time.Second, Attempts: 1,
		}},
		[]byte("user"),
		password,
		[]byte("nas"),
	)
	if err != nil || !ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword() = %v, %v", ok, err)
	}
	if got := <-seen; got != string(password[:openLDAPRADIUSMaxPasswordSize]) {
		t.Fatalf("RADIUS password length = %d, want %d", len(got), openLDAPRADIUSMaxPasswordSize)
	}
}

func TestVerifyOpenLDAPRADIUSPassword(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "radius-shared-secret"
		username     = "radius-alice"
		password     = "radius-password"
		nas          = "ldap.example.test"
	)
	requests := make(chan [3]string, 4)
	address, stop := startOpenLDAPRADIUSTestServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			gotUsername := rfc2865.UserName_GetString(packet)
			gotPassword := rfc2865.UserPassword_GetString(packet)
			gotNAS := rfc2865.NASIdentifier_GetString(packet)
			requests <- [3]string{gotUsername, gotPassword, gotNAS}
			if gotUsername == username && gotPassword == password {
				return radius.CodeAccessAccept
			}
			return radius.CodeAccessReject
		},
	)
	defer stop()

	servers := []OpenLDAPRADIUSServer{{
		Address:  address,
		Secret:   []byte(sharedSecret),
		Timeout:  time.Second,
		Attempts: 1,
	}}
	ok, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		servers,
		[]byte(username),
		[]byte(password),
		[]byte(nas),
	)
	if err != nil || !ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword(valid) = %v, %v", ok, err)
	}
	if got := <-requests; got != [3]string{username, password, nas} {
		t.Fatalf("RADIUS request = %q", got)
	}

	ok, err = VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		servers,
		[]byte(username),
		[]byte("wrong"),
		[]byte(nas),
	)
	if err != nil || ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword(wrong) = %v, %v", ok, err)
	}
}

func TestVerifyOpenLDAPRADIUSPasswordFailoverAndValidation(t *testing.T) {
	t.Parallel()

	const sharedSecret = "radius-failover-secret"
	address, stop := startOpenLDAPRADIUSTestServer(
		t,
		[]byte(sharedSecret),
		func(*radius.Packet) radius.Code { return radius.CodeAccessAccept },
	)
	defer stop()

	unused, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate unused RADIUS address: %v", err)
	}
	unusedAddress := unused.LocalAddr().String()
	_ = unused.Close()
	servers := []OpenLDAPRADIUSServer{
		{Address: unusedAddress, Secret: []byte(sharedSecret), Timeout: 10 * time.Millisecond, Attempts: 1},
		{Address: address, Secret: []byte(sharedSecret), Timeout: time.Second, Attempts: 1},
	}
	ok, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		servers,
		[]byte("user"),
		[]byte("password"),
		[]byte("nas"),
	)
	if err != nil || !ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword(failover) = %v, %v", ok, err)
	}
	if _, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		servers[1:],
		[]byte{'u', 0, 'x'},
		[]byte("password"),
		[]byte("nas"),
	); err == nil {
		t.Fatal("VerifyOpenLDAPRADIUSPassword() accepted a NUL username")
	}
	if _, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		servers[1:],
		[]byte("user"),
		[]byte("password"),
		[]byte{'n', 0, 's'},
	); err == nil {
		t.Fatal("VerifyOpenLDAPRADIUSPassword() accepted a NUL NAS-Identifier")
	}
	withoutSecret := append([]OpenLDAPRADIUSServer(nil), servers[1:]...)
	withoutSecret[0].Secret = nil
	if _, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		withoutSecret,
		[]byte("user"),
		[]byte("password"),
		[]byte("nas"),
	); err == nil {
		t.Fatal("VerifyOpenLDAPRADIUSPassword() accepted an empty shared secret")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyOpenLDAPRADIUSPassword(
		canceled,
		servers[:1],
		[]byte("user"),
		[]byte("password"),
		[]byte("nas"),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification error = %v", err)
	}
}

func TestVerifyOpenLDAPRADIUSPasswordDoesNotFailOverAfterValidReject(t *testing.T) {
	t.Parallel()

	secret := []byte("radius-reject-secret")
	rejected := make(chan struct{}, 1)
	firstAddress, stopFirst := startOpenLDAPRADIUSTestServer(
		t,
		secret,
		func(*radius.Packet) radius.Code {
			rejected <- struct{}{}
			return radius.CodeAccessReject
		},
	)
	defer stopFirst()
	accepted := make(chan struct{}, 1)
	secondAddress, stopSecond := startOpenLDAPRADIUSTestServer(
		t,
		secret,
		func(*radius.Packet) radius.Code {
			accepted <- struct{}{}
			return radius.CodeAccessAccept
		},
	)
	defer stopSecond()

	ok, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		[]OpenLDAPRADIUSServer{
			{Address: firstAddress, Secret: secret, Timeout: time.Second, Attempts: 1},
			{Address: secondAddress, Secret: secret, Timeout: time.Second, Attempts: 1},
		},
		[]byte("user"),
		[]byte("password"),
		[]byte("nas"),
	)
	if err != nil || ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword(reject) = %v, %v", ok, err)
	}
	select {
	case <-rejected:
	default:
		t.Fatal("first RADIUS server did not receive the request")
	}
	select {
	case <-accepted:
		t.Fatal("RADIUS request failed over after a valid Access-Reject")
	default:
	}
}

func TestVerifyOpenLDAPRADIUSPasswordReusesRetryPacket(t *testing.T) {
	t.Parallel()

	secret := []byte("raw-radius-secret")
	connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw RADIUS: %v", err)
	}
	defer connection.Close()
	type observation struct {
		first, second []byte
		firstPeer     string
		secondPeer    string
		err           error
	}
	observed := make(chan observation, 1)
	go func() {
		buffer := make([]byte, radius.MaxPacketLength)
		length, firstPeer, err := connection.ReadFrom(buffer)
		if err != nil {
			observed <- observation{err: err}
			return
		}
		first := bytes.Clone(buffer[:length])
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			observed <- observation{first: first, firstPeer: firstPeer.String(), err: err}
			return
		}
		second := bytes.Clone(buffer[:length])
		_, err = connection.WriteTo(rawRADIUSResponse(second, radius.CodeAccessAccept, secret), peer)
		observed <- observation{
			first: first, second: second,
			firstPeer: firstPeer.String(), secondPeer: peer.String(),
			err: err,
		}
	}()

	ok, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		[]OpenLDAPRADIUSServer{{
			Address: connection.LocalAddr().String(), Secret: secret,
			Timeout: 250 * time.Millisecond, Attempts: 2,
		}},
		[]byte("raw-user"),
		[]byte("raw-password"),
		[]byte("raw-nas"),
	)
	if err != nil || !ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword() = %v, %v", ok, err)
	}
	got := <-observed
	if got.err != nil {
		t.Fatalf("raw RADIUS server: %v", got.err)
	}
	if !bytes.Equal(got.first, got.second) {
		t.Fatal("RADIUS retry changed the request wire packet")
	}
	if got.firstPeer != got.secondPeer {
		t.Fatalf("RADIUS retry source changed from %s to %s", got.firstPeer, got.secondPeer)
	}
	attributes, err := parseRawRADIUSRequest(got.first, secret)
	if err != nil {
		t.Fatalf("parse raw RADIUS request: %v", err)
	}
	if string(attributes.username) != "raw-user" ||
		string(attributes.password) != "raw-password" ||
		string(attributes.nasIdentifier) != "raw-nas" {
		t.Fatalf("raw RADIUS attributes = %#v", attributes)
	}
}

func TestVerifyOpenLDAPRADIUSPasswordReencryptsOnFailover(t *testing.T) {
	t.Parallel()

	firstSecret := []byte("first-radius-secret")
	secondSecret := []byte("second-radius-secret")
	first, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen first raw RADIUS: %v", err)
	}
	defer first.Close()
	second, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen second raw RADIUS: %v", err)
	}
	defer second.Close()
	firstWire := make(chan []byte, 1)
	secondWire := make(chan []byte, 1)
	go readRawRADIUSRequest(first, firstSecret, false, firstWire)
	go readRawRADIUSRequest(second, secondSecret, true, secondWire)

	ok, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		[]OpenLDAPRADIUSServer{
			{Address: first.LocalAddr().String(), Secret: firstSecret, Timeout: 20 * time.Millisecond, Attempts: 1},
			{Address: second.LocalAddr().String(), Secret: secondSecret, Timeout: time.Second, Attempts: 1},
		},
		[]byte("failover-user"),
		[]byte("failover-password"),
		[]byte("failover-nas"),
	)
	if err != nil || !ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword() = %v, %v", ok, err)
	}
	firstRequest := <-firstWire
	secondRequest := <-secondWire
	if firstRequest[1] != secondRequest[1] || !bytes.Equal(firstRequest[4:20], secondRequest[4:20]) {
		t.Fatal("RADIUS failover changed identifier or request authenticator")
	}
	firstAttributes, err := parseRawRADIUSRequest(firstRequest, firstSecret)
	if err != nil {
		t.Fatalf("parse first failover request: %v", err)
	}
	secondAttributes, err := parseRawRADIUSRequest(secondRequest, secondSecret)
	if err != nil {
		t.Fatalf("parse second failover request: %v", err)
	}
	if !bytes.Equal(firstAttributes.password, secondAttributes.password) ||
		string(firstAttributes.password) != "failover-password" {
		t.Fatalf("failover plaintext passwords = %q, %q", firstAttributes.password, secondAttributes.password)
	}
	if bytes.Equal(firstAttributes.encryptedPassword, secondAttributes.encryptedPassword) {
		t.Fatal("RADIUS failover reused password ciphertext with a different shared secret")
	}
}

func TestVerifyOpenLDAPRADIUSPasswordAcceptsAuthenticatedDifferentIdentifier(t *testing.T) {
	t.Parallel()

	secret := []byte("different-identifier-secret")
	connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw RADIUS: %v", err)
	}
	defer connection.Close()
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, radius.MaxPacketLength)
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		request := bytes.Clone(buffer[:length])
		identifier := request[1] + 1
		_, err = connection.WriteTo(
			rawRADIUSResponseWithIdentifier(
				request,
				radius.CodeAccessAccept,
				identifier,
				secret,
			),
			peer,
		)
		serverErr <- err
	}()

	ok, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		[]OpenLDAPRADIUSServer{{
			Address: connection.LocalAddr().String(), Secret: secret,
			Timeout: time.Second, Attempts: 1,
		}},
		[]byte("identifier-user"),
		[]byte("identifier-password"),
		[]byte("identifier-nas"),
	)
	if err != nil || !ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword() = %v, %v", ok, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("raw RADIUS server: %v", err)
	}
}

func TestVerifyOpenLDAPRADIUSPasswordRejectsInvalidResponseAuthenticator(t *testing.T) {
	t.Parallel()

	secret := []byte("response-authenticator-secret")
	connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw RADIUS: %v", err)
	}
	defer connection.Close()
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, radius.MaxPacketLength)
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		response := rawRADIUSResponse(
			bytes.Clone(buffer[:length]),
			radius.CodeAccessAccept,
			[]byte("wrong-response-secret"),
		)
		_, err = connection.WriteTo(response, peer)
		serverErr <- err
	}()

	ok, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		[]OpenLDAPRADIUSServer{{
			Address: connection.LocalAddr().String(), Secret: secret,
			Timeout: time.Second, Attempts: 1,
		}},
		[]byte("authenticator-user"),
		[]byte("authenticator-password"),
		[]byte("authenticator-nas"),
	)
	if err == nil || ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword() = %v, %v", ok, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("raw RADIUS server: %v", err)
	}
}

func TestVerifyOpenLDAPRADIUSPasswordMessageAuthenticator(t *testing.T) {
	t.Parallel()

	for _, valid := range []bool{true, false} {
		valid := valid
		name := "valid"
		if !valid {
			name = "invalid"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			secret := []byte("message-authenticator-secret")
			connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen raw RADIUS: %v", err)
			}
			defer connection.Close()
			serverErr := make(chan error, 1)
			go func() {
				buffer := make([]byte, radius.MaxPacketLength)
				length, peer, err := connection.ReadFrom(buffer)
				if err != nil {
					serverErr <- err
					return
				}
				response := rawRADIUSResponseWithMessageAuthenticator(
					bytes.Clone(buffer[:length]),
					radius.CodeAccessAccept,
					secret,
					valid,
				)
				_, err = connection.WriteTo(response, peer)
				serverErr <- err
			}()

			ok, err := VerifyOpenLDAPRADIUSPassword(
				context.Background(),
				[]OpenLDAPRADIUSServer{{
					Address: connection.LocalAddr().String(), Secret: secret,
					Timeout: time.Second, Attempts: 1,
				}},
				[]byte("message-authenticator-user"),
				[]byte("message-authenticator-password"),
				[]byte("message-authenticator-nas"),
			)
			if valid && (err != nil || !ok) {
				t.Fatalf("VerifyOpenLDAPRADIUSPassword(valid) = %v, %v", ok, err)
			}
			if !valid && (err == nil || ok) {
				t.Fatalf("VerifyOpenLDAPRADIUSPassword(invalid) = %v, %v", ok, err)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("raw RADIUS server: %v", err)
			}
		})
	}
}

func TestVerifyOpenLDAPRADIUSPasswordIgnoresAuthenticatedResponseTrailingBytes(t *testing.T) {
	t.Parallel()

	secret := []byte("response-trailing-bytes-secret")
	connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw RADIUS: %v", err)
	}
	defer connection.Close()
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, radius.MaxPacketLength)
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		response := rawRADIUSResponse(
			bytes.Clone(buffer[:length]),
			radius.CodeAccessAccept,
			secret,
		)
		response = append(response, 0xde, 0xad, 0xbe, 0xef)
		_, err = connection.WriteTo(response, peer)
		serverErr <- err
	}()

	ok, err := VerifyOpenLDAPRADIUSPassword(
		context.Background(),
		[]OpenLDAPRADIUSServer{{
			Address: connection.LocalAddr().String(), Secret: secret,
			Timeout: time.Second, Attempts: 1,
		}},
		[]byte("trailing-user"),
		[]byte("trailing-password"),
		[]byte("trailing-nas"),
	)
	if err != nil || !ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword() = %v, %v", ok, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("raw RADIUS server: %v", err)
	}
}

func TestVerifyOpenLDAPRADIUSPasswordReprobesFirstServerAfterDeadTime(t *testing.T) {
	t.Parallel()

	secret := []byte("radius-dead-time-secret")
	first, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen first raw RADIUS server: %v", err)
	}
	defer first.Close()
	second, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen second raw RADIUS server: %v", err)
	}
	defer second.Close()

	events := make(chan string, 3)
	serverErr := make(chan error, 2)
	go func() {
		buffer := make([]byte, radius.MaxPacketLength)
		for attempt := 1; attempt <= 2; attempt++ {
			length, peer, err := first.ReadFrom(buffer)
			if err != nil {
				serverErr <- err
				return
			}
			events <- fmt.Sprintf("first-%d", attempt)
			if attempt == 2 {
				_, err = first.WriteTo(
					rawRADIUSResponse(
						bytes.Clone(buffer[:length]),
						radius.CodeAccessAccept,
						secret,
					),
					peer,
				)
				serverErr <- err
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, radius.MaxPacketLength)
		if _, _, err := second.ReadFrom(buffer); err != nil {
			serverErr <- err
			return
		}
		events <- "second-1"
		serverErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, err := VerifyOpenLDAPRADIUSPassword(
		ctx,
		[]OpenLDAPRADIUSServer{
			{
				Address: first.LocalAddr().String(), Secret: secret,
				Timeout: 30 * time.Millisecond, Attempts: 1, DeadTime: 50 * time.Millisecond,
			},
			{
				Address: second.LocalAddr().String(), Secret: secret,
				Timeout: 120 * time.Millisecond, Attempts: 1, DeadTime: 50 * time.Millisecond,
			},
		},
		[]byte("dead-time-user"),
		[]byte("dead-time-password"),
		[]byte("dead-time-nas"),
	)
	if err != nil || !ok {
		t.Fatalf("VerifyOpenLDAPRADIUSPassword() = %v, %v", ok, err)
	}
	for _, want := range []string{"first-1", "second-1", "first-2"} {
		if got := <-events; got != want {
			t.Fatalf("RADIUS request order = %q, want %q", got, want)
		}
	}
	for range 2 {
		if err := <-serverErr; err != nil {
			t.Fatalf("raw RADIUS server: %v", err)
		}
	}
}

type rawRADIUSAttributes struct {
	username          []byte
	password          []byte
	encryptedPassword []byte
	nasIdentifier     []byte
}

func readRawRADIUSRequest(
	connection net.PacketConn,
	secret []byte,
	respond bool,
	requests chan<- []byte,
) {
	buffer := make([]byte, radius.MaxPacketLength)
	length, peer, err := connection.ReadFrom(buffer)
	if err != nil {
		requests <- nil
		return
	}
	wire := bytes.Clone(buffer[:length])
	requests <- wire
	if respond {
		_, _ = connection.WriteTo(rawRADIUSResponse(wire, radius.CodeAccessAccept, secret), peer)
	}
}

func parseRawRADIUSRequest(wire, secret []byte) (rawRADIUSAttributes, error) {
	var result rawRADIUSAttributes
	if len(wire) < 20 || wire[0] != byte(radius.CodeAccessRequest) ||
		int(binary.BigEndian.Uint16(wire[2:4])) != len(wire) {
		return result, errors.New("invalid RADIUS Access-Request header")
	}
	for attributes := wire[20:]; len(attributes) > 0; {
		if len(attributes) < 2 || int(attributes[1]) < 2 || int(attributes[1]) > len(attributes) {
			return result, errors.New("invalid RADIUS attribute length")
		}
		value := bytes.Clone(attributes[2:attributes[1]])
		switch radius.Type(attributes[0]) {
		case rfc2865.UserName_Type:
			result.username = value
		case rfc2865.UserPassword_Type:
			result.encryptedPassword = value
			result.password = decryptRawRADIUSPassword(value, secret, wire[4:20])
		case rfc2865.NASIdentifier_Type:
			result.nasIdentifier = value
		}
		attributes = attributes[attributes[1]:]
	}
	return result, nil
}

func decryptRawRADIUSPassword(ciphertext, secret, authenticator []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	previous := authenticator
	for offset := 0; offset < len(ciphertext); offset += md5.Size {
		digest := md5.New()
		_, _ = digest.Write(secret)
		_, _ = digest.Write(previous)
		mask := digest.Sum(nil)
		for index := 0; index < md5.Size; index++ {
			plaintext[offset+index] = ciphertext[offset+index] ^ mask[index]
		}
		previous = ciphertext[offset : offset+md5.Size]
	}
	return bytes.TrimRight(plaintext, "\x00")
}

func rawRADIUSResponse(request []byte, code radius.Code, secret []byte) []byte {
	return rawRADIUSResponseWithIdentifier(request, code, request[1], secret)
}

func rawRADIUSResponseWithIdentifier(
	request []byte,
	code radius.Code,
	identifier byte,
	secret []byte,
) []byte {
	response := make([]byte, 20)
	response[0] = byte(code)
	response[1] = identifier
	binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
	digest := md5.New()
	_, _ = digest.Write(response[:4])
	_, _ = digest.Write(request[4:20])
	_, _ = digest.Write(secret)
	copy(response[4:20], digest.Sum(nil))
	return response
}

func rawRADIUSResponseWithMessageAuthenticator(
	request []byte,
	code radius.Code,
	secret []byte,
	valid bool,
) []byte {
	response := make([]byte, 20+2+md5.Size)
	response[0] = byte(code)
	response[1] = request[1]
	binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
	copy(response[4:20], request[4:20])
	response[20] = 80
	response[21] = md5.Size + 2
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(response)
	copy(response[22:], mac.Sum(nil))
	if !valid {
		response[22] ^= 0xff
	}
	digest := md5.New()
	_, _ = digest.Write(response[:4])
	_, _ = digest.Write(request[4:20])
	_, _ = digest.Write(response[20:])
	_, _ = digest.Write(secret)
	copy(response[4:20], digest.Sum(nil))
	return response
}

func startOpenLDAPRADIUSTestServer(
	t *testing.T,
	secret []byte,
	response func(*radius.Packet) radius.Code,
) (string, func()) {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen RADIUS: %v", err)
	}
	server := &radius.PacketServer{
		SecretSource: radius.StaticSecretSource(secret),
		Handler: radius.HandlerFunc(func(
			writer radius.ResponseWriter,
			request *radius.Request,
		) {
			if err := writer.Write(request.Response(response(request.Packet))); err != nil {
				t.Errorf("write RADIUS response: %v", err)
			}
		}),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(connection) }()
	return connection.LocalAddr().String(), func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			t.Errorf("shutdown RADIUS server: %v", err)
		}
		if err := <-done; !errors.Is(err, radius.ErrServerShutdown) {
			t.Errorf("RADIUS Serve() error = %v", err)
		}
	}
}

func TestOpenLDAPRADIUSSchemeIsVerifyOnly(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizePasswordHashScheme(strings.ToLower(OpenLDAPRADIUSHashScheme))
	if err != nil || normalized != OpenLDAPRADIUSHashScheme {
		t.Fatalf(
			"NormalizePasswordHashScheme(%s) = %q, %v",
			OpenLDAPRADIUSHashScheme,
			normalized,
			err,
		)
	}
	for _, password := range [][]byte{nil, []byte("password")} {
		if _, err := HashPassword(
			password,
			OpenLDAPRADIUSHashScheme,
			nil,
		); !errors.Is(err, ErrPasswordHashUnavailable) {
			t.Fatalf("HashPassword(%s) error = %v", OpenLDAPRADIUSHashScheme, err)
		}
	}
}
