package auth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	OpenLDAPRADIUSHashScheme        = "{RADIUS}"
	openLDAPRADIUSDefaultPort       = "1812"
	openLDAPRADIUSDefaultTimeout    = 3 * time.Second
	openLDAPRADIUSDefaultAttempts   = 3
	openLDAPRADIUSMaxServers        = 10
	openLDAPRADIUSMaxConfigLineSize = 1023
	openLDAPRADIUSMaxPasswordSize   = 128
)

type OpenLDAPRADIUSServer struct {
	Address  string
	Secret   []byte
	Timeout  time.Duration
	Attempts int
	DeadTime time.Duration
	BindIP   net.IP
}

type openLDAPRADIUSServerState struct {
	numTries  int
	isDead    bool
	nextProbe time.Time
}

type openLDAPRADIUSExchangeSession struct {
	connections map[string]*net.UDPConn
	remotes     map[string]*net.UDPAddr
}

// LoadOpenLDAPRADIUSConfig parses the radius.conf format consumed by the
// libradius-backed OpenLDAP module.
func LoadOpenLDAPRADIUSConfig(
	path string,
) (servers []OpenLDAPRADIUSServer, returnErr error) {
	defer func() {
		if returnErr == nil {
			return
		}
		for index := range servers {
			clear(servers[index].Secret)
		}
		servers = nil
	}()
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read RADIUS configuration: %w", err)
	}
	defer file.Close()

	lineNumber := 0
	reader := bufio.NewReaderSize(file, openLDAPRADIUSMaxConfigLineSize+1)
	for {
		lineNumber++
		line, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, io.EOF) && len(line) == 0 {
			break
		}
		if errors.Is(readErr, bufio.ErrBufferFull) || len(line) > openLDAPRADIUSMaxConfigLineSize {
			clear(line)
			return nil, fmt.Errorf("RADIUS configuration line %d: line too long", lineNumber)
		}
		if errors.Is(readErr, io.EOF) {
			clear(line)
			return nil, fmt.Errorf("RADIUS configuration line %d: missing newline", lineNumber)
		}
		if readErr != nil {
			clear(line)
			return nil, fmt.Errorf("read RADIUS configuration line %d: %w", lineNumber, readErr)
		}
		err := appendOpenLDAPRADIUSConfigLine(&servers, line[:len(line)-1])
		clear(line)
		if err != nil {
			return nil, fmt.Errorf("RADIUS configuration line %d: %w", lineNumber, err)
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("RADIUS configuration has no authentication servers")
	}
	return servers, nil
}

func appendOpenLDAPRADIUSConfigLine(
	servers *[]OpenLDAPRADIUSServer,
	line []byte,
) error {
	fields, err := parseOpenLDAPRADIUSConfigFields(line)
	if err != nil {
		return err
	}
	allFields := fields
	defer func() {
		for _, field := range allFields {
			clear(field)
		}
	}()
	if len(fields) == 0 {
		return nil
	}

	service := []byte("auth")
	if bytes.Equal(fields[0], []byte("auth")) || bytes.Equal(fields[0], []byte("acct")) {
		service = fields[0]
		fields = fields[1:]
	}
	if len(fields) < 2 || len(fields) > 6 {
		return errors.New("expected server, secret, timeout, attempts, dead-time, and bind-address")
	}
	if bytes.Equal(service, []byte("acct")) {
		return nil
	}
	if len(*servers) == openLDAPRADIUSMaxServers {
		return fmt.Errorf("more than %d authentication servers", openLDAPRADIUSMaxServers)
	}

	address, err := normalizeOpenLDAPRADIUSAddress(string(fields[0]))
	if err != nil {
		return err
	}
	if len(fields[1]) == 0 {
		return errors.New("shared secret must not be empty")
	}
	timeout := openLDAPRADIUSDefaultTimeout
	if len(fields) >= 3 {
		seconds, err := parseOpenLDAPRADIUSUnsignedInteger(string(fields[2]), "timeout")
		if err != nil {
			return err
		}
		timeout = time.Duration(seconds) * time.Second
	}
	attempts := openLDAPRADIUSDefaultAttempts
	if len(fields) >= 4 {
		attempts, err = parseOpenLDAPRADIUSUnsignedInteger(string(fields[3]), "attempts")
		if err != nil {
			return err
		}
	}
	deadTime := time.Duration(0)
	if len(fields) >= 5 {
		seconds, err := parseOpenLDAPRADIUSUnsignedInteger(string(fields[4]), "dead-time")
		if err != nil {
			return err
		}
		deadTime = time.Duration(seconds) * time.Second
	}
	var bindIP net.IP
	if len(fields) == 6 {
		bindAddress := string(fields[5])
		bindIP = net.ParseIP(bindAddress)
		if bindIP == nil || bindIP.To4() == nil || bindAddress == "255.255.255.255" {
			return fmt.Errorf("invalid RADIUS bind-address %q", bindAddress)
		}
		bindIP = bytes.Clone(bindIP.To4())
	}
	*servers = append(*servers, OpenLDAPRADIUSServer{
		Address:  address,
		Secret:   bytes.Clone(fields[1]),
		Timeout:  timeout,
		Attempts: attempts,
		DeadTime: deadTime,
		BindIP:   bindIP,
	})
	return nil
}

func VerifyOpenLDAPRADIUSPassword(
	ctx context.Context,
	servers []OpenLDAPRADIUSServer,
	username, password, nasIdentifier []byte,
) (bool, error) {
	if ctx == nil {
		return false, errors.New("RADIUS verification context is required")
	}
	if len(servers) == 0 {
		return false, errors.New("RADIUS authentication server is required")
	}
	if bytes.IndexByte(username, 0) >= 0 || bytes.IndexByte(password, 0) >= 0 ||
		bytes.IndexByte(nasIdentifier, 0) >= 0 {
		return false, errors.New("RADIUS attributes must not contain NUL")
	}
	if len(username) > 253 || len(nasIdentifier) > 253 {
		return false, errors.New("RADIUS credential attribute exceeds protocol limit")
	}
	if len(password) > openLDAPRADIUSMaxPasswordSize {
		password = password[:openLDAPRADIUSMaxPasswordSize]
	}

	states := make([]openLDAPRADIUSServerState, len(servers))
	for _, server := range servers {
		if len(server.Secret) == 0 {
			return false, errors.New("RADIUS shared secret is required")
		}
		if server.Timeout < 0 || server.Attempts < 0 || server.DeadTime < 0 {
			return false, errors.New("invalid RADIUS server timeout, attempt count, or dead-time")
		}
	}

	var lastErr error
	base := radius.New(radius.CodeAccessRequest, nil)
	session := openLDAPRADIUSExchangeSession{
		connections: make(map[string]*net.UDPConn),
		remotes:     make(map[string]*net.UDPAddr),
	}
	defer session.close()
	serverIndex := 0
	for {
		selected, ok := selectOpenLDAPRADIUSServer(
			servers,
			states,
			serverIndex,
			time.Now(),
		)
		if !ok {
			break
		}
		serverIndex = selected
		server := servers[serverIndex]
		packet := &radius.Packet{
			Code:          radius.CodeAccessRequest,
			Identifier:    base.Identifier,
			Authenticator: base.Authenticator,
			Secret:        server.Secret,
		}
		if err := rfc2865.UserName_Set(packet, username); err != nil {
			return false, fmt.Errorf("set RADIUS User-Name: %w", err)
		}
		if err := rfc2865.UserPassword_Set(packet, password); err != nil {
			return false, fmt.Errorf("set RADIUS User-Password: %w", err)
		}
		if err := rfc2865.NASIdentifier_Set(packet, nasIdentifier); err != nil {
			return false, fmt.Errorf("set RADIUS NAS-Identifier: %w", err)
		}
		response, err := session.exchange(ctx, server, packet)
		states[serverIndex].numTries++
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			continue
		}
		if response.Code == radius.CodeAccessAccept {
			return true, nil
		}
		return false, nil
	}
	if lastErr == nil {
		lastErr = errors.New("RADIUS authentication failed without a response")
	}
	return false, lastErr
}

func selectOpenLDAPRADIUSServer(
	servers []OpenLDAPRADIUSServer,
	states []openLDAPRADIUSServerState,
	current int,
	now time.Time,
) (int, bool) {
	state := &states[current]
	if !state.isDead && state.numTries < servers[current].Attempts {
		return current, true
	}
	if !state.isDead {
		state.isDead = true
		if servers[current].DeadTime > 0 {
			state.nextProbe = now.Add(servers[current].DeadTime)
		}
	}

	for offset := 1; offset <= len(servers); offset++ {
		candidate := (current + offset) % len(servers)
		candidateState := &states[candidate]
		if !candidateState.isDead {
			return candidate, true
		}
		if servers[candidate].DeadTime > 0 &&
			!candidateState.nextProbe.After(now) {
			candidateState.isDead = false
			candidateState.numTries = 0
			return candidate, true
		}
	}
	return 0, false
}

func (session *openLDAPRADIUSExchangeSession) exchange(
	ctx context.Context,
	server OpenLDAPRADIUSServer,
	packet *radius.Packet,
) (*radius.Packet, error) {
	connection, remote, err := session.connection(server)
	if err != nil {
		return nil, err
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
	})
	defer stopCancellation()
	wire, err := packet.Encode()
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, radius.MaxPacketLength)
	deadline := time.Now().Add(server.Timeout)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := connection.WriteToUDP(wire, remote); err != nil {
		return nil, err
	}
	length, peer, err := connection.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}
	if !peer.IP.Equal(remote.IP) || peer.Port != remote.Port {
		return nil, errors.New("RADIUS response source address is invalid")
	}
	response, err := radius.Parse(buffer[:length], packet.Secret)
	if err != nil {
		return nil, err
	}
	declaredLength := int(binary.BigEndian.Uint16(buffer[2:4]))
	responseWire := buffer[:declaredLength]
	if !radius.IsAuthenticResponse(responseWire, wire, packet.Secret) {
		return nil, errors.New("RADIUS response authenticator is invalid")
	}
	if !validOpenLDAPRADIUSMessageAuthenticator(
		buffer[:length],
		wire,
		packet.Secret,
	) {
		return nil, errors.New("RADIUS message authenticator is invalid")
	}
	// The libradius response check authenticates the declared response and
	// its source address, but does not separately compare the Identifier.
	return response, nil
}

func (session *openLDAPRADIUSExchangeSession) connection(
	server OpenLDAPRADIUSServer,
) (*net.UDPConn, *net.UDPAddr, error) {
	remote := session.remotes[server.Address]
	if remote == nil {
		resolved, err := net.ResolveUDPAddr("udp4", server.Address)
		if err != nil {
			return nil, nil, err
		}
		remote = resolved
		session.remotes[server.Address] = remote
	}
	bindKey := "0.0.0.0"
	local := &net.UDPAddr{IP: net.IPv4zero}
	if len(server.BindIP) > 0 {
		bindKey = server.BindIP.String()
		local.IP = server.BindIP
	}
	connection := session.connections[bindKey]
	if connection == nil {
		var err error
		connection, err = net.ListenUDP("udp4", local)
		if err != nil {
			return nil, nil, err
		}
		session.connections[bindKey] = connection
	}
	return connection, remote, nil
}

func (session *openLDAPRADIUSExchangeSession) close() {
	for key, connection := range session.connections {
		_ = connection.Close()
		delete(session.connections, key)
	}
}

func validOpenLDAPRADIUSMessageAuthenticator(
	response, request, secret []byte,
) bool {
	if len(response) < 20 || len(request) < 20 {
		return false
	}
	declaredLength := int(binary.BigEndian.Uint16(response[2:4]))
	if declaredLength < 20 || declaredLength > len(response) {
		return false
	}
	for offset := 20; offset+2 <= declaredLength; {
		attributeLength := int(response[offset+1])
		if attributeLength < 2 || offset+attributeLength > declaredLength {
			return false
		}
		if response[offset] == 80 {
			if attributeLength != md5.Size+2 {
				return false
			}
			candidate := bytes.Clone(response)
			copy(candidate[4:20], request[4:20])
			clear(candidate[offset+2 : offset+attributeLength])
			mac := hmac.New(md5.New, secret)
			_, _ = mac.Write(candidate)
			return hmac.Equal(
				mac.Sum(nil),
				response[offset+2:offset+attributeLength],
			)
		}
		offset += attributeLength
	}
	return true
}

func parseOpenLDAPRADIUSConfigFields(line []byte) ([][]byte, error) {
	var fields [][]byte
	fail := func(field []byte, message string) ([][]byte, error) {
		clear(field)
		for _, value := range fields {
			clear(value)
		}
		return nil, errors.New(message)
	}
	for offset := 0; ; {
		for offset < len(line) && (line[offset] == ' ' || line[offset] == '\t') {
			offset++
		}
		if offset == len(line) || line[offset] == '#' {
			return fields, nil
		}
		if line[offset] != '"' {
			start := offset
			for offset < len(line) && line[offset] != ' ' && line[offset] != '\t' {
				offset++
			}
			fields = append(fields, line[start:offset])
			continue
		}

		offset++
		var field []byte
		closed := false
		for offset < len(line) {
			switch line[offset] {
			case '"':
				offset++
				closed = true
			case '\\':
				if offset+1 >= len(line) ||
					(line[offset+1] != '\\' && line[offset+1] != '"') {
					return fail(field, "quoted field has an unsupported escape")
				}
				field = append(field, line[offset+1])
				offset += 2
			default:
				field = append(field, line[offset])
				offset++
			}
			if closed {
				break
			}
		}
		if !closed {
			return fail(field, "unterminated quoted field")
		}
		if len(field) == 0 {
			return fail(field, "empty quoted field is not permitted")
		}
		if offset < len(line) && line[offset] != ' ' && line[offset] != '\t' {
			return fail(field, "quoted field must be followed by whitespace")
		}
		fields = append(fields, field)
	}
}

func normalizeOpenLDAPRADIUSAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("RADIUS server address must not be empty")
	}
	if strings.Count(value, ":") == 1 {
		host, port, _ := strings.Cut(value, ":")
		if host == "" {
			return "", errors.New("RADIUS server host must not be empty")
		}
		if err := validateOpenLDAPRADIUSPort(port); err != nil {
			return "", err
		}
		if port == "0" {
			port = openLDAPRADIUSServicePort()
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("invalid RADIUS server address %q", value)
	}
	return net.JoinHostPort(value, openLDAPRADIUSServicePort()), nil
}

func openLDAPRADIUSServicePort() string {
	port, err := net.LookupPort("udp", "radius")
	if err == nil && port > 0 && port <= 65535 {
		return strconv.Itoa(port)
	}
	return openLDAPRADIUSDefaultPort
}

func validateOpenLDAPRADIUSPort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("invalid RADIUS server port %q", value)
	}
	return nil
}

func parseOpenLDAPRADIUSUnsignedInteger(value, name string) (int, error) {
	parsed, err := strconv.ParseUint(value, 10, 31)
	if err != nil {
		return 0, fmt.Errorf("RADIUS %s must be an unsigned integer", name)
	}
	return int(parsed), nil
}
