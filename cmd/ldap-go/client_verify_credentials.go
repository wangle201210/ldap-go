package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/lloadd"
)

const (
	ldapVerifyCredentialsOID = "1.3.6.1.4.1.4203.666.6.5"
	ldapVCAuthzIDRequestOID  = "2.16.840.1.113730.3.4.16"
	ldapVCAuthzIDOID         = "2.16.840.1.113730.3.4.15"
	maxLDAPVCControls        = 64
	maxLDAPVCBERDepth        = 8
	maxLDAPVCBERElements     = 1024
)

// Reference: OpenLDAP 2.6.13 d172686d3d270bc961b78f3ff00d7019c8dfb094,
// clients/tools/ldapvc.c, libraries/libldap/vc.c, doc/man/man1/ldapvc.1.
// Its interactive VC SASL API is disabled and is only a stub. Connection SASL
// remains independent of the simple authentication inside this operation.
const ldapVCUsage = `usage: ldap-go ldapvc [options] [DN [cred]]
Verify credentials without changing the connection's authorization identity.
DN omitted verifies anonymous credentials; cred omitted prompts for the user's password.
-D/-w/-W/-y and -Y/-U/-X/-R/-O authenticate the connection, not the verified user.

Requires the vc module on OpenLDAP or ldap-go (olcModuleLoad: vc.la).
The ldap-go server disables this extension until the module is configured.
VC-specific -E sasl/mech/realm/authcid/authzid/secprops and cookie/SASL continuation
are unsupported, as the pinned OpenLDAP interactive VC API is not implemented.
Verification failures return nonzero, including an inner failure with outer success.
Dry runs validate locally without connecting or prompting.

Options:
`

func runLDAPVC(args []string, stdin io.Reader, stdout, stderr io.Writer) (runErr error) {
	flags := flag.NewFlagSet("ldapvc", flag.ContinueOnError)
	// flag's default error includes rejected argument values, which may be secrets.
	flags.SetOutput(io.Discard)
	var client ldapClientOptions
	client.register(flags)
	defer client.clear()
	for _, name := range []string{"v", "V"} {
		client.unsupportedFlags = withoutLDAPClientUnsupportedFlag(client.unsupportedFlags, name)
	}
	flags.Lookup("v").Usage = "print the outer LDAP result even on success"
	flags.Lookup("V").Usage = "print version information (-VV prints version and exits)"
	versionOnly := flags.Bool("VV", false, "print version information and exit")
	authzID := flags.Bool("a", false, "request the verified user's authorization identity")
	policy := flags.Bool("b", false, "request the verified user's password policy information")
	var extensions repeatedStringFlag
	flags.Var(&extensions, "E", "VC SASL parameters (unsupported by the pinned OpenLDAP implementation)")
	flags.Usage = func() {
		fmt.Fprint(stderr, ldapVCUsage)
		flags.SetOutput(stderr)
		flags.PrintDefaults()
		flags.SetOutput(io.Discard)
	}
	normalized, err := normalizeLDAPVCArgs(flags, args)
	if err != nil {
		return err
	}
	if err := client.parse(flags, normalized); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errors.New("invalid ldapvc options; use -help for usage")
	}
	verbose, _ := ldapBooleanFlagValue(flags, "v")
	showVersion, _ := ldapBooleanFlagValue(flags, "V")
	for _, name := range []string{"a", "b", "v", "V", "VV"} {
		value, _ := ldapBooleanFlagValue(flags, name)
		if flagWasSet(flags, name) && !value {
			return fmt.Errorf("-%s=false is not supported", name)
		}
	}
	if showVersion || *versionOnly {
		if _, err := fmt.Fprintln(stderr, "ldap-go ldapvc", version); err != nil {
			return err
		}
		if *versionOnly {
			return nil
		}
	}
	if len(extensions) != 0 {
		return errors.New("ldapvc -E: VC SASL parameters are unsupported; the OpenLDAP 2.6.13 interactive VC API is not implemented")
	}
	if flags.NArg() > 2 {
		return errors.New("ldapvc accepts at most DN and credentials")
	}
	dn := flags.Arg(0)
	if len(dn) > maxLDAPExtendedValueSize || !utf8.ValidString(dn) || strings.ContainsRune(dn, 0) {
		return errors.New("invalid or oversized verification DN")
	}
	if _, err := ldap.ParseDN(dn); err != nil {
		return errors.New("invalid verification DN")
	}
	var credential []byte
	if flags.NArg() == 2 {
		if len(flags.Arg(1)) > maxPasswordInputSize || strings.ContainsRune(flags.Arg(1), 0) {
			return errors.New("invalid or oversized verification credentials")
		}
		credential = []byte(flags.Arg(1))
	}
	defer func() {
		runErr = redactLDAPVCError(runErr, credential)
		clear(credential)
	}()
	if err := client.validateWrite(flags); err != nil {
		return err
	}
	if client.chaseReferrals {
		return errors.New("ldapvc does not support referral chasing")
	}
	if len(client.generalControls) > maxLDAPVCControls {
		return errors.New("too many ldapvc controls")
	}
	var innerControls []ldap.Control
	if *authzID {
		innerControls = append(innerControls, &ldapRawControl{oid: ldapVCAuthzIDRequestOID})
	}
	if *policy {
		innerControls = append(innerControls, &ldapRawControl{oid: ldap.ControlTypeBeheraPasswordPolicy})
	}
	if !client.dryRun && flags.NArg() == 1 {
		if _, err := io.WriteString(stderr, "User's password: "); err != nil {
			return err
		}
		credential, err = readLDAPPromptPassword(stdin, stderr)
		if err != nil {
			return err
		}
	}
	value, err := encodeLDAPVCRequest(dn, credential, innerControls)
	if err != nil {
		return err
	}
	defer clear(value)
	controls, err := ldapRawControlsToWire(client.generalControls)
	if err != nil {
		return err
	}
	// Reserve BER headers and the largest LDAP message ID before encoding controls.
	remaining := int(ldapwire.DefaultMaxMessageSize) - len(value) - len(ldapVerifyCredentialsOID) - 64
	for _, control := range controls {
		size := len(control.OID) + len(control.Value) + 32
		if size > remaining {
			return errors.New("ldapvc request exceeds the LDAP message size limit")
		}
		remaining -= size
	}
	if client.dryRun {
		if verbose {
			_, err = io.WriteString(stdout, "Result: Success (0)\n")
		}
		return err
	}
	connection, err := connectLDAPVC(&client, flags, stdin, stderr)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(ldapClientDeadline(client.timeout)); err != nil {
		return err
	}
	messageID := takeLDAPClientMessageID(&connection.nextMessageID)
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID, Request: ldapwire.ExtendedRequest{Name: ldapVerifyCredentialsOID, Value: value, HasValue: true},
		Controls: controls,
	})
	if err != nil {
		return err
	}
	defer clear(request)
	if err := ldapwire.Write(connection, request); err != nil {
		return fmt.Errorf("write Verify Credentials request: %w", err)
	}
	frame, err := lloadd.ReadFrame(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		return fmt.Errorf("read Verify Credentials response: %w", err)
	}
	defer clear(frame.Raw)
	result, err := decodeLDAPVCResponse(frame.Raw, messageID, ldap.ApplicationExtendedResponse)
	if err != nil {
		return err
	}
	if result.hasValue && (result.code == ldap.LDAPResultSaslBindInProgress || result.hasCookie || result.hasSASL) {
		return errors.New("unexpected VC cookie or SASL continuation for simple verification")
	}
	var output bytes.Buffer
	if err := writeLDAPVCResult(client.ldifWriter(&output), result, verbose); err != nil {
		return err
	}
	if _, err := io.WriteString(stdout, ldapVCRedact(output.String(), credential)); err != nil {
		return err
	}
	if result.outerCode != 0 || result.code != 0 {
		return &ldapClientExitError{code: 1}
	}
	return nil
}

// Split native getopt short clusters and attached values without interpreting
// password operands or the arguments after --. Retain the shared long options.
func normalizeLDAPVCArgs(flags *flag.FlagSet, args []string) ([]string, error) {
	if len(args) > maxLDAPVCBERElements {
		return nil, errors.New("too many ldapvc arguments")
	}
	var normalized []string
	versions := 0
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || arg == "-" || !strings.HasPrefix(arg, "-") {
			return append(normalized, args[i:]...), nil
		}
		name, _, assigned := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if option := flags.Lookup(name); option != nil || arg == "-help" || arg == "--help" {
			if name == "V" && !assigned {
				versions++
				if versions > 1 {
					arg = "-VV"
				}
			}
			normalized = append(normalized, arg)
			if option != nil && !assigned {
				if boolean, ok := option.Value.(interface{ IsBoolFlag() bool }); !ok || !boolean.IsBoolFlag() {
					if i+1 < len(args) {
						i++
						normalized = append(normalized, args[i])
					}
				}
			}
			continue
		}
		if strings.HasPrefix(arg, "--") {
			return nil, errors.New("unknown ldapvc option; use -help for usage")
		}
		for j := 1; j < len(arg); j++ {
			name := arg[j : j+1]
			option := flags.Lookup(name)
			if option == nil {
				return nil, errors.New("unknown ldapvc option; use -help for usage")
			}
			if name == "V" {
				versions++
				if versions > 1 {
					name = "VV"
				}
			}
			normalized = append(normalized, "-"+name)
			if boolean, ok := option.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
				continue
			}
			if j+1 < len(arg) {
				normalized = append(normalized, arg[j+1:])
			} else if i+1 < len(args) {
				i++
				normalized = append(normalized, args[i])
			}
			break
		}
	}
	return normalized, nil
}

func encodeLDAPVCRequest(dn string, credential []byte, controls []ldap.Control) ([]byte, error) {
	if len(dn) > maxLDAPExtendedValueSize || len(credential) > maxPasswordInputSize {
		return nil, errors.New("Verify Credentials input exceeds the size limit")
	}
	value := ber.NewSequence("Verify Credentials")
	defer clearBERPacket(value)
	value.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "DN"))
	password := ber.Encode(ber.ClassContext, ber.TypePrimitive, 0, nil, "simple")
	password.Data.Write(credential)
	value.AppendChild(password)
	if len(controls) != 0 {
		wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 2, nil, "controls")
		for _, control := range controls {
			wrapper.AppendChild(control.Encode())
		}
		value.AppendChild(wrapper)
	}
	if value.Data.Len()+1+ldapBERLengthSize(value.Data.Len()) > maxLDAPExtendedValueSize {
		return nil, errors.New("Verify Credentials value exceeds the size limit")
	}
	return value.Bytes(), nil
}

func connectLDAPVC(client *ldapClientOptions, flags *flag.FlagSet, stdin io.Reader, stderr io.Writer) (*ldapRawCompareConnection, error) {
	endpoints, err := client.connectionConfigurations(flags)
	if err != nil {
		return nil, err
	}
	password, hasPassword, err := client.loadPassword(flags, stdin, stderr)
	if err != nil {
		return nil, err
	}
	defer clear(password)
	var attempts []error
	for _, endpoint := range endpoints {
		connection, err := connectLDAPCompareRawEndpoint(client, endpoint, password, hasPassword, stderr)
		if err == nil {
			client.uri = endpoint.dialURI
			return connection, nil
		}
		if !ldapClientFailoverRetryable(err) {
			return nil, redactLDAPVCError(err, password)
		}
		attempts = append(attempts, err)
	}
	return nil, redactLDAPVCError(ldapClientFailoverError(attempts), password)
}

type ldapVCResult struct {
	outerCode, code                     uint16
	matchedDN, diagnostic, vcDiagnostic string
	referrals                           []string
	controls, vcControls                []ldapSearchResponseControl
	hasValue, hasCookie, hasSASL        bool
}

func decodeLDAPVCResponse(raw []byte, messageID int64, responseTag uint64) (ldapVCResult, error) {
	var result ldapVCResult
	packet, err := decodeLDAPVCBER(raw, int(ldapwire.DefaultMaxMessageSize))
	if err != nil {
		return result, err
	}
	defer clearBERPacket(packet)
	if !ldapClientPacketIs(packet, ber.ClassUniversal, ber.TypeConstructed, uint64(ber.TagSequence)) || len(packet.Children) < 2 || len(packet.Children) > 3 {
		return result, errors.New("malformed ldapvc response envelope")
	}
	id := packet.Children[0]
	number, ok := ldapClientPacketInteger(id)
	if !ldapClientPacketIs(id, ber.ClassUniversal, ber.TypePrimitive, uint64(ber.TagInteger)) || !ok || number != messageID || number <= 0 {
		return result, errors.New("unexpected ldapvc response message ID")
	}
	op := packet.Children[1]
	if !ldapClientPacketIs(op, ber.ClassApplication, ber.TypeConstructed, responseTag) || len(op.Children) < 3 {
		return result, errors.New("unexpected ldapvc response operation")
	}
	result.outerCode, err = ldapVCCode(op.Children[0], false)
	if err != nil {
		return result, err
	}
	result.matchedDN, err = ldapVCString(op.Children[1])
	if err != nil {
		return result, err
	}
	result.diagnostic, err = ldapVCString(op.Children[2])
	if err != nil {
		return result, err
	}
	lastTag := -1
	for _, field := range op.Children[3:] {
		if field.ClassType != ber.ClassContext || int(field.Tag) <= lastTag {
			return result, errors.New("duplicate or out-of-order ldapvc response field")
		}
		lastTag = int(field.Tag)
		switch {
		case field.Tag == 3 && field.TagType == ber.TypeConstructed:
			if len(field.Children) == 0 || len(field.Children) > maxLDAPVCControls {
				return result, errors.New("invalid ldapvc referrals")
			}
			for _, referral := range field.Children {
				value, err := ldapVCString(referral)
				if err != nil || value == "" {
					return result, errors.New("invalid ldapvc referral")
				}
				result.referrals = append(result.referrals, value)
			}
		case responseTag == ldap.ApplicationExtendedResponse && field.Tag == 10 && field.TagType == ber.TypePrimitive:
			if string(field.Data.Bytes()) != ldapVerifyCredentialsOID {
				return result, errors.New("unexpected Verify Credentials response OID")
			}
		case responseTag == ldap.ApplicationExtendedResponse && field.Tag == 11 && field.TagType == ber.TypePrimitive:
			result.hasValue = true
			if err := decodeLDAPVCValue(field.Data.Bytes(), &result); err != nil {
				return result, err
			}
		default:
			return result, errors.New("unexpected ldapvc response field")
		}
	}
	if len(packet.Children) == 3 {
		result.controls, err = decodeLDAPVCControls(packet.Children[2], 0)
		if err != nil {
			return result, err
		}
	}
	if responseTag == ldap.ApplicationExtendedResponse && result.outerCode == 0 && !result.hasValue {
		return result, errors.New("Verify Credentials success response is missing its value")
	}
	return result, nil
}

func decodeLDAPVCValue(value []byte, result *ldapVCResult) error {
	packet, err := decodeLDAPVCBER(value, maxLDAPExtendedValueSize)
	if err != nil {
		return err
	}
	defer clearBERPacket(packet)
	if !ldapClientPacketIs(packet, ber.ClassUniversal, ber.TypeConstructed, uint64(ber.TagSequence)) || len(packet.Children) < 2 || len(packet.Children) > 5 {
		return errors.New("malformed Verify Credentials response value")
	}
	// vc_create_response uses ber_printf("{is"), i.e. INTEGER, not ENUMERATED.
	result.code, err = ldapVCCode(packet.Children[0], true)
	if err != nil {
		return err
	}
	result.vcDiagnostic, err = ldapVCString(packet.Children[1])
	if err != nil {
		return err
	}
	lastTag := -1
	for _, field := range packet.Children[2:] {
		if field.ClassType != ber.ClassContext || int(field.Tag) <= lastTag {
			return errors.New("duplicate or out-of-order Verify Credentials field")
		}
		lastTag = int(field.Tag)
		switch {
		case field.Tag == 0 && field.TagType == ber.TypePrimitive:
			result.hasCookie = true
		case field.Tag == 1 && field.TagType == ber.TypePrimitive:
			result.hasSASL = true
		case field.Tag == 2 && field.TagType == ber.TypeConstructed:
			result.vcControls, err = decodeLDAPVCControls(field, 2)
			if err != nil {
				return err
			}
		default:
			return errors.New("unexpected Verify Credentials field")
		}
	}
	return nil
}

func ldapVCCode(packet *ber.Packet, allowInteger bool) (uint16, error) {
	code, ok := ldapClientPacketInteger(packet)
	if !ok || packet.Data == nil || packet.Data.Len() == 0 || code < 0 || code > 65535 || (!allowInteger && packet.Tag != ber.TagEnumerated) {
		return 0, errors.New("invalid ldapvc result code")
	}
	return uint16(code), nil
}

func ldapVCString(packet *ber.Packet) (string, error) {
	if !ldapClientPacketIs(packet, ber.ClassUniversal, ber.TypePrimitive, uint64(ber.TagOctetString)) ||
		!utf8.Valid(packet.Data.Bytes()) || bytesContainNUL(packet.Data.Bytes()) {
		return "", errors.New("invalid ldapvc LDAPString")
	}
	return string(packet.Data.Bytes()), nil
}

func decodeLDAPVCControls(wrapper *ber.Packet, tag uint64) ([]ldapSearchResponseControl, error) {
	if !ldapClientPacketIs(wrapper, ber.ClassContext, ber.TypeConstructed, tag) || len(wrapper.Children) == 0 || len(wrapper.Children) > maxLDAPVCControls {
		return nil, errors.New("invalid ldapvc control list")
	}
	var controls []ldapSearchResponseControl
	seen := make(map[string]bool)
	for _, packet := range wrapper.Children {
		if !ldapClientPacketIs(packet, ber.ClassUniversal, ber.TypeConstructed, uint64(ber.TagSequence)) || len(packet.Children) < 1 || len(packet.Children) > 3 {
			return nil, errors.New("malformed ldapvc control")
		}
		oid, err := ldapVCString(packet.Children[0])
		if err != nil || !validLDAPOperationOID(oid) || seen[oid] {
			return nil, errors.New("invalid or duplicate ldapvc control OID")
		}
		seen[oid] = true
		control := ldapSearchResponseControl{oid: oid}
		position := 1
		if position < len(packet.Children) && ldapClientPacketIs(packet.Children[position], ber.ClassUniversal, ber.TypePrimitive, uint64(ber.TagBoolean)) {
			field := packet.Children[position]
			if field.Data.Len() != 1 {
				return nil, errors.New("invalid ldapvc control criticality")
			}
			control.critical = field.Data.Bytes()[0] != 0
			position++
		}
		if position < len(packet.Children) {
			field := packet.Children[position]
			if !ldapClientPacketIs(field, ber.ClassUniversal, ber.TypePrimitive, uint64(ber.TagOctetString)) || field.Data.Len() > maxLDAPControlValueSize {
				return nil, errors.New("invalid ldapvc control value")
			}
			control.hasValue = true
			control.value = bytes.Clone(field.Data.Bytes())
			position++
		}
		if position != len(packet.Children) {
			return nil, errors.New("unexpected ldapvc control field")
		}
		if oid == ldap.ControlTypeBeheraPasswordPolicy || oid == ldapControlPreRead || oid == ldapControlPostRead {
			bounded, err := decodeLDAPVCBER(control.value, maxLDAPControlValueSize)
			if err != nil {
				return nil, err
			}
			clearBERPacket(bounded)
			if oid == ldap.ControlTypeBeheraPasswordPolicy {
				if _, err := decodeLDAPPasswordPolicyResponse(control.value); err != nil {
					return nil, err
				}
			} else if _, err := decodeLDAPReadControlEntry(control.value); err != nil {
				return nil, err
			}
		}
		if oid == ldapVCAuthzIDOID && (!control.hasValue || !utf8.Valid(control.value) || bytesContainNUL(control.value)) {
			return nil, errors.New("invalid ldapvc authorization identity")
		}
		controls = append(controls, control)
	}
	return controls, nil
}

// Bound BER work before the recursive library decoder allocates a packet tree.
// LDAP uses definite lengths; all fields in this response use single-byte tags.
// Nonminimal definite lengths are valid BER and occur in OpenLDAP responses.
func decodeLDAPVCBER(raw []byte, limit int) (*ber.Packet, error) {
	if len(raw) == 0 || len(raw) > limit {
		return nil, errors.New("ldapvc BER value is empty or exceeds the size limit")
	}
	elements := 0
	var check func([]byte, int) error
	check = func(data []byte, depth int) error {
		if depth > maxLDAPVCBERDepth {
			return errors.New("ldapvc BER nesting limit exceeded")
		}
		for len(data) != 0 {
			elements++
			if elements > maxLDAPVCBERElements {
				return errors.New("ldapvc BER element limit exceeded")
			}
			if len(data) < 2 || data[0]&31 == 31 || data[0] == 0 {
				return errors.New("malformed ldapvc BER tag")
			}
			tag, length, header := data[0], int(data[1]), 2
			if length&128 != 0 {
				n := length & 127
				if n == 0 || n > 4 || len(data) < 2+n {
					return errors.New("invalid ldapvc BER length")
				}
				length = 0
				for _, octet := range data[2 : 2+n] {
					if length > limit/256 {
						return errors.New("ldapvc BER length exceeds the size limit")
					}
					length = length*256 + int(octet)
				}
				header += n
			}
			if length > len(data)-header {
				return errors.New("truncated ldapvc BER value")
			}
			if tag&32 != 0 {
				if err := check(data[header:header+length], depth+1); err != nil {
					return err
				}
			}
			data = data[header+length:]
		}
		return nil
	}
	if err := check(raw, 0); err != nil {
		return nil, err
	}
	reader := bytes.NewReader(raw)
	packet, err := ber.ReadPacket(reader)
	if err != nil || reader.Len() != 0 {
		return nil, errors.New("malformed ldapvc BER value")
	}
	return packet, nil
}

func writeLDAPVCResult(writer io.Writer, result ldapVCResult, verbose bool) error {
	if result.hasValue {
		if result.code != 0 {
			if _, err := fmt.Fprintf(writer, "Failed: %s (%d)\n", ldapVCResultName(result.code), result.code); err != nil {
				return err
			}
		}
		if result.vcDiagnostic != "" {
			if _, err := fmt.Fprintf(writer, "Diagnostic: %s\n", result.vcDiagnostic); err != nil {
				return err
			}
		}
		if err := writeLDAPVCControls(writer, result.vcControls); err != nil {
			return err
		}
	}
	if verbose || result.outerCode != 0 || result.matchedDN != "" || result.diagnostic != "" || len(result.referrals) != 0 || len(result.controls) != 0 {
		if _, err := fmt.Fprintf(writer, "Result: %s (%d)\n", ldapVCResultName(result.outerCode), result.outerCode); err != nil {
			return err
		}
		for _, field := range []struct{ name, value string }{{"Additional info", result.diagnostic}, {"Matched DN", result.matchedDN}} {
			if field.value != "" {
				if _, err := fmt.Fprintf(writer, "%s: %s\n", field.name, field.value); err != nil {
					return err
				}
			}
		}
		for _, referral := range result.referrals {
			if _, err := fmt.Fprintf(writer, "Referral: %s\n", referral); err != nil {
				return err
			}
		}
		return writeLDAPVCControls(writer, result.controls)
	}
	return nil
}

func writeLDAPVCControls(writer io.Writer, controls []ldapSearchResponseControl) error {
	output := ldapSearchLDIFOutput{writer: writer}
	for _, control := range controls {
		wire := ldapwire.Control{OID: control.oid, Critical: control.critical, HasValue: control.hasValue, Value: control.value}
		if err := writeLDAPCompareOutput(writer, ldapCompareResult{controls: []ldapwire.Control{wire}}, true, false); err != nil {
			return err
		}
		if control.oid == ldap.ControlTypeBeheraPasswordPolicy || control.oid == ldapControlPreRead || control.oid == ldapControlPostRead {
			if err := output.writeKnownResponseControl(control); err != nil {
				return err
			}
		}
		if control.oid == ldapVCAuthzIDOID {
			identity := control.value
			if len(identity) == 0 {
				identity = []byte("anonymous")
			}
			if err := writeLDIFAttribute(writer, "authzid", identity); err != nil {
				return err
			}
		}
	}
	return nil
}

func ldapVCRedact(value string, secret []byte) string {
	if len(secret) == 0 {
		return value
	}
	return strings.ReplaceAll(value, string(secret), "[redacted]")
}

func ldapVCResultName(code uint16) string {
	if name := openLDAPControlResultText(ldapwire.ResultCode(code)); name != "Unknown error" {
		return name
	}
	if name, ok := map[uint16]string{
		5: "Compare False", 6: "Compare True", 7: "Authentication method not supported",
		9: "Partial results and referral received", 14: "SASL bind in progress",
		20: "Type or value exists", 21: "Invalid syntax", 34: "Invalid DN syntax",
		54: "Loop detected", 66: "Operation not allowed on non-leaf", 67: "Operation not allowed on RDN",
		68: "Already exists", 69: "Cannot modify object class", 71: "Operation affects multiple DSAs",
	}[code]; ok {
		return name
	}
	return openLDAPResultName(code)
}

func redactLDAPVCError(err error, secret []byte) error {
	if err == nil || len(secret) == 0 {
		return err
	}
	if code, cause, ok := ldapClientExitStatus(err); ok {
		if cause == nil {
			return err
		}
		return &ldapClientExitError{code: code, cause: redactLDAPVCError(cause, secret)}
	}
	if strings.Contains(err.Error(), string(secret)) {
		return errors.New(ldapVCRedact(err.Error(), secret))
	}
	return err
}
