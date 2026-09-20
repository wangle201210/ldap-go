package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func ldapVCTestTLV(tag byte, parts ...[]byte) []byte {
	packet := ber.Encode(ber.Class(tag&0xc0), ber.Type(tag&0x20), ber.Tag(tag&0x1f), nil, "fixture")
	for _, part := range parts {
		packet.Data.Write(part)
	}
	return packet.Bytes()
}

func ldapVCTestValue(code byte, diagnostic string, optional ...[]byte) []byte {
	fields := [][]byte{{0x02, 0x01, code}, ldapVCTestTLV(4, []byte(diagnostic))}
	return ldapVCTestTLV(0x30, append(fields, optional...)...)
}

func ldapVCTestResponse(id int64, outer ldapwire.Result, value []byte, controls ...ldapwire.Control) []byte {
	return ldapwire.EncodeExtendedResponse(id, outer, "", value, controls)
}

func TestLDAPVCWireAndIndependentAuthentication(t *testing.T) {
	for _, test := range []struct {
		name, input        string
		args               []string
		bindPassword, sasl string
	}{
		{name: "anonymous connection", args: []string{"-x", "cn=user", "pw"}},
		{name: "simple connection", args: []string{"-x", "-Dcn=operator", "-wbind-secret", "cn=user", "pw"}, bindPassword: "bind-secret"},
		{name: "prompt order", args: []string{"-x", "-Dcn=operator", "-W", "cn=user"}, input: "pw\nbind-secret\n", bindPassword: "bind-secret"},
		{name: "SASL connection", args: []string{"-YPLAIN", "-Uoperator", "-wbind-secret", "cn=user", "pw"}, bindPassword: "bind-secret", sasl: "PLAIN"},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan ldapwire.Message, 2)
			fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
				requests <- message
				if _, ok := message.Request.(ldapwire.BindRequest); ok {
					return nil, nil
				}
				return [][]byte{ldapVCTestResponse(message.ID, ldapwire.Result{}, ldapVCTestValue(0, ""))}, nil
			})
			args := append([]string{"ldapvc", "-H", fixture.uri}, test.args...)
			stdout, stderr, code := runLDAPClientCommand(args, test.input)
			if code != 0 || stdout != "" {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if test.input != "" && stderr != "User's password: Enter LDAP Password: " {
				t.Fatalf("prompt order: %q", stderr)
			}
			bind := awaitLDAPClientWireMessage(t, requests).Request.(ldapwire.BindRequest)
			if bind.Authentication.SASLMechanism != test.sasl {
				t.Fatal("connection SASL mechanism changed")
			}
			if test.sasl == "" && (string(bind.Authentication.Simple) != test.bindPassword || (test.bindPassword != "" && bind.Name != "cn=operator")) {
				t.Fatal("connection credentials differ from bind options")
			}
			if test.sasl != "" && string(bind.Authentication.SASLCredentials) != "\x00operator\x00bind-secret" {
				t.Fatal("connection SASL credentials differ from bind options")
			}
			message := awaitLDAPClientWireMessage(t, requests)
			request, ok := message.Request.(ldapwire.ExtendedRequest)
			// Independent golden: SEQUENCE { OCTET STRING "cn=user", [0] "pw" }.
			golden, _ := hex.DecodeString("300d0407636e3d7573657280027077")
			if !ok || request.Name != "1.3.6.1.4.1.4203.666.6.5" || !request.HasValue || !bytes.Equal(request.Value, golden) || len(message.Controls) != 0 {
				t.Fatal("wrong Verify Credentials wire request")
			}
			for _, secret := range []string{"bind-secret", "pw"} {
				if strings.Contains(stdout+stderr, secret) {
					t.Fatal("credential appeared in command output")
				}
			}
		})
	}
}

func TestLDAPVCNestedControlsAndPasswordFile(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "bind-password")
	if err := os.WriteFile(passwordFile, []byte("bind-file-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	requests := make(chan ldapwire.Message, 2)
	identity := "dn:cn=user"
	inner := ldapVCTestTLV(0xa2,
		ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte(ldapVCAuthzIDOID)), []byte{1, 1, 0xff}, ldapVCTestTLV(4, []byte(identity))),
		ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte(ldap.ControlTypeBeheraPasswordPolicy)), ldapVCTestTLV(4, []byte{0x30, 5, 0xa0, 3, 0x80, 1, 60})),
	)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		requests <- message
		if _, ok := message.Request.(ldapwire.BindRequest); ok {
			return nil, nil
		}
		return [][]byte{ldapVCTestResponse(message.ID, ldapwire.Result{}, ldapVCTestValue(0, "", inner),
			ldapwire.Control{OID: "1.2.3", Critical: true, HasValue: true, Value: []byte{0, 255}})}, nil
	})
	stdout, stderr, code := runLDAPClientCommand([]string{
		"ldapvc", "-xabv", "-H", fixture.uri, "-Dcn=operator", "-y", passwordFile,
		"-eppolicy", "-e!1.2.4", "-o", "ldif_wrap=no", "cn=user", "pw",
	}, "")
	if code != 0 || stderr != "" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, expected := range []string{"authzid: dn:cn=user\n", "ppolicy: expire=60\n", "Result: Success (0)\n", "control: 1.2.3 true AP8=\n", "control: " + ldapVCAuthzIDOID + " true "} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("output missing %q: %q", expected, stdout)
		}
	}
	bindMessage := awaitLDAPClientWireMessage(t, requests)
	bind := bindMessage.Request.(ldapwire.BindRequest)
	if string(bind.Authentication.Simple) != "bind-file-password\n" {
		t.Fatal("bind password file lost its trailing newline")
	}
	assertLDAPWireControl(t, bindMessage.Controls, ldap.ControlTypeBeheraPasswordPolicy, false, false, nil)
	message := awaitLDAPClientWireMessage(t, requests)
	assertLDAPWireControl(t, message.Controls, "1.2.4", true, false, nil)
	assertLDAPWireControl(t, message.Controls, ldap.ControlTypeBeheraPasswordPolicy, false, false, nil)
	value, err := ber.DecodePacketErr(message.Request.(ldapwire.ExtendedRequest).Value)
	if err != nil || len(value.Children) != 3 {
		t.Fatal("invalid request sequence")
	}
	wrapper := value.Children[2]
	if wrapper.ClassType != ber.ClassContext || wrapper.Tag != 2 || wrapper.TagType != ber.TypeConstructed || len(wrapper.Children) != 2 {
		t.Fatal("VC controls are not IMPLICIT [2] Controls")
	}
	for index, oid := range []string{"2.16.840.1.113730.3.4.16", ldap.ControlTypeBeheraPasswordPolicy} {
		control := wrapper.Children[index]
		if len(control.Children) != 1 || string(control.Children[0].Data.Bytes()) != oid {
			t.Fatal("wrong inner control OID, criticality, or value presence")
		}
	}
}

func TestLDAPCompareRawSimpleBindControlsRegression(t *testing.T) {
	requests := make(chan ldapwire.Message, 2)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		requests <- message
		if _, ok := message.Request.(ldapwire.BindRequest); ok {
			return nil, nil
		}
		return [][]byte{ldapwire.EncodeResultResponse(message.ID, ldap.ApplicationCompareResponse, ldapwire.Result{Code: ldapwire.ResultCompareTrue}, nil)}, nil
	})
	stdout, stderr, code := runLDAPClientCommand([]string{
		"ldapcompare", "-x", "-H", fixture.uri, "-D", "cn=operator", "-w", "bind-secret",
		"-e", "ppolicy", "-e", "sessiontracking=operator", "-e", "!1.2.3", "cn=user", "cn:user",
	}, "")
	if code != 6 || stdout != "TRUE\n" || stderr != "" {
		t.Fatalf("Compare exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	bind := awaitLDAPClientWireMessage(t, requests)
	if len(bind.Controls) != 2 {
		t.Fatal("raw simple bind did not select exactly the bind controls")
	}
	assertLDAPWireControl(t, bind.Controls, ldap.ControlTypeBeheraPasswordPolicy, false, false, nil)
	assertLDAPWireControl(t, bind.Controls, ldapwire.SessionTrackingControlOID, false, true, nil)
	compare := awaitLDAPClientWireMessage(t, requests)
	if len(compare.Controls) != 3 {
		t.Fatal("Compare request lost general controls")
	}
	assertLDAPWireControl(t, compare.Controls, "1.2.3", true, false, nil)
}

func TestLDAPVCResultExitPolicyAndRedaction(t *testing.T) {
	for _, test := range []struct {
		name             string
		outer            ldapwire.Result
		value            []byte
		want, diagnostic string
		status           int
		requireVerified  bool
	}{
		{name: "success", value: ldapVCTestValue(0, ""), want: "Result: Success (0)\n"},
		{name: "inner rejection", value: ldapVCTestValue(49, "denied target-secret"), want: "Failed: Invalid credentials (49)\nDiagnostic: denied [redacted]\nResult: Success (0)\n"},
		{name: "required verification rejection", value: ldapVCTestValue(49, "denied target-secret"), want: "Failed: Invalid credentials (49)\nDiagnostic: denied [redacted]\nResult: Success (0)\n", status: 1, requireVerified: true},
		{name: "required verification success", value: ldapVCTestValue(0, ""), want: "Result: Success (0)\n", requireVerified: true},
		{name: "outer rejection", outer: ldapwire.Result{Code: 53, DiagnosticMessage: "denied target-secret", MatchedDN: "dc=example"}, want: "Result: Server is unwilling to perform (53)\nAdditional info: denied [redacted]\nMatched DN: dc=example\n", status: 1},
		{name: "both codes", outer: ldapwire.Result{Code: 49}, value: ldapVCTestValue(32, ""), want: "Failed: No such object (32)\nResult: Invalid credentials (49)\n", status: 1},
		{name: "missing response", diagnostic: "missing its value", status: 1},
		{name: "continuation", value: ldapVCTestValue(14, "", ldapVCTestTLV(0x80, []byte("cookie-secret")), ldapVCTestTLV(0x81, []byte("server-secret"))), diagnostic: "continuation", status: 1},
		{name: "cookie on success", value: ldapVCTestValue(0, "", ldapVCTestTLV(0x80)), diagnostic: "continuation", status: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			uri, done := startLDAPExtendedWireServer(t, func(id int64, _ ldapwire.ExtendedRequest) ([]byte, error) {
				return ldapVCTestResponse(id, test.outer, test.value), nil
			})
			args := []string{"ldapvc", "-xv", "-H", uri}
			if test.requireVerified {
				args = append(args, "-require-verified")
			}
			args = append(args, "cn=user", "target-secret")
			stdout, stderr, status := runLDAPClientCommand(args, "")
			awaitLDAPExtendedWireServer(t, done)
			if status != test.status || stdout != test.want || (test.diagnostic == "" && stderr != "") || !strings.Contains(stderr, test.diagnostic) {
				t.Fatalf("exit=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			for _, secret := range []string{"target-secret", "cookie-secret", "server-secret"} {
				if strings.Contains(stdout+stderr, secret) {
					t.Fatal("secret appeared in output")
				}
			}
		})
	}
	for _, code := range []int{0, 1, 32, 49, 53, 80} {
		for _, cause := range []error{nil, errors.New("denied target-secret"), errors.New("unrelated diagnostic")} {
			original := &ldapClientExitError{code: code, cause: cause}
			redacted := redactLDAPVCError(fmt.Errorf("wrapped: %w", original), []byte("target-secret"))
			actual, printedCause, ok := ldapClientExitStatus(redacted)
			if !ok || actual != code || (printedCause == nil) != (cause == nil) {
				t.Fatalf("redaction dropped exit status %d", code)
			}
			// This is main's actual printed error path, not redacted.Error().
			var stderr bytes.Buffer
			if printedCause != nil {
				fmt.Fprintln(&stderr, "error:", printedCause)
			}
			if strings.Contains(stderr.String(), "target-secret") {
				t.Fatal("main's exit cause printing exposed credentials")
			}
		}
	}
}

func TestLDAPVCMalformedResponses(t *testing.T) {
	validControl := ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte("1.2.3")))
	validFields := [][]byte{{10, 1, 0}, {4, 0}, {4, 0}}
	outer := func(fields ...[]byte) []byte {
		return ldapVCTestTLV(0x30, []byte{2, 1, 2}, ldapVCTestTLV(0x78, append(validFields, fields...)...))
	}
	value := ldapVCTestValue(0, "")
	responseValue := ldapVCTestTLV(0x8b, value)
	for name, raw := range map[string][]byte{
		"wrong ID":                    ldapVCTestResponse(3, ldapwire.Result{}, value),
		"unsolicited":                 ldapVCTestResponse(0, ldapwire.Result{}, value),
		"wrong op":                    ldapwire.EncodeBindResponse(2, ldapwire.Result{}, nil),
		"missing value":               outer(),
		"duplicate value":             outer(responseValue, responseValue),
		"duplicate name":              outer(ldapVCTestTLV(0x8a, []byte(ldapVerifyCredentialsOID)), ldapVCTestTLV(0x8a, []byte(ldapVerifyCredentialsOID)), responseValue),
		"wrong name":                  outer(ldapVCTestTLV(0x8a, []byte("1.2.3")), responseValue),
		"empty name":                  outer(ldapVCTestTLV(0x8a), responseValue),
		"out of order name":           outer(responseValue, ldapVCTestTLV(0x8a, []byte(ldapVerifyCredentialsOID))),
		"constructed value":           outer(ldapVCTestTLV(0xab, value)),
		"unknown outer field":         outer(responseValue, ldapVCTestTLV(0x8c)),
		"duplicate referrals":         outer(ldapVCTestTLV(0xa3, ldapVCTestTLV(4, []byte("ldap://example"))), ldapVCTestTLV(0xa3, ldapVCTestTLV(4, []byte("ldap://example"))), responseValue),
		"empty referral":              outer(ldapVCTestTLV(0xa3), responseValue),
		"wrong outer result tag":      ldapVCTestTLV(0x30, []byte{2, 1, 2}, ldapVCTestTLV(0x78, []byte{2, 1, 0}, []byte{4, 0}, []byte{4, 0}, responseValue)),
		"outer result overflow":       ldapVCTestTLV(0x30, []byte{2, 1, 2}, ldapVCTestTLV(0x78, []byte{10, 3, 1, 0, 0}, []byte{4, 0}, []byte{4, 0}, responseValue)),
		"outer controls duplicated":   ldapVCTestTLV(0x30, []byte{2, 1, 2}, ldapVCTestTLV(0x78, append(validFields, responseValue)...), ldapVCTestTLV(0xa0, validControl), ldapVCTestTLV(0xa0, validControl)),
		"outer control duplicate OID": ldapVCTestResponse(2, ldapwire.Result{}, value, ldapwire.Control{OID: "1.2.3"}, ldapwire.Control{OID: "1.2.3"}),
		"outer string NUL":            ldapVCTestResponse(2, ldapwire.Result{DiagnosticMessage: "bad\x00text"}, value),
		"outer string UTF8":           ldapVCTestResponse(2, ldapwire.Result{DiagnosticMessage: "\xff"}, value),
		"trailing frame":              append(ldapVCTestResponse(2, ldapwire.Result{}, value), 4, 0),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeLDAPVCResponse(raw, 2, ldap.ApplicationExtendedResponse); err == nil {
				t.Fatal("accepted malformed response")
			}
		})
	}
	for name, inner := range map[string][]byte{
		"empty":                   {},
		"wrong sequence":          {0x31, 5, 2, 1, 0, 4, 0},
		"missing diagnostic":      {0x30, 3, 2, 1, 0},
		"wrong code tag":          {0x30, 5, 4, 1, 0, 4, 0},
		"negative code":           ldapVCTestValue(255, ""),
		"overflow code":           {0x30, 7, 2, 3, 1, 0, 0, 4, 0},
		"empty code":              {0x30, 4, 2, 0, 4, 0},
		"NUL diagnostic":          ldapVCTestValue(0, "secret\x00text"),
		"unknown field":           ldapVCTestValue(0, "", ldapVCTestTLV(0x83)),
		"duplicate cookie":        ldapVCTestValue(0, "", ldapVCTestTLV(0x80), ldapVCTestTLV(0x80)),
		"duplicate SASL":          ldapVCTestValue(0, "", ldapVCTestTLV(0x81), ldapVCTestTLV(0x81)),
		"out of order":            ldapVCTestValue(0, "", ldapVCTestTLV(0x81), ldapVCTestTLV(0x80)),
		"constructed cookie":      ldapVCTestValue(0, "", ldapVCTestTLV(0xa0)),
		"primitive controls":      ldapVCTestValue(0, "", ldapVCTestTLV(0x82)),
		"empty controls":          ldapVCTestValue(0, "", ldapVCTestTLV(0xa2)),
		"duplicate controls":      ldapVCTestValue(0, "", ldapVCTestTLV(0xa2, validControl), ldapVCTestTLV(0xa2, validControl)),
		"duplicate OID":           ldapVCTestValue(0, "", ldapVCTestTLV(0xa2, validControl, validControl)),
		"invalid OID":             ldapVCTestValue(0, "", ldapVCTestTLV(0xa2, ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte("secret"))))),
		"bad criticality":         ldapVCTestValue(0, "", ldapVCTestTLV(0xa2, ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte("1.2.3")), []byte{1, 0}))),
		"duplicate criticality":   ldapVCTestValue(0, "", ldapVCTestTLV(0xa2, ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte("1.2.3")), []byte{1, 1, 0}, []byte{1, 1, 0}))),
		"duplicate control value": ldapVCTestValue(0, "", ldapVCTestTLV(0xa2, ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte("1.2.3")), []byte{4, 0}, []byte{4, 0}))),
		"malformed ppolicy":       ldapVCTestValue(0, "", ldapVCTestTLV(0xa2, ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte(ldap.ControlTypeBeheraPasswordPolicy)), ldapVCTestTLV(4, []byte{0x30, 3, 0x81, 1, 10})))),
		"absent authzid value":    ldapVCTestValue(0, "", ldapVCTestTLV(0xa2, ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte(ldapVCAuthzIDOID))))),
		"trailing data":           append(ldapVCTestValue(0, ""), 4, 0),
		"indefinite":              {0x30, 0x80, 2, 1, 0, 4, 0, 0, 0},
		"truncated":               {0x30, 10, 2, 1, 0, 4, 0},
	} {
		t.Run("inner/"+name, func(t *testing.T) {
			if _, err := decodeLDAPVCResponse(ldapVCTestResponse(2, ldapwire.Result{}, inner), 2, ldap.ApplicationExtendedResponse); err == nil {
				t.Fatal("accepted malformed inner response")
			}
		})
	}
	for _, inner := range [][]byte{ldapVCTestValue(0, ""), {0x30, 5, 10, 1, 0, 4, 0}, {0x30, 0x81, 5, 2, 1, 0, 4, 0}} {
		if _, err := decodeLDAPVCResponse(ldapVCTestResponse(2, ldapwire.Result{}, inner), 2, ldap.ApplicationExtendedResponse); err != nil {
			t.Fatalf("rejected valid native/standard BER: %v", err)
		}
	}
}

func TestLDAPVCLimitsAndLocalValidation(t *testing.T) {
	for name, args := range map[string][]string{
		"too many operands":       {"cn=user", "secret", "secret-extra"},
		"invalid DN":              {"not-a-dn", "secret"},
		"credential length":       {"cn=user", strings.Repeat("x", maxPasswordInputSize+1)},
		"credential NUL":          {"cn=user", "secret\x00"},
		"missing flag value":      {"-H"},
		"unknown flag secret":     {"--secret-option"},
		"bad boolean secret":      {"-a=secret"},
		"bad extension secret":    {"-E", "mech=secret"},
		"cookie flag invented":    {"-cookie", "secret"},
		"false a":                 {"-a=false"},
		"unsupported debug":       {"-d1"},
		"unsupported interactive": {"-I"},
		"referrals":               {"-C"},
		"TLS conflict":            {"-Z", "-ZZ"},
	} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, code := runLDAPClientCommand(append([]string{"ldapvc", "-xn"}, args...), "")
			if code == 0 || stdout != "" || strings.Contains(stderr, "secret") {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
	for _, extension := range []string{"sasl=automatic", "mech=PLAIN", "realm=example", "authcid=user", "authzid=u:user", "secprops=none", "!SASL=quiet"} {
		_, stderr, code := runLDAPClientCommand([]string{"ldapvc", "-xn", "-E" + extension}, "")
		if code == 0 || !strings.Contains(stderr, "interactive VC API is not implemented") {
			t.Fatalf("-E unexpectedly accepted: exit=%d stderr=%q", code, stderr)
		}
	}
	for _, args := range [][]string{{"-xn"}, {"-xnv", "cn=user"}, {"-xn", "--", "cn=user", "-password"}, {"-VV"}, {"-V", "-V"}, {"-VVV"}, {"-help"}} {
		_, stderr, code := runLDAPClientCommand(append([]string{"ldapvc"}, args...), "")
		if code != 0 {
			t.Fatalf("valid flags %v: exit=%d stderr=%q", args, code, stderr)
		}
	}
	_, help, _ := runLDAPClientCommand([]string{"ldapvc", "-help"}, "")
	for _, text := range []string{"vc module", "until the module is configured", "cookie/SASL continuation", "-a", "-b", "-E"} {
		if !strings.Contains(help, text) {
			t.Fatalf("help missing %q", text)
		}
	}
	stdout, _, code := runLDAPClientCommand([]string{"help"}, "")
	if code != 0 || !strings.Contains(stdout, "ldapvc") {
		t.Fatal("main help omits ldapvc")
	}
	deep := []byte{4, 0}
	for range maxLDAPVCBERDepth + 2 {
		deep = ldapVCTestTLV(0x30, deep)
	}
	for _, raw := range [][]byte{deep, ldapVCTestTLV(0x30, bytes.Repeat([]byte{4, 0}, maxLDAPVCBERElements+1)), {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, bytes.Repeat([]byte{0}, maxLDAPExtendedValueSize+1)} {
		if _, err := decodeLDAPVCBER(raw, maxLDAPExtendedValueSize); err == nil {
			t.Fatal("accepted BER beyond resource limits")
		}
	}
	var controls [][]byte
	for i := 0; i <= maxLDAPVCControls; i++ {
		controls = append(controls, ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte(fmt.Sprintf("1.2.%d", i)))))
	}
	if _, err := decodeLDAPVCResponse(ldapVCTestResponse(2, ldapwire.Result{}, ldapVCTestValue(0, "", ldapVCTestTLV(0xa2, controls...))), 2, ldap.ApplicationExtendedResponse); err == nil {
		t.Fatal("accepted too many controls")
	}
}

func TestLDAPVCTransportFailureAndFailover(t *testing.T) {
	var binds atomic.Int32
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); ok {
			binds.Add(1)
			return nil, nil
		}
		return [][]byte{ldapVCTestResponse(message.ID, ldapwire.Result{}, ldapVCTestValue(0, ""))}, nil
	})
	stdout, stderr, code := runLDAPClientCommand([]string{"ldapvc", "-x", "-H", unavailableLDAPClientURI(t) + " " + fixture.uri, "cn=user", "pw"}, "")
	if code != 0 || stdout != "" || stderr != "" || binds.Load() != 1 {
		t.Fatalf("failover exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	rejected := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		return [][]byte{ldapwire.EncodeBindResponse(message.ID, ldapwire.Result{Code: 49, DiagnosticMessage: "bind-secret"}, nil)}, nil
	})
	_, stderr, code = runLDAPClientCommand([]string{"ldapvc", "-x", "-H", rejected.uri + " " + fixture.uri, "-Dcn=operator", "-wbind-secret", "cn=user", "pw"}, "")
	if code == 0 || binds.Load() != 1 || strings.Contains(stderr, "bind-secret") {
		t.Fatal("bind rejection leaked a secret or retried another endpoint")
	}
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprintf("oversized=%t", oversized), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				bind, err := ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
				if err != nil {
					done <- err
					return
				}
				if err = ldapwire.Write(conn, ldapwire.EncodeBindResponse(bind.ID, ldapwire.Result{}, nil)); err != nil {
					done <- err
					return
				}
				if _, err = ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize); err != nil {
					done <- err
					return
				}
				if oversized {
					_, err = conn.Write([]byte{0x30, 0x84, 1, 0, 0, 1})
					if err != nil {
						done <- err
						return
					}
				}
				// No body: an oversized header must fail immediately, not at timeout.
				_, err = io.Copy(io.Discard, conn)
				done <- err
			}()
			start := time.Now()
			_, stderr, code := runLDAPClientCommand([]string{"ldapvc", "-x", "-H", "ldap://" + listener.Addr().String(), "-timeout", "100ms", "cn=user", "pw"}, "")
			if code == 0 || (!oversized && !strings.Contains(stderr, "timeout")) || (oversized && !strings.Contains(stderr, "limit")) || time.Since(start) > time.Second {
				t.Fatalf("exit=%d stderr=%q elapsed=%s", code, stderr, time.Since(start))
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLDAPVCTLSAndDisabledServerModule(t *testing.T) {
	config, ca := newLDAPClientToolTLSConfig(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	uri := startLDAPClientTLSWireFixture(t, config, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); ok {
			return [][]byte{ldapwire.EncodeBindResponse(message.ID, ldapwire.Result{}, nil)}, nil
		}
		return [][]byte{ldapVCTestResponse(message.ID, ldapwire.Result{}, ldapVCTestValue(0, ""))}, nil
	})
	stdout, stderr, code := runLDAPClientCommand([]string{"ldapvc", "-x", "-H", uri, "-tls-ca", caPath, "-tls-server-name", "localhost", "cn=user", "pw"}, "")
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("LDAPS exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	uri = startLDAPClientToolServer(t, config)
	stdout, stderr, code = runLDAPClientCommand([]string{"ldapvc", "-x", "-ZZ", "-H", uri, "-tls-ca", caPath, "-tls-server-name", "localhost", "cn=user", "pw"}, "")
	if code != 1 || !strings.Contains(stdout, "(2)") || !strings.Contains(stdout, "unsupported extended operation") {
		t.Fatalf("own server limitation exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func FuzzLDAPVCResponse(f *testing.F) {
	f.Add(ldapVCTestResponse(2, ldapwire.Result{}, ldapVCTestValue(0, "")))
	f.Add(ldapVCTestResponse(2, ldapwire.Result{}, ldapVCTestValue(14, "", ldapVCTestTLV(0x80, []byte("cookie")))))
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<16 {
			return
		}
		result, err := decodeLDAPVCResponse(raw, 2, ldap.ApplicationExtendedResponse)
		if err == nil && result.outerCode == 0 && !result.hasValue {
			t.Fatal("accepted success without a VC response")
		}
	})
}
