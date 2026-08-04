package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPOTPVersion = "2.6.13"
	openLDAPOTPCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	openLDAPOTPSecret = "12345678901234567890"

	openLDAPOTPHOTPParamsDN = "ou=hotp-params,ou=people,dc=example,dc=com"
	openLDAPOTPHOTPTokenDN  = "ou=hotp-token,ou=people,dc=example,dc=com"
	openLDAPOTPHOTPUserDN   = "uid=otp-hotp,ou=people,dc=example,dc=com"
	openLDAPOTPHOTPPassword = "hotp-static"
	openLDAPOTPHOTPNewPass  = "hotp-new"

	openLDAPOTPTOTPParamsDN = "ou=totp-params,ou=people,dc=example,dc=com"
	openLDAPOTPTOTPTokenDN  = "ou=totp-token,ou=people,dc=example,dc=com"
	openLDAPOTPTOTPUserDN   = "uid=otp-totp,ou=people,dc=example,dc=com"
	openLDAPOTPTOTPPassword = "totp-static"

	// A ten-year period keeps this differential away from ordinary clock
	// boundaries while still exercising the TOTP path with a live clock.
	openLDAPOTPTOTPPeriod int64 = 315360000
)

type openLDAPOTPState struct {
	counter  string
	lastStep string
	drift    string
	secret   string
}

type openLDAPOTPDifferentialOutcome struct {
	staticBind uint16
	otpBind    uint16
	counter    string
}

func TestOpenLDAPReferenceOTPPhaseOne(t *testing.T) {
	tools := requireOpenLDAPOTPReferenceTools(t)
	assertPinnedOpenLDAPOTPReference(t, tools)

	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		assertOpenLDAPOTPPhaseOneFixture(t, tools)
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go differential", func(t *testing.T) {
		assertLDAPGoOTPPhaseOneFixture(t)

		want := observeOpenLDAPOTPMinimalReference(t, tools)
		got := observeLDAPGoOTPMinimalReference(t)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf(
				"ldap-go OTP Phase 1 is not implemented or differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				want,
				got,
			)
		}
	})
}

func assertLDAPGoOTPPhaseOneFixture(t *testing.T) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedOTPEntries(t, store, true, true)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stop()
	uri := "ldap://" + address
	root := bindOverlayReferenceClient(t, uri, "secret")
	defer root.Close()

	assertOpenLDAPOTPHOTPFlow(t, uri, root)
	assertOpenLDAPOTPTOTPFlow(t, uri, root)
}

func requireOpenLDAPOTPReferenceTools(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run the pinned OpenLDAP OTP reference test",
			openLDAPReferenceTestsEnv,
		)
	}

	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	features := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		features[strings.ToLower(strings.TrimSpace(line))] = true
	}
	if !features["otp"] {
		t.Skipf(
			"the selected OpenLDAP slapd was not built with the otp overlay:\n%s",
			output,
		)
	}
	if err != nil {
		t.Fatalf("inspect pinned OpenLDAP overlays: %v\n%s", err, output)
	}
	return tools
}

func assertPinnedOpenLDAPOTPReference(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPOTPVersion {
		t.Fatalf(
			"OpenLDAP reference version = %q, want %q",
			got,
			openLDAPOTPVersion,
		)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPOTPCommit {
		t.Fatalf(
			"OpenLDAP reference commit = %q, want %q",
			got,
			openLDAPOTPCommit,
		)
	}

	versionOutput, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil && len(versionOutput) == 0 {
		t.Fatalf("inspect OpenLDAP version: %v", err)
	}
	if !strings.Contains(
		string(versionOutput),
		"OpenLDAP: slapd "+openLDAPOTPVersion+" ",
	) {
		t.Fatalf(
			"OTP differential requires OpenLDAP slapd %s, got:\n%s",
			openLDAPOTPVersion,
			versionOutput,
		)
	}

	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	revision, err := exec.Command(
		"git",
		"-C",
		sourceRoot,
		"rev-parse",
		"HEAD",
	).Output()
	if err != nil {
		t.Fatalf("inspect pinned OpenLDAP checkout: %v", err)
	}
	if got := strings.TrimSpace(string(revision)); got != openLDAPOTPCommit {
		t.Fatalf(
			"OpenLDAP source checkout = %q, want %q",
			got,
			openLDAPOTPCommit,
		)
	}

	sources := []struct {
		path    string
		hash    string
		anchors []string
		absent  []string
	}{
		{
			path: filepath.Join("servers", "slapd", "overlays", "otp.c"),
			hash: "c45ab324bec2241126d766decde665a6721ea293c84d88741cbbd29250a532e3",
			anchors: []string{
				"otp.on_bi.bi_op_bind = otp_op_bind;",
				"op->orb_cred.bv_len -= otp_len;",
				"cb->sc_response = otp_bind_response;",
				"m->sml_op = LDAP_MOD_REPLACE;",
				"op2.o_tag = LDAP_REQ_MODIFY;",
				"be_entry_get_rw( op, &totpdn, oc_oathTOTPToken, ad_oathSecret, 0,",
				"be_entry_get_rw( op, &hotpdn, oc_oathHOTPToken, ad_oathSecret, 0,",
				"be_entry_release_r( op, token );",
				"op2.o_bd->be_modify( &op2, &rs2 );",
			},
			absent: []string{
				"otp.on_bi.bi_extended",
				"otp.on_bi.bi_op_extended",
			},
		},
		{
			path: filepath.Join("tests", "scripts", "test080-hotp"),
			hash: "9a9559c6bac0d64c7e1ea03812d954b6243fb3557acec0ebd591ef5774581643",
			anchors: []string{
				"if test $OTP = otpno; then",
				"TOKEN_4=892599",
				"a valid and expected token...",
				"reusing the same token...",
				"right token, wrong password...",
				"making sure previous token has been retired too...",
				"Retrieving token status...",
			},
		},
		{
			path: filepath.Join("tests", "scripts", "test081-totp"),
			hash: "52d056896a068e54b76ef3ff314bbff98fd0228935cd840c210c770df0785ebd",
			anchors: []string{
				"if test $OTP = otpno; then",
				"OTP_DATA=$DATADIR/otp/totp.ldif",
				"olcOverlay={0}otp",
				`"$python" "$0".py`,
			},
		},
		{
			path: filepath.Join("tests", "scripts", "test081-totp.py"),
			hash: "d91953f1983db05243c06727c37cfda413796c1330e2152cbd5ff8d6c44496fb",
			anchors: []string{
				"def get_hotp_token(secret, interval_no):",
				"Testing token can only be used once",
				"Testing token is retired even with a wrong password",
			},
		},
	}
	for _, source := range sources {
		path := filepath.Join(sourceRoot, source.path)
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", source.path, err)
		}
		got := fmt.Sprintf("%x", sha256.Sum256(contents))
		if got != source.hash {
			t.Fatalf(
				"pinned OpenLDAP source %s SHA-256 = %s, want %s",
				source.path,
				got,
				source.hash,
			)
		}
		for _, anchor := range source.anchors {
			if !strings.Contains(string(contents), anchor) {
				t.Fatalf(
					"pinned OpenLDAP source %s lacks %q",
					source.path,
					anchor,
				)
			}
		}
		for _, absent := range source.absent {
			if strings.Contains(string(contents), absent) {
				t.Fatalf(
					"pinned OpenLDAP source %s unexpectedly contains %q",
					source.path,
					absent,
				)
			}
		}
		if source.path == filepath.Join("servers", "slapd", "overlays", "otp.c") {
			// This ordered path is the source-level TOCTOU contract. A runtime
			// assertion on the number of concurrent successes would be unstable.
			assertOpenLDAPOTPOrderedSourceAnchors(t, string(contents),
				"be_entry_get_rw( op, &hotpdn, oc_oathHOTPToken, ad_oathSecret, 0,",
				"t = otp_hotp( op, token );",
				"be_entry_release_r( op, token );",
				"m->sml_op = LDAP_MOD_REPLACE;",
				"op2.o_bd->be_modify( &op2, &rs2 );",
			)
		}
	}
}

func assertOpenLDAPOTPOrderedSourceAnchors(
	t *testing.T,
	contents string,
	anchors ...string,
) {
	t.Helper()
	offset := 0
	for _, anchor := range anchors {
		index := strings.Index(contents[offset:], anchor)
		if index < 0 {
			t.Fatalf("pinned otp.c lacks ordered anchor %q", anchor)
		}
		offset += index + len(anchor)
	}
}

func assertOpenLDAPOTPPhaseOneFixture(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		openLDAPOTPDatabaseConfig(),
		openLDAPOTPFixtureLDIF(),
	)
	defer stop()

	root := bindOverlayReferenceClient(t, uri, "secret")
	defer root.Close()

	assertOpenLDAPOTPHOTPFlow(t, uri, root)
	assertOpenLDAPOTPTOTPFlow(t, uri, root)
}

func assertOpenLDAPOTPHOTPFlow(
	t *testing.T,
	uri string,
	root *ldap.Conn,
) {
	t.Helper()
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPHOTPUserDN,
		openLDAPOTPHOTPPassword,
		ldap.LDAPResultInvalidCredentials,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "3",
		secret:  openLDAPOTPSecret,
	})

	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPHOTPUserDN,
		openLDAPOTPHOTPPassword+openLDAPOTPToken(openLDAPOTPSecret, 8, 6),
		ldap.LDAPResultInvalidCredentials,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "3",
		secret:  openLDAPOTPSecret,
	})

	token4 := openLDAPOTPToken(openLDAPOTPSecret, 4, 6)
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPHOTPUserDN,
		openLDAPOTPHOTPPassword+token4,
		ldap.LDAPResultSuccess,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "4",
		secret:  openLDAPOTPSecret,
	})
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPHOTPUserDN,
		openLDAPOTPHOTPPassword+token4,
		ldap.LDAPResultInvalidCredentials,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "4",
		secret:  openLDAPOTPSecret,
	})

	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPHOTPUserDN,
		"wrong-static"+openLDAPOTPToken(openLDAPOTPSecret, 5, 6),
		ldap.LDAPResultInvalidCredentials,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "5",
		secret:  openLDAPOTPSecret,
	})

	user, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(HOTP Password Modify): %v", err)
	}
	defer user.Close()
	if err := user.Bind(
		openLDAPOTPHOTPUserDN,
		openLDAPOTPHOTPPassword+openLDAPOTPToken(openLDAPOTPSecret, 6, 6),
	); err != nil {
		t.Fatalf("Bind(HOTP Password Modify): %v", err)
	}
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "6",
		secret:  openLDAPOTPSecret,
	})

	_, err = user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		openLDAPOTPHOTPPassword+openLDAPOTPToken(openLDAPOTPSecret, 7, 6),
		"must-not-be-stored",
	))
	assertOpenLDAPOTPResultCode(
		t,
		err,
		ldap.LDAPResultUnwillingToPerform,
		"Password Modify with static password and OTP",
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "6",
		secret:  openLDAPOTPSecret,
	})

	_, err = user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		openLDAPOTPHOTPPassword,
		openLDAPOTPHOTPNewPass,
	))
	assertOpenLDAPOTPResultCode(
		t,
		err,
		ldap.LDAPResultSuccess,
		"Password Modify with static password",
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "6",
		secret:  openLDAPOTPSecret,
	})

	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPHOTPUserDN,
		openLDAPOTPHOTPPassword,
		ldap.LDAPResultInvalidCredentials,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "6",
		secret:  openLDAPOTPSecret,
	})
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPHOTPUserDN,
		openLDAPOTPHOTPNewPass+openLDAPOTPToken(openLDAPOTPSecret, 7, 6),
		ldap.LDAPResultSuccess,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPHOTPTokenDN, openLDAPOTPState{
		counter: "7",
		secret:  openLDAPOTPSecret,
	})
}

func assertOpenLDAPOTPTOTPFlow(
	t *testing.T,
	uri string,
	root *ldap.Conn,
) {
	t.Helper()
	step := time.Now().Unix() / openLDAPOTPTOTPPeriod
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPTOTPUserDN,
		openLDAPOTPTOTPPassword,
		ldap.LDAPResultInvalidCredentials,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPTOTPTokenDN, openLDAPOTPState{
		secret: openLDAPOTPSecret,
	})
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPTOTPUserDN,
		openLDAPOTPTOTPPassword+openLDAPOTPToken(
			openLDAPOTPSecret,
			uint64(step+2),
			6,
		),
		ldap.LDAPResultInvalidCredentials,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPTOTPTokenDN, openLDAPOTPState{
		secret: openLDAPOTPSecret,
	})

	current := openLDAPOTPToken(openLDAPOTPSecret, uint64(step), 6)
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPTOTPUserDN,
		openLDAPOTPTOTPPassword+current,
		ldap.LDAPResultSuccess,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPTOTPTokenDN, openLDAPOTPState{
		lastStep: strconv.FormatInt(step, 10),
		drift:    "0",
		secret:   openLDAPOTPSecret,
	})
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPTOTPUserDN,
		openLDAPOTPTOTPPassword+current,
		ldap.LDAPResultInvalidCredentials,
	)

	future := openLDAPOTPToken(openLDAPOTPSecret, uint64(step+1), 6)
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPTOTPUserDN,
		"wrong-static"+future,
		ldap.LDAPResultInvalidCredentials,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPTOTPTokenDN, openLDAPOTPState{
		lastStep: strconv.FormatInt(step+1, 10),
		drift:    "1",
		secret:   openLDAPOTPSecret,
	})
	assertOpenLDAPOTPBindCode(
		t,
		uri,
		openLDAPOTPTOTPUserDN,
		openLDAPOTPTOTPPassword+future,
		ldap.LDAPResultInvalidCredentials,
	)
	assertOpenLDAPOTPState(t, root, openLDAPOTPTOTPTokenDN, openLDAPOTPState{
		lastStep: strconv.FormatInt(step+1, 10),
		drift:    "1",
		secret:   openLDAPOTPSecret,
	})
}

func observeOpenLDAPOTPMinimalReference(
	t *testing.T,
	tools openLDAPReferenceTools,
) openLDAPOTPDifferentialOutcome {
	t.Helper()
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		openLDAPOTPDatabaseConfig(),
		openLDAPOTPFixtureLDIF(),
	)
	defer stop()
	root := bindOverlayReferenceClient(t, uri, "secret")
	defer root.Close()

	return openLDAPOTPDifferentialOutcome{
		staticBind: openLDAPOTPBindResultCode(
			t,
			uri,
			openLDAPOTPHOTPUserDN,
			openLDAPOTPHOTPPassword,
		),
		otpBind: openLDAPOTPBindResultCode(
			t,
			uri,
			openLDAPOTPHOTPUserDN,
			openLDAPOTPHOTPPassword+
				openLDAPOTPToken(openLDAPOTPSecret, 4, 6),
		),
		counter: readOpenLDAPOTPState(
			t,
			root,
			openLDAPOTPHOTPTokenDN,
		).counter,
	}
}

func observeLDAPGoOTPMinimalReference(
	t *testing.T,
) openLDAPOTPDifferentialOutcome {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	entries := []directory.Entry{
		{
			DN: "olcOverlay={0}otp,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}otp")},
			},
		},
		{
			DN: openLDAPOTPHOTPParamsDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathHOTPParams")},
				{Description: "ou", Values: stringValues("hotp-params")},
				{Description: "oathOTPLength", Values: stringValues("6")},
				{Description: "oathHOTPLookAhead", Values: stringValues("3")},
				{Description: "oathHMACAlgorithm", Values: stringValues("1.2.840.113549.2.7")},
			},
		},
		{
			DN: openLDAPOTPHOTPTokenDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathHOTPToken")},
				{Description: "ou", Values: stringValues("hotp-token")},
				{Description: "oathHOTPParams", Values: stringValues(openLDAPOTPHOTPParamsDN)},
				{Description: "oathSecret", Values: stringValues(openLDAPOTPSecret)},
				{Description: "oathHOTPCounter", Values: stringValues("3")},
			},
		},
		{
			DN: openLDAPOTPHOTPUserDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson", "oathHOTPUser")},
				{Description: "uid", Values: stringValues("otp-hotp")},
				{Description: "cn", Values: stringValues("OTP HOTP")},
				{Description: "sn", Values: stringValues("HOTP")},
				{Description: "userPassword", Values: stringValues(openLDAPOTPHOTPPassword)},
				{Description: "oathHOTPToken", Values: stringValues(openLDAPOTPHOTPTokenDN)},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed ldap-go OTP differential fixture: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()
	uri := "ldap://" + address
	outcome := openLDAPOTPDifferentialOutcome{
		staticBind: openLDAPOTPBindResultCode(
			t,
			uri,
			openLDAPOTPHOTPUserDN,
			openLDAPOTPHOTPPassword,
		),
		otpBind: openLDAPOTPBindResultCode(
			t,
			uri,
			openLDAPOTPHOTPUserDN,
			openLDAPOTPHOTPPassword+
				openLDAPOTPToken(openLDAPOTPSecret, 4, 6),
		),
	}
	state := readStoredEntry(t, store, openLDAPOTPHOTPTokenDN)
	values := state.Values("oathHOTPCounter")
	if len(values) != 1 {
		t.Fatalf("ldap-go oathHOTPCounter values = %q, want one", values)
	}
	outcome.counter = string(values[0])
	return outcome
}

func openLDAPOTPFixtureLDIF() string {
	return fmt.Sprintf(`
dn: %s
objectClass: top
objectClass: organizationalUnit
objectClass: oathHOTPParams
ou: hotp-params
oathOTPLength: 6
oathHOTPLookAhead: 3
oathHMACAlgorithm: 1.2.840.113549.2.7

dn: %s
objectClass: top
objectClass: organizationalUnit
objectClass: oathHOTPToken
ou: hotp-token
oathHOTPParams: %s
oathSecret: %s
oathHOTPCounter: 3

dn: %s
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: oathHOTPUser
uid: otp-hotp
cn: OTP HOTP
sn: HOTP
userPassword: %s
oathHOTPToken: %s

dn: %s
objectClass: top
objectClass: organizationalUnit
objectClass: oathTOTPParams
ou: totp-params
oathOTPLength: 6
oathTOTPTimeStepPeriod: %d
oathTOTPTimeStepWindow: 1
oathHMACAlgorithm: 1.2.840.113549.2.7

dn: %s
objectClass: top
objectClass: organizationalUnit
objectClass: oathTOTPToken
ou: totp-token
oathTOTPParams: %s
oathSecret: %s

dn: %s
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: oathTOTPUser
uid: otp-totp
cn: OTP TOTP
sn: TOTP
userPassword: %s
oathTOTPToken: %s
`,
		openLDAPOTPHOTPParamsDN,
		openLDAPOTPHOTPTokenDN,
		openLDAPOTPHOTPParamsDN,
		openLDAPOTPSecret,
		openLDAPOTPHOTPUserDN,
		openLDAPOTPHOTPPassword,
		openLDAPOTPHOTPTokenDN,
		openLDAPOTPTOTPParamsDN,
		openLDAPOTPTOTPPeriod,
		openLDAPOTPTOTPTokenDN,
		openLDAPOTPTOTPParamsDN,
		openLDAPOTPSecret,
		openLDAPOTPTOTPUserDN,
		openLDAPOTPTOTPPassword,
		openLDAPOTPTOTPTokenDN,
	)
}

func openLDAPOTPDatabaseConfig() string {
	return "access to attrs=userPassword by self write by anonymous auth by * none\n" +
		"access to * by * read\n" +
		"overlay otp"
}

func openLDAPOTPToken(secret string, movingFactor uint64, digits int) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], movingFactor)
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := int(digest[len(digest)-1] & 0x0f)
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus)
}

func assertOpenLDAPOTPBindCode(
	t *testing.T,
	uri,
	dn,
	password string,
	want uint16,
) {
	t.Helper()
	got := openLDAPOTPBindResultCode(t, uri, dn, password)
	if got != want {
		t.Fatalf("Bind(%s) result = %d, want %d", dn, got, want)
	}
}

func openLDAPOTPBindResultCode(
	t *testing.T,
	uri,
	dn,
	password string,
) uint16 {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	return openLDAPOTPResultCode(t, client.Bind(dn, password))
}

func assertOpenLDAPOTPResultCode(
	t *testing.T,
	err error,
	want uint16,
	operation string,
) {
	t.Helper()
	got := openLDAPOTPResultCode(t, err)
	if got != want {
		t.Fatalf("%s result = %d (%v), want %d", operation, got, err, want)
	}
}

func openLDAPOTPResultCode(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("OTP operation returned a non-LDAP error: %v", err)
	}
	return ldapErr.ResultCode
}

func assertOpenLDAPOTPState(
	t *testing.T,
	root *ldap.Conn,
	dn string,
	want openLDAPOTPState,
) {
	t.Helper()
	got := readOpenLDAPOTPState(t, root, dn)
	if got != want {
		t.Fatalf("OTP state for %s = %#v, want %#v", dn, got, want)
	}
}

func readOpenLDAPOTPState(
	t *testing.T,
	root *ldap.Conn,
	dn string,
) openLDAPOTPState {
	t.Helper()
	result, err := root.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{
			"oathHOTPCounter",
			"oathTOTPLastTimeStep",
			"oathTOTPTimeStepDrift",
			"oathSecret",
		},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(OTP state %s): %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(OTP state %s) entries = %d, want 1", dn, len(result.Entries))
	}
	entry := result.Entries[0]
	return openLDAPOTPState{
		counter:  entry.GetAttributeValue("oathHOTPCounter"),
		lastStep: entry.GetAttributeValue("oathTOTPLastTimeStep"),
		drift:    entry.GetAttributeValue("oathTOTPTimeStepDrift"),
		secret:   entry.GetAttributeValue("oathSecret"),
	}
}
