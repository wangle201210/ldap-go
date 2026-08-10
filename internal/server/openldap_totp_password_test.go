package server

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPTOTPPasswordCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func TestOpenLDAPReferenceTOTPPasswordModule(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPTOTPPasswordModule(t)
	assertOpenLDAPTOTPPasswordSourceContract(t)

	for _, test := range []struct {
		name         string
		scheme       string
		algorithmOID string
		static       string
	}{
		{name: "SHA1", scheme: auth.TOTP1HashScheme, algorithmOID: otpHMACSHA1OID},
		{name: "SHA256", scheme: auth.TOTP256HashScheme, algorithmOID: otpHMACSHA256OID},
		{name: "SHA512", scheme: auth.TOTP512HashScheme, algorithmOID: otpHMACSHA512OID},
		{
			name:         "SHA1 and password",
			scheme:       auth.TOTP1AndPWHashScheme,
			algorithmOID: otpHMACSHA1OID,
			static:       "static-secret",
		},
		{
			name:         "SHA256 and password",
			scheme:       auth.TOTP256AndPWHashScheme,
			algorithmOID: otpHMACSHA256OID,
			static:       "static-secret",
		},
		{
			name:         "SHA512 and password",
			scheme:       auth.TOTP512AndPWHashScheme,
			algorithmOID: otpHMACSHA512OID,
			static:       "static-secret",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := append([]byte(nil), totpPasswordTestSecret...)
			if test.static != "" {
				input = append(input, '|')
				input = append(input, test.static...)
			}
			stored, err := auth.HashPassword(
				input,
				test.scheme,
				bytes.NewReader([]byte{1, 2, 3, 4}),
			)
			if err != nil {
				t.Fatalf("HashPassword(%s): %v", test.scheme, err)
			}

			openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				[]string{"totp"},
				"moduleload "+module,
				"",
				"userPassword: "+string(stored)+"\n",
			)
			defer stopOpenLDAP()

			ldapGoStore := storage.NewMemory()
			t.Cleanup(func() { _ = ldapGoStore.Close() })
			seedDirectory(t, ldapGoStore)
			seedTOTPPasswordConfiguration(t, ldapGoStore, stored, false, "")
			ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{
				RootDN:       "cn=admin,dc=example,dc=com",
				RootPassword: []byte("secret"),
			})
			defer stopLDAPGo()

			now := stableTOTPPasswordReferenceTime()
			step := now.Unix() / 30
			current := totpPasswordCredential(
				t,
				totpPasswordTestSecret,
				step,
				test.algorithmOID,
				test.static,
			)
			future := totpPasswordCredential(
				t,
				totpPasswordTestSecret,
				step+1,
				test.algorithmOID,
				test.static,
			)
			wrongStatic := current[:len(current)-1] + "0"
			if strings.HasSuffix(current, "0") {
				wrongStatic = current[:len(current)-1] + "1"
			}
			if test.static != "" {
				wrongStatic = "wrong-static" + current[len(test.static):]
			}

			openLDAPResult := exerciseTOTPPasswordReference(
				t,
				openLDAPURI,
				"uid=bob,ou=people,dc=example,dc=com",
				future,
				wrongStatic,
				current,
			)
			ldapGoResult := exerciseTOTPPasswordReference(
				t,
				"ldap://"+ldapGoAddress,
				totpPasswordUserDN,
				future,
				wrongStatic,
				current,
			)
			if openLDAPResult != ldapGoResult {
				t.Fatalf(
					"TOTP reference result differs:\nOpenLDAP: %#v\nldap-go:  %#v",
					openLDAPResult,
					ldapGoResult,
				)
			}
			want := totpPasswordReferenceResult{
				future:      ldap.LDAPResultInvalidCredentials,
				wrongLength: ldap.LDAPResultInvalidCredentials,
				wrongStatic: ldap.LDAPResultInvalidCredentials,
				current:     ldap.LDAPResultSuccess,
				replay:      ldap.LDAPResultInvalidCredentials,
			}
			if ldapGoResult != want {
				t.Fatalf("TOTP result = %#v, want %#v", ldapGoResult, want)
			}
		})
	}

	t.Run("SHA2 nested password", func(t *testing.T) {
		sha2Module := buildOpenLDAPSHA2PasswordModule(t)
		stored := []byte(
			auth.TOTP1AndPWHashScheme +
				"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ|" +
				"{SHA256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
		)
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"totp"},
			"moduleload "+module+"\nmoduleload "+sha2Module,
			"",
			"userPassword: "+string(stored)+"\n",
		)
		defer stopOpenLDAP()

		ldapGoStore := storage.NewMemory()
		t.Cleanup(func() { _ = ldapGoStore.Close() })
		seedDirectory(t, ldapGoStore)
		seedTOTPPasswordConfiguration(t, ldapGoStore, stored, false, "")
		ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{
			RootDN:       "cn=admin,dc=example,dc=com",
			RootPassword: []byte("secret"),
		})
		defer stopLDAPGo()

		credential := totpPasswordCredential(
			t,
			totpPasswordTestSecret,
			stableTOTPPasswordReferenceTime().Unix()/30,
			otpHMACSHA1OID,
			"secret",
		)
		want := [2]uint16{ldap.LDAPResultSuccess, ldap.LDAPResultInvalidCredentials}
		openLDAPCodes := bindTOTPPasswordTwice(
			t,
			openLDAPURI,
			"uid=bob,ou=people,dc=example,dc=com",
			credential,
		)
		ldapGoCodes := bindTOTPPasswordTwice(
			t,
			"ldap://"+ldapGoAddress,
			totpPasswordUserDN,
			credential,
		)
		if openLDAPCodes != want || ldapGoCodes != want {
			t.Fatalf(
				"SHA-2 nested TOTP results: OpenLDAP=%v ldap-go=%v want=%v",
				openLDAPCodes,
				ldapGoCodes,
				want,
			)
		}
	})

	t.Run("database root password", func(t *testing.T) {
		stored, err := auth.HashPassword(
			totpPasswordTestSecret,
			auth.TOTP1HashScheme,
			nil,
		)
		if err != nil {
			t.Fatalf("HashPassword(TOTP1): %v", err)
		}
		const rootDN = "cn=admin,dc=example,dc=com"
		rootEntry := "\n\ndn: " + rootDN + "\n" +
			"objectClass: person\ncn: admin\nsn: admin\n"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"totp"},
			"moduleload "+module,
			"rootpw "+string(stored),
			rootEntry,
		)
		defer stopOpenLDAP()

		ldapGoStore := storage.NewMemory()
		t.Cleanup(func() { _ = ldapGoStore.Close() })
		seedDirectory(t, ldapGoStore)
		seedTOTPPasswordConfiguration(t, ldapGoStore, []byte("ordinary"), false, "")
		if err := ldapGoStore.Update(t.Context(), func(writer storage.Writer) error {
			return writer.Put(directory.Entry{
				DN: rootDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("person")},
					{Description: "cn", Values: stringValues("admin")},
					{Description: "sn", Values: stringValues("admin")},
				},
			}, false)
		}); err != nil {
			t.Fatalf("seed ldap-go root entry: %v", err)
		}
		ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{
			RootDN:       rootDN,
			RootPassword: stored,
		})
		defer stopLDAPGo()

		now := stableTOTPPasswordReferenceTime()
		credential := totpPasswordCredential(
			t,
			totpPasswordTestSecret,
			now.Unix()/30,
			otpHMACSHA1OID,
			"",
		)
		openLDAPCodes := bindTOTPPasswordTwice(t, openLDAPURI, rootDN, credential)
		ldapGoCodes := bindTOTPPasswordTwice(
			t,
			"ldap://"+ldapGoAddress,
			rootDN,
			credential,
		)
		want := [2]uint16{ldap.LDAPResultSuccess, ldap.LDAPResultInvalidCredentials}
		if openLDAPCodes != want || ldapGoCodes != want {
			t.Fatalf(
				"root TOTP results: OpenLDAP=%v ldap-go=%v want=%v",
				openLDAPCodes,
				ldapGoCodes,
				want,
			)
		}
	})

	t.Run("previous window after old authentication", func(t *testing.T) {
		stored, err := auth.HashPassword(
			totpPasswordTestSecret,
			auth.TOTP1HashScheme,
			nil,
		)
		if err != nil {
			t.Fatalf("HashPassword(TOTP1): %v", err)
		}
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"totp"},
			"moduleload "+module,
			"",
			"userPassword: "+string(stored)+"\n",
		)
		defer stopOpenLDAP()
		ldapGoStore := storage.NewMemory()
		t.Cleanup(func() { _ = ldapGoStore.Close() })
		seedDirectory(t, ldapGoStore)
		seedTOTPPasswordConfiguration(t, ldapGoStore, stored, false, "")
		ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{
			RootDN:       "cn=admin,dc=example,dc=com",
			RootPassword: []byte("secret"),
		})
		defer stopLDAPGo()

		now := stableTOTPPasswordReferenceTime()
		step := now.Unix() / 30
		oldTimestamp := time.Unix((step-3)*30, 0).UTC().Format("20060102150405Z")
		setTOTPPasswordReferenceTimestamp(
			t,
			openLDAPURI,
			"uid=bob,ou=people,dc=example,dc=com",
			oldTimestamp,
		)
		setTOTPPasswordReferenceTimestamp(
			t,
			"ldap://"+ldapGoAddress,
			totpPasswordUserDN,
			oldTimestamp,
		)
		previous := totpPasswordCredential(
			t,
			totpPasswordTestSecret,
			step-1,
			otpHMACSHA1OID,
			"",
		)
		openLDAPCodes := bindTOTPPasswordTwice(
			t,
			openLDAPURI,
			"uid=bob,ou=people,dc=example,dc=com",
			previous,
		)
		ldapGoCodes := bindTOTPPasswordTwice(
			t,
			"ldap://"+ldapGoAddress,
			totpPasswordUserDN,
			previous,
		)
		if openLDAPCodes != ldapGoCodes ||
			ldapGoCodes != [2]uint16{ldap.LDAPResultSuccess, ldap.LDAPResultInvalidCredentials} {
			t.Fatalf(
				"previous-window results: OpenLDAP=%v ldap-go=%v",
				openLDAPCodes,
				ldapGoCodes,
			)
		}
	})

	t.Run("ordinary password records authentication timestamp", func(t *testing.T) {
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"totp"},
			"moduleload "+module,
			"",
			"userPassword: ordinary-secret\n",
		)
		defer stopOpenLDAP()

		ldapGoStore := storage.NewMemory()
		t.Cleanup(func() { _ = ldapGoStore.Close() })
		seedDirectory(t, ldapGoStore)
		seedTOTPPasswordConfiguration(
			t,
			ldapGoStore,
			[]byte("ordinary-secret"),
			false,
			"",
		)
		ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{
			RootDN:       "cn=admin,dc=example,dc=com",
			RootPassword: []byte("secret"),
		})
		defer stopLDAPGo()

		for _, server := range []struct {
			name string
			uri  string
			dn   string
		}{
			{
				name: "OpenLDAP",
				uri:  openLDAPURI,
				dn:   "uid=bob,ou=people,dc=example,dc=com",
			},
			{
				name: "ldap-go",
				uri:  "ldap://" + ldapGoAddress,
				dn:   totpPasswordUserDN,
			},
		} {
			t.Run(server.name, func(t *testing.T) {
				assertTOTPPasswordReferenceTimestampAfterBind(
					t,
					server.uri,
					server.dn,
					"ordinary-secret",
				)
			})
		}
	})

	for _, placement := range []struct {
		name         string
		globalConfig string
		overlays     []string
		frontend     bool
		duplicate    bool
	}{
		{
			name:         "frontend overlay",
			globalConfig: "moduleload " + module + "\ndatabase frontend\noverlay totp",
			frontend:     true,
		},
		{
			name:         "duplicate database overlays",
			globalConfig: "moduleload " + module,
			overlays:     []string{"totp", "totp"},
			duplicate:    true,
		},
	} {
		t.Run(placement.name, func(t *testing.T) {
			stored, err := auth.HashPassword(
				totpPasswordTestSecret,
				auth.TOTP1HashScheme,
				nil,
			)
			if err != nil {
				t.Fatalf("HashPassword(TOTP1): %v", err)
			}
			openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				placement.overlays,
				placement.globalConfig,
				"",
				"userPassword: "+string(stored)+"\n",
			)
			defer stopOpenLDAP()

			ldapGoStore := storage.NewMemory()
			t.Cleanup(func() { _ = ldapGoStore.Close() })
			seedDirectory(t, ldapGoStore)
			seedTOTPPasswordReferencePlacement(
				t,
				ldapGoStore,
				stored,
				placement.frontend,
				placement.duplicate,
			)
			ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{
				RootDN:       "cn=admin,dc=example,dc=com",
				RootPassword: []byte("secret"),
			})
			defer stopLDAPGo()

			now := stableTOTPPasswordReferenceTime()
			credential := totpPasswordCredential(
				t,
				totpPasswordTestSecret,
				now.Unix()/30,
				otpHMACSHA1OID,
				"",
			)
			openLDAPCodes := bindTOTPPasswordTwice(
				t,
				openLDAPURI,
				"uid=bob,ou=people,dc=example,dc=com",
				credential,
			)
			ldapGoCodes := bindTOTPPasswordTwice(
				t,
				"ldap://"+ldapGoAddress,
				totpPasswordUserDN,
				credential,
			)
			want := [2]uint16{
				ldap.LDAPResultSuccess,
				ldap.LDAPResultInvalidCredentials,
			}
			if openLDAPCodes != want || ldapGoCodes != want {
				t.Fatalf(
					"placement results: OpenLDAP=%v ldap-go=%v want=%v",
					openLDAPCodes,
					ldapGoCodes,
					want,
				)
			}
		})
	}
}

type totpPasswordReferenceResult struct {
	future      uint16
	wrongLength uint16
	wrongStatic uint16
	current     uint16
	replay      uint16
}

func exerciseTOTPPasswordReference(
	t *testing.T,
	uri,
	dn,
	future,
	wrongStatic,
	current string,
) totpPasswordReferenceResult {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	return totpPasswordReferenceResult{
		future:      otpLDAPResultCode(client.Bind(dn, future)),
		wrongLength: otpLDAPResultCode(client.Bind(dn, current[:len(current)-1])),
		wrongStatic: otpLDAPResultCode(client.Bind(dn, wrongStatic)),
		current:     otpLDAPResultCode(client.Bind(dn, current)),
		replay:      otpLDAPResultCode(client.Bind(dn, current)),
	}
}

func bindTOTPPasswordTwice(
	t *testing.T,
	uri,
	dn,
	credential string,
) [2]uint16 {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	return [2]uint16{
		otpLDAPResultCode(client.Bind(dn, credential)),
		otpLDAPResultCode(client.Bind(dn, credential)),
	}
}

func setTOTPPasswordReferenceTimestamp(
	t *testing.T,
	uri,
	dn,
	timestamp string,
) {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("root Bind(%s): %v", uri, err)
	}
	request := ldap.NewModifyRequest(dn, nil)
	request.Replace("authTimestamp", []string{timestamp})
	if code := otpLDAPResultCode(client.Modify(request)); code != ldap.LDAPResultConstraintViolation {
		t.Fatalf("set authTimestamp without Relax on %s = %d, want %d", uri, code, ldap.LDAPResultConstraintViolation)
	}
	request = ldap.NewModifyRequest(dn, []ldap.Control{relaxLDAPControl()})
	request.Replace("authTimestamp", []string{timestamp})
	if err := client.Modify(request); err != nil {
		t.Fatalf("set authTimestamp on %s: %v", uri, err)
	}
}

func assertTOTPPasswordReferenceTimestampAfterBind(
	t *testing.T,
	uri,
	dn,
	password string,
) {
	t.Helper()
	user, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	if err := user.Bind(dn, password); err != nil {
		user.Close()
		t.Fatalf("ordinary Bind(%s): %v", uri, err)
	}
	user.Close()

	root, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(root %s): %v", uri, err)
	}
	defer root.Close()
	if err := root.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("root Bind(%s): %v", uri, err)
	}
	values := readReferenceAttribute(t, root, dn, "authTimestamp")
	if len(values) != 1 {
		t.Fatalf("authTimestamp after ordinary Bind on %s = %q", uri, values)
	}
	if _, err := time.Parse("20060102150405Z", values[0]); err != nil {
		t.Fatalf("authTimestamp after ordinary Bind on %s = %q: %v", uri, values[0], err)
	}
}

func seedTOTPPasswordReferencePlacement(
	t *testing.T,
	store storage.Store,
	stored []byte,
	frontend,
	duplicate bool,
) {
	t.Helper()
	seedTOTPPasswordConfiguration(t, store, stored, false, "")
	if !frontend && !duplicate {
		return
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		if duplicate {
			entry := totpPasswordOverlayEntry(false)
			entry.DN = "olcOverlay={1}totp,olcDatabase={1}mdb,cn=config"
			entry.ReplaceValues("olcOverlay", stringValues("{1}totp"))
			return writer.Put(entry, false)
		}
		if err := writer.Delete(mustTOTPPasswordDN(t, totpPasswordOverlayDN)); err != nil {
			return err
		}
		if err := writer.Put(directory.Entry{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcDatabase",
				Values:      stringValues("{-1}frontend"),
			}},
		}, false); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}totp,olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}totp")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed totp placement: %v", err)
	}
}

func stableTOTPPasswordReferenceTime() time.Time {
	for {
		now := time.Now()
		if remainder := now.Unix() % 30; remainder < 20 {
			return now
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func buildOpenLDAPTOTPPasswordModule(t *testing.T) string {
	t.Helper()
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	buildRoot := os.Getenv("OPENLDAP_BUILD_WORK")
	if sourceRoot == "" || buildRoot == "" {
		t.Fatal("OPENLDAP_SOURCE and OPENLDAP_BUILD_WORK are required")
	}
	portable, err := os.ReadFile(filepath.Join(buildRoot, "include", "portable.h"))
	if err != nil {
		t.Fatalf("read OpenLDAP portable.h: %v", err)
	}
	if !bytes.Contains(portable, []byte("#define SLAPD_MODULES 1")) {
		t.Fatal("OpenLDAP reference must be rebuilt with --enable-modules=yes")
	}

	moduleRoot := filepath.Join(t.TempDir(), "totp")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatalf("create pw-totp build directory: %v", err)
	}
	sourceDir := filepath.Join(
		sourceRoot,
		"contrib",
		"slapd-modules",
		"passwd",
		"totp",
	)
	for _, name := range []string{"Makefile", "slapd-totp.c"} {
		contents, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatalf("read pw-totp %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(moduleRoot, name), contents, 0o600); err != nil {
			t.Fatalf("write pw-totp %s: %v", name, err)
		}
	}
	cppflags := os.Getenv("OPENLDAP_CPPFLAGS")
	ldflags := os.Getenv("OPENLDAP_LDFLAGS")
	command := exec.Command(
		"make",
		"-C",
		moduleRoot,
		"LDAP_SRC="+sourceRoot,
		"LDAP_BUILD="+buildRoot,
		"CPPFLAGS="+cppflags,
		"LDFLAGS="+ldflags,
		"UNIX_LIB="+strings.TrimSpace(ldflags+" -lcrypto"),
		"CC=cc",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build OpenLDAP pw-totp module: %v\n%s", err, output)
	}
	module := filepath.Join(moduleRoot, "pw-totp.la")
	if info, err := os.Stat(module); err != nil || info.IsDir() {
		t.Fatalf("pw-totp module was not built at %s", module)
	}
	return module
}

func assertOpenLDAPTOTPPasswordSourceContract(t *testing.T) {
	t.Helper()
	source := filepath.Join(
		os.Getenv("OPENLDAP_SOURCE"),
		"contrib",
		"slapd-modules",
		"passwd",
		"totp",
		"slapd-totp.c",
	)
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read pinned pw-totp source: %v", err)
	}
	for _, fragment := range []string{
		`BER_BVC("{TOTP1}")`,
		`BER_BVC("{TOTP256}")`,
		`BER_BVC("{TOTP512}")`,
		`BER_BVC("{TOTP1ANDPW}")`,
		`#define TIME_STEP`,
		`#define DIGITS`,
		`o_dont_replicate = 1`,
	} {
		if !bytes.Contains(contents, []byte(fragment)) {
			t.Fatalf("pinned pw-totp source is missing %q", fragment)
		}
	}
	if revision := os.Getenv("OPENLDAP_COMMIT"); revision != openLDAPTOTPPasswordCommit {
		t.Fatalf(
			"pw-totp reference commit = %q, want %q",
			revision,
			openLDAPTOTPPasswordCommit,
		)
	}
}
