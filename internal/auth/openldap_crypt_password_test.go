package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestOpenLDAPCryptKnownVectors(t *testing.T) {
	t.Parallel()

	const password = "password"
	tests := []struct {
		name    string
		format  string
		entropy string
		want    string
		wrong   string
	}{
		{
			name:    "traditional DES",
			format:  "%.2s",
			entropy: "aa",
			want:    "{CRYPT}aajfMKNH1hTm2",
			wrong:   "passwore",
		},
		{
			name:    "MD5 crypt",
			format:  "$1$%.8s",
			entropy: "12345678",
			want:    "{CRYPT}$1$12345678$o2n/JiO/h5VviOInWJ4OQ/",
			wrong:   "wrong",
		},
		{
			name:    "bcrypt 2a",
			format:  "$2a$05$%.22s",
			entropy: "abcdefghijklmnopqrstuu",
			want:    "{CRYPT}$2a$05$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu",
			wrong:   "wrong",
		},
		{
			name:    "bcrypt 2b",
			format:  "$2b$05$%.22s",
			entropy: "abcdefghijklmnopqrstuu",
			want:    "{CRYPT}$2b$05$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu",
			wrong:   "wrong",
		},
		{
			name:    "bcrypt 2y",
			format:  "$2y$05$%.22s",
			entropy: "abcdefghijklmnopqrstuu",
			want:    "{CRYPT}$2y$05$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu",
			wrong:   "wrong",
		},
		{
			name:    "SHA256 crypt",
			format:  "$5$%.16s",
			entropy: "1234567890abcdef",
			want:    "{CRYPT}$5$1234567890abcdef$Y9E1oV2b5rfo0XbJievQAAPfdOUEfVNWacVfdrP0bo4",
			wrong:   "wrong",
		},
		{
			name:    "SHA512 crypt",
			format:  "$6$%.16s",
			entropy: "1234567890abcdef",
			want:    "{CRYPT}$6$1234567890abcdef$CBFXtqpRR1ddYz1RnbP5n/T3SopKJ/m5cWFMZimwP60dam5WZuLumvWttgtCq/QBTxGOp9.Ts3KepQ8O.RuyL/",
			wrong:   "wrong",
		},
		{
			name:    "SHA256 explicit rounds",
			format:  "$5$rounds=1000$%.16s",
			entropy: "1234567890abcdef",
			want:    "{CRYPT}$5$rounds=1000$1234567890abcdef$9J6rZiT1NJtPaoYn3hEgLDdIx6LIoRLd5PLurUfdKED",
			wrong:   "wrong",
		},
		{
			name:    "SHA512 explicit rounds",
			format:  "$6$rounds=1000$%.16s",
			entropy: "1234567890abcdef",
			want:    "{CRYPT}$6$rounds=1000$1234567890abcdef$pUr3qusS1J8r3cWpsPRKP91CCJzO.MrNbH5orrmdy8mXd4/r4UnXjKIDpK8fk0tgvt82XBzP6XFB8gpD/RtnR/",
			wrong:   "wrong",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			random := openLDAPCryptVectorRandom(t, test.entropy)
			stored, err := HashPasswordOpenLDAPCrypt(
				[]byte(password),
				test.format,
				bytes.NewReader(random),
			)
			if err != nil {
				t.Fatalf("HashPasswordOpenLDAPCrypt(): %v", err)
			}
			if string(stored) != test.want {
				t.Fatalf("HashPasswordOpenLDAPCrypt() = %q, want %q", stored, test.want)
			}
			if !VerifyPassword(stored, []byte(password)) {
				t.Fatal("VerifyPassword() rejected the matching password")
			}
			if VerifyPassword(stored, []byte(test.wrong)) {
				t.Fatal("VerifyPassword() accepted a different password")
			}
		})
	}
}

func TestOpenLDAPCryptCompatibilityAndLimits(t *testing.T) {
	t.Parallel()

	if !VerifyPassword([]byte("{CRYPT}aajfMKNH1hTm2"), []byte("password-and-ignored")) {
		t.Fatal("traditional DES did not apply the crypt(3) eight-byte password limit")
	}
	for _, stored := range []string{
		"{CRYPT}$y$j9T$salt$hash",
		"{CRYPT}$7$salt$hash",
		"{CRYPT}$2b$17$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu",
		"{CRYPT}$6$rounds=1000001$1234567890abcdef$" + strings.Repeat(".", 86),
		"{CRYPT}$1$toolongsalt$" + strings.Repeat(".", 22),
	} {
		if VerifyPassword([]byte(stored), []byte("password")) {
			t.Fatalf("VerifyPassword(%q) accepted an unsupported or excessive hash", stored)
		}
	}
	if VerifyPassword(
		[]byte("{CRYPT}$2b$05$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu"),
		bytes.Repeat([]byte{'p'}, maxOpenLDAPCryptBcryptPassword+1),
	) {
		t.Fatal("VerifyPassword() accepted an oversized bcrypt input")
	}
	if VerifyPassword(
		[]byte("{CRYPT}$2b$05$abcdefghijklmnopqrstuzWG29KuyeAicPCJODk1zjyGvyQUU2awu"),
		[]byte("password"),
	) {
		t.Fatal("VerifyPassword() accepted a non-canonical bcrypt salt")
	}
	generated, err := HashPasswordOpenLDAPCrypt(
		[]byte("password"),
		"$2b$05$%.22s",
		bytes.NewReader(openLDAPCryptVectorRandom(t, "abcdefghijklmnopqrstuz")),
	)
	if err != nil || string(generated) !=
		"{CRYPT}$2b$05$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu" {
		t.Fatalf("bcrypt salt normalization = %q, %v", generated, err)
	}

	for _, test := range []struct {
		name   string
		format string
		want   string
	}{
		{name: "malformed scrypt", format: "$7$%.16s", want: "invalid scrypt N parameter"},
		{name: "bcrypt cost", format: "$2b$17$%.22s", want: "exceeds 16"},
		{name: "SHA rounds", format: "$6$rounds=1000001$%.8s", want: "exceeds 1000000"},
		{name: "conversion", format: "%x", want: "only supports"},
		{name: "multiple entropy", format: "%.2s%.2s", want: "exactly one conversion"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := HashPasswordOpenLDAPCrypt(
				[]byte("password"),
				test.format,
				bytes.NewReader(make([]byte, openLDAPCryptEntropyLength)),
			); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("HashPasswordOpenLDAPCrypt() error = %v, want %q", err, test.want)
			}
		})
	}
	if _, err := HashPasswordOpenLDAPCrypt(
		bytes.Repeat([]byte{'p'}, MaxOpenLDAPCryptPasswordLength+1),
		"%.2s",
		nil,
	); err == nil {
		t.Fatal("HashPasswordOpenLDAPCrypt() accepted an oversized password")
	}
	if _, err := HashPasswordOpenLDAPCrypt([]byte{'p', 0}, "%.2s", nil); err == nil {
		t.Fatal("HashPasswordOpenLDAPCrypt() accepted a NUL password")
	}
	if _, err := HashPasswordOpenLDAPCrypt(
		[]byte("password"),
		"%.2s",
		errorReader{},
	); err == nil || !strings.Contains(err.Error(), "random source failed") {
		t.Fatalf("HashPasswordOpenLDAPCrypt() random error = %v", err)
	}
}

func TestOpenLDAPCryptLinuxLibxcryptVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		format   string
		entropy  string
		want     string
	}{
		{
			name:     "yescrypt",
			password: "abc",
			format:   "$y$j75$%.7s",
			entropy:  ".......",
			want:     "{CRYPT}$y$j75$.......$stbr2M6i8w/SU36N/.i6VVEHCMYG2OkDpj/I1wKYZC4",
		},
		{
			name:     "scrypt",
			password: "abc",
			format:   "$7$66..../....%.14s",
			entropy:  "SodiumChloride",
			want:     "{CRYPT}$7$66..../....SodiumChloride$WpfVhZgVj63.RiL2fAQZsLyYNROrrN67Wlo8QJ5bI/A",
		},
		{
			name:     "BSDI extended DES",
			password: "abc",
			format:   "_B...%.4s",
			entropy:  "CCCC",
			want:     "{CRYPT}_B...CCCCqx0iPZT5wZ.",
		},
		{
			name:     "bigcrypt",
			password: "alexander",
			format:   "%.2s..............",
			entropy:  "ab",
			want:     "{CRYPT}ab76vmlPVRy5Q2/bWVChp3m.",
		},
		{
			name:     "SHA1 crypt",
			password: "abc",
			format:   "$sha1$12$%.16s",
			entropy:  "GGXpNqoJvglVTkGU",
			want:     "{CRYPT}$sha1$12$GGXpNqoJvglVTkGU$I2kBSbaKuC5BRdOKHDkuhGyZrkxV",
		},
		{
			name:     "SunMD5",
			password: "abc",
			format:   "$md5,rounds=12$%.8s",
			entropy:  "9ZLwtuTO",
			want:     "{CRYPT}$md5,rounds=12$9ZLwtuTO$My0RfHdMxCWOibFsKw0990",
		},
		{
			name:     "SunMD5 separator compatibility",
			password: "abc",
			format:   "$md5,rounds=12$%.8s$",
			entropy:  "9ZLwtuTO",
			want:     "{CRYPT}$md5,rounds=12$9ZLwtuTO$$3u/OIHOy0UMiMfEiW92HL/",
		},
		{
			name:     "NT",
			password: "abc",
			format:   "",
			want:     "{CRYPT}$3$$e0fba38268d0ec66ef1cb452d5885e53",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.format == "" {
				if !VerifyPassword([]byte(test.want), []byte(test.password)) {
					t.Fatal("VerifyPassword() rejected the imported unsalted hash")
				}
				return
			}
			stored, err := HashPasswordOpenLDAPCrypt(
				[]byte(test.password),
				test.format,
				bytes.NewReader(openLDAPCryptVectorRandom(t, test.entropy)),
			)
			if err != nil {
				t.Fatalf("HashPasswordOpenLDAPCrypt(): %v", err)
			}
			if string(stored) != test.want {
				t.Fatalf("HashPasswordOpenLDAPCrypt() = %q, want %q", stored, test.want)
			}
			if !VerifyPassword(stored, []byte(test.password)) {
				t.Fatal("VerifyPassword() rejected the matching password")
			}
			if VerifyPassword(stored, []byte(test.password+"-wrong")) {
				t.Fatal("VerifyPassword() accepted a different password")
			}
		})
	}
}

func TestOpenLDAPCryptExtendedCostLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setting string
		want    string
	}{
		{name: "yescrypt memory", setting: "$y$jDT$%.7s", want: "memory exceeds"},
		{name: "scrypt memory", setting: "$7$H6..../....%.14s", want: "memory exceeds"},
		{name: "BSDI rounds", setting: "_zzzz%.4s", want: "rounds"},
		{name: "SHA1 rounds", setting: "$sha1$1000001$%.4s", want: "exceeds"},
		{name: "SunMD5 rounds", setting: "$md5,rounds=1000001$%.8s", want: "exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := HashPasswordOpenLDAPCrypt(
				[]byte("password"),
				test.setting,
				bytes.NewReader(make([]byte, openLDAPCryptEntropyLength)),
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("HashPasswordOpenLDAPCrypt() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRenderOpenLDAPCryptSaltFormatControlledPrintfSubset(t *testing.T) {
	t.Parallel()

	entropy := []byte("abcdefghijklmnopqrstuvwxyz12345")
	for _, test := range []struct {
		format string
		want   string
	}{
		{format: "x%.4s%%", want: "xabcd%"},
		{format: "%8.4s", want: "    abcd"},
		{format: "%-8.4s", want: "abcd    "},
		{format: "%.0sOK", want: "OK"},
	} {
		got, err := renderOpenLDAPCryptSaltFormat(test.format, entropy)
		if err != nil || got != test.want {
			t.Errorf("renderOpenLDAPCryptSaltFormat(%q) = %q, %v; want %q", test.format, got, err, test.want)
		}
	}
	for _, format := range []string{"fixed", "%n", "%*s", "%s%s", "%32s", "%"} {
		if _, err := renderOpenLDAPCryptSaltFormat(format, entropy); err == nil {
			t.Errorf("renderOpenLDAPCryptSaltFormat(%q) accepted an unsafe format", format)
		}
	}
}

func TestOpenLDAPCryptSafeDefaultAndResourceController(t *testing.T) {
	stored, err := HashPassword(
		[]byte("password-longer-than-eight-bytes"),
		OpenLDAPCryptHashScheme,
		bytes.NewReader(openLDAPCryptVectorRandom(t, "1234567890abcdef")),
	)
	if err != nil {
		t.Fatalf("HashPassword({CRYPT}): %v", err)
	}
	if !strings.HasPrefix(string(stored), "{CRYPT}$6$rounds=100000$") {
		t.Fatalf("default {CRYPT} hash = %q, want SHA-512-crypt", stored)
	}
	if VerifyPassword(stored, []byte("password")) {
		t.Fatal("safe default ignored the password suffix after eight bytes")
	}

	controller := openLDAPCryptResourceController{
		maximumConcurrent: 2,
		maximumMemory:     128,
	}
	releaseFirst, ok := controller.tryAcquire(64)
	if !ok {
		t.Fatal("first resource reservation was rejected")
	}
	releaseSecond, ok := controller.tryAcquire(64)
	if !ok {
		t.Fatal("second resource reservation was rejected")
	}
	if release, acquired := controller.tryAcquire(1); acquired {
		release()
		t.Fatal("controller exceeded its concurrency and memory budget")
	}
	releaseFirst()
	if release, acquired := controller.tryAcquire(65); acquired {
		release()
		t.Fatal("controller exceeded its memory budget")
	}
	releaseSecond()
	if release, acquired := controller.tryAcquire(128); !acquired {
		t.Fatal("released resource budget was not reusable")
	} else {
		release()
		release()
	}
}

func openLDAPCryptVectorRandom(t *testing.T, entropy string) []byte {
	t.Helper()
	if len(entropy) > openLDAPCryptEntropyLength {
		t.Fatalf("test entropy is too long: %d", len(entropy))
	}
	random := make([]byte, openLDAPCryptEntropyLength)
	for i := range entropy {
		index := strings.IndexByte(openLDAPCryptAlphabet, entropy[i])
		if index < 0 {
			t.Fatalf("invalid test entropy character %q", entropy[i])
		}
		random[i] = byte(index)
	}
	return random
}
