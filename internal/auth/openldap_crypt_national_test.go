package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestOpenLDAPCryptNationalKnownVectors(t *testing.T) {
	t.Parallel()

	// Fixed answers from libxcrypt v4.5.2 test/ka-table.inc.
	tests := []struct {
		name, password, format, entropy, want string
	}{
		{
			name: "SM3 crypt", password: "abc",
			format:  "$sm3$rounds=1000$%.10s",
			entropy: "saltstring",
			want:    "{CRYPT}$sm3$rounds=1000$saltstring$rA2ewUHqiQH5Le9o318IWjgsADyZCgfFXofbx1T1NCD",
		},
		{
			name: "SM3 yescrypt", password: "abc",
			format:  "$sm3y$j75$%.7s",
			entropy: ".......",
			want:    "{CRYPT}$sm3y$j75$.......$duiiYQVhOT63KI.mAoLYbyaDvBu8kRypgtoCouFp3r8",
		},
		{
			name: "GOST yescrypt", password: "abc",
			format:  "$gy$j75$%.7s",
			entropy: ".......",
			want:    "{CRYPT}$gy$j75$.......$XH2YP.u9tPw6ObDCXTRJiUfyrAEZ/TGIF0CjnxNW3h/",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stored, err := HashPasswordOpenLDAPCrypt(
				[]byte(test.password), test.format,
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

func TestOpenLDAPCryptNationalLimitsAndUnknownFormats(t *testing.T) {
	for _, test := range []struct{ name, format, want string }{
		{"SM3 rounds", "$sm3$rounds=1000001$%.8s", "SM3-crypt rounds 1000001 exceeds 1000000"},
		{"SM3 yescrypt memory", "$sm3y$jDT$%.7s", "memory exceeds"},
		{"GOST yescrypt memory", "$gy$jDT$%.7s", "memory exceeds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := HashPasswordOpenLDAPCrypt(
				[]byte("password"), test.format,
				bytes.NewReader(make([]byte, openLDAPCryptEntropyLength)),
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("HashPasswordOpenLDAPCrypt() error = %v, want %q", err, test.want)
			}
		})
	}

	for _, stored := range []string{
		"{CRYPT}$sm3$rounds=999$abcd$...........................................",
		"{CRYPT}$sm3y$j75$.......$invalid",
		"{CRYPT}$gy$j75$.......$invalid",
		"{CRYPT}$gost$rounds=1000$salt$digest",
		"{CRYPT}$sm3gost$j75$salt$digest",
	} {
		if VerifyPassword([]byte(stored), []byte("password")) {
			t.Fatalf("VerifyPassword(%q) accepted an invalid or unknown format", stored)
		}
	}
}
