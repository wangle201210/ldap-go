package auth

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"testing"
)

func TestVerifyPassword(t *testing.T) {
	t.Parallel()

	password := []byte("correct horse battery staple")
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	sha := sha1.Sum(password)
	sshaInput := append(append([]byte(nil), password...), salt...)
	ssha := sha1.Sum(sshaInput)
	md := md5.Sum(password)
	smdInput := append(append([]byte(nil), password...), salt...)
	smd := md5.Sum(smdInput)

	tests := []struct {
		name   string
		stored []byte
		want   bool
	}{
		{name: "plain", stored: password, want: true},
		{name: "cleartext", stored: append([]byte("{CLEARTEXT}"), password...), want: true},
		{name: "sha", stored: encoded("{SHA}", sha[:]), want: true},
		{name: "ssha", stored: encoded("{SSHA}", append(ssha[:], salt...)), want: true},
		{name: "md5", stored: encoded("{MD5}", md[:]), want: true},
		{name: "smd5", stored: encoded("{SMD5}", append(smd[:], salt...)), want: true},
		{name: "unknown scheme", stored: []byte("{ARGON2}value"), want: false},
		{name: "empty", stored: nil, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := VerifyPassword(test.stored, password); got != test.want {
				t.Fatalf("VerifyPassword() = %v, want %v", got, test.want)
			}
			if len(test.stored) > 0 && VerifyPassword(test.stored, []byte("wrong")) {
				t.Fatal("VerifyPassword() accepted an incorrect password")
			}
		})
	}
}

func encoded(prefix string, value []byte) []byte {
	return []byte(prefix + base64.StdEncoding.EncodeToString(value))
}
