package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	cryptargon2 "github.com/sergeymakinen/go-crypt/argon2"
)

func TestOpenLDAPArgon2HashAndVerify(t *testing.T) {
	password := []byte("argon2-secret")
	stored, err := HashPasswordOpenLDAPArgon2(
		password,
		bytes.NewReader(bytes.Repeat([]byte{0x42}, openLDAPArgon2SaltLength)),
	)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := "{ARGON2}$argon2id$v=19$m=7168,t=5,p=1$QkJCQkJCQkJCQkJCQkJCQg$"
	if !strings.HasPrefix(string(stored), wantPrefix) {
		t.Fatalf("stored ARGON2 = %q", stored)
	}
	if !VerifyPassword(stored, password) {
		t.Fatal("generated ARGON2 password did not verify")
	}
	if VerifyPassword(stored, []byte("wrong")) {
		t.Fatal("ARGON2 accepted wrong password")
	}
}

func TestOpenLDAPArgon2ImportedVariantsAndBounds(t *testing.T) {
	password := []byte("password")
	salt := base64.RawStdEncoding.EncodeToString([]byte("somesalt12345678"))
	for _, variant := range []struct {
		prefix  string
		version int
	}{
		{cryptargon2.Prefix2d, cryptargon2.Version10},
		{cryptargon2.Prefix2i, cryptargon2.Version13},
		{cryptargon2.Prefix2id, cryptargon2.Version13},
	} {
		key, err := cryptargon2.Key(
			password,
			[]byte(salt),
			32,
			3,
			1,
			&cryptargon2.CompatibilityOptions{
				Prefix:  variant.prefix,
				Version: variant.version,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		stored := fmt.Sprintf(
			"{ARGON2}%sv=%d$m=32,t=3,p=1$%s$%s",
			variant.prefix,
			variant.version,
			salt,
			base64.RawStdEncoding.EncodeToString(key),
		)
		if !VerifyPassword([]byte(stored), password) {
			t.Fatalf("valid %s v=%d password did not verify", variant.prefix, variant.version)
		}
	}
	overMemory := []byte("{ARGON2}$argon2id$v=19$m=1048576,t=1,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if VerifyPassword(overMemory, password) {
		t.Fatal("ARGON2 accepted excessive memory cost")
	}
	if VerifyPassword([]byte("{ARGON2}$argon2id$malformed"), password) {
		t.Fatal("ARGON2 accepted malformed payload")
	}
}
