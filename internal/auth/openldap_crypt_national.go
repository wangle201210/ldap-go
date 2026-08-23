package auth

import (
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/emmansun/gmsm/sm3"
	"github.com/tarantool/go-gostcrypto/streebog"
)

const (
	MaxOpenLDAPCryptSM3Rounds = 1_000_000

	openLDAPCryptSM3DefaultRounds = 5_000
	openLDAPCryptSM3MinimumRounds = 1_000
	openLDAPCryptSM3SaltLength    = 16
	openLDAPCryptNationalDigest   = 43
)

func hashOpenLDAPNationalCrypt(
	password []byte,
	setting string,
) (string, bool, error) {
	switch {
	case strings.HasPrefix(setting, "$sm3$"):
		derived, err := deriveOpenLDAPSM3Crypt(password, setting, false)
		return derived, true, err
	case strings.HasPrefix(setting, "$sm3y$"):
		derived, err := deriveOpenLDAPSM3Yescrypt(password, setting, false)
		return derived, true, err
	case strings.HasPrefix(setting, "$gy$"):
		derived, err := deriveOpenLDAPGOSTYescrypt(password, setting, false)
		return derived, true, err
	default:
		return "", false, nil
	}
}

func verifyOpenLDAPNationalCrypt(hash string, password []byte) (bool, bool) {
	var derived string
	var err error
	switch {
	case strings.HasPrefix(hash, "$sm3$"):
		derived, err = deriveOpenLDAPSM3Crypt(password, hash, true)
	case strings.HasPrefix(hash, "$sm3y$"):
		derived, err = deriveOpenLDAPSM3Yescrypt(password, hash, true)
	case strings.HasPrefix(hash, "$gy$"):
		derived, err = deriveOpenLDAPGOSTYescrypt(password, hash, true)
	default:
		return false, false
	}
	if err != nil || len(derived) != len(hash) {
		return false, true
	}
	return subtle.ConstantTimeCompare([]byte(derived), []byte(hash)) == 1, true
}

func deriveOpenLDAPSM3Crypt(password []byte, value string, verify bool) (string, error) {
	const prefix = "$sm3$"
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("invalid SM3-crypt setting")
	}

	remainder := value[len(prefix):]
	rounds := uint32(openLDAPCryptSM3DefaultRounds)
	explicitRounds := false
	if strings.HasPrefix(remainder, "rounds=") {
		separator := strings.IndexByte(remainder, '$')
		if separator < 0 {
			return "", errors.New("invalid SM3-crypt rounds setting")
		}
		roundsText := remainder[len("rounds="):separator]
		if roundsText == "" || roundsText[0] == '0' {
			return "", errors.New("invalid SM3-crypt rounds")
		}
		parsed, err := strconv.ParseUint(roundsText, 10, 32)
		if err != nil || parsed < openLDAPCryptSM3MinimumRounds {
			return "", errors.New("invalid SM3-crypt rounds")
		}
		if parsed > MaxOpenLDAPCryptSM3Rounds {
			return "", fmt.Errorf(
				"%w: SM3-crypt rounds %d exceeds %d",
				errOpenLDAPCryptCostLimit,
				parsed,
				MaxOpenLDAPCryptSM3Rounds,
			)
		}
		rounds = uint32(parsed)
		explicitRounds = true
		remainder = remainder[separator+1:]
	}

	salt := remainder
	digest := ""
	if verify {
		separator := strings.IndexByte(remainder, '$')
		if separator < 0 || strings.IndexByte(remainder[separator+1:], '$') >= 0 {
			return "", errors.New("invalid SM3-crypt hash")
		}
		salt = remainder[:separator]
		digest = remainder[separator+1:]
		if len(digest) != openLDAPCryptNationalDigest ||
			!validOpenLDAPCryptString(digest) {
			return "", errors.New("invalid SM3-crypt digest")
		}
	} else {
		salt = strings.TrimSuffix(salt, "$")
	}
	if len(salt) < 1 || len(salt) > openLDAPCryptSM3SaltLength ||
		!validOpenLDAPCryptString(salt) {
		return "", errors.New("invalid SM3-crypt salt")
	}

	result := sm3CryptDigest(password, []byte(salt), rounds)
	defer clear(result)
	encoded := encodeOpenLDAPSM3CryptDigest(result)
	var output strings.Builder
	output.WriteString(prefix)
	if explicitRounds {
		fmt.Fprintf(&output, "rounds=%d$", rounds)
	}
	output.WriteString(salt)
	output.WriteByte('$')
	output.WriteString(encoded)
	return output.String(), nil
}

func sm3CryptDigest(password, salt []byte, rounds uint32) []byte {
	alternate := sm3Sum(password, salt, password)
	defer clear(alternate)

	initial := sm3.New()
	_, _ = initial.Write(password)
	_, _ = initial.Write(salt)
	writeOpenLDAPCryptRecycled(initial, alternate, len(password))
	for count := len(password); count > 0; count >>= 1 {
		if count&1 != 0 {
			_, _ = initial.Write(alternate)
		} else {
			_, _ = initial.Write(password)
		}
	}
	result := initial.Sum(nil)

	pHash := sm3.New()
	for range len(password) {
		_, _ = pHash.Write(password)
	}
	pBytes := pHash.Sum(nil)
	defer clear(pBytes)

	sHash := sm3.New()
	for range 16 + int(result[0]) {
		_, _ = sHash.Write(salt)
	}
	sBytes := sHash.Sum(nil)
	defer clear(sBytes)

	for count := uint32(0); count < rounds; count++ {
		next := sm3.New()
		if count&1 != 0 {
			writeOpenLDAPCryptRecycled(next, pBytes, len(password))
		} else {
			_, _ = next.Write(result)
		}
		if count%3 != 0 {
			writeOpenLDAPCryptRecycled(next, sBytes, len(salt))
		}
		if count%7 != 0 {
			writeOpenLDAPCryptRecycled(next, pBytes, len(password))
		}
		if count&1 != 0 {
			_, _ = next.Write(result)
		} else {
			writeOpenLDAPCryptRecycled(next, pBytes, len(password))
		}
		clear(result)
		result = next.Sum(nil)
	}
	return result
}

func sm3Sum(parts ...[]byte) []byte {
	digest := sm3.New()
	for _, part := range parts {
		_, _ = digest.Write(part)
	}
	return digest.Sum(nil)
}

func writeOpenLDAPCryptRecycled(digest hash.Hash, block []byte, length int) {
	for length >= len(block) {
		_, _ = digest.Write(block)
		length -= len(block)
	}
	if length != 0 {
		_, _ = digest.Write(block[:length])
	}
}

func encodeOpenLDAPSM3CryptDigest(digest []byte) string {
	var output strings.Builder
	output.Grow(openLDAPCryptNationalDigest)
	writeOpenLDAPCrypt24 := func(b2, b1, b0 byte, count int) {
		value := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
		for range count {
			output.WriteByte(openLDAPCryptAlphabet[value&0x3f])
			value >>= 6
		}
	}
	writeOpenLDAPCrypt24(digest[0], digest[10], digest[20], 4)
	writeOpenLDAPCrypt24(digest[21], digest[1], digest[11], 4)
	writeOpenLDAPCrypt24(digest[12], digest[22], digest[2], 4)
	writeOpenLDAPCrypt24(digest[3], digest[13], digest[23], 4)
	writeOpenLDAPCrypt24(digest[24], digest[4], digest[14], 4)
	writeOpenLDAPCrypt24(digest[15], digest[25], digest[5], 4)
	writeOpenLDAPCrypt24(digest[6], digest[16], digest[26], 4)
	writeOpenLDAPCrypt24(digest[27], digest[7], digest[17], 4)
	writeOpenLDAPCrypt24(digest[18], digest[28], digest[8], 4)
	writeOpenLDAPCrypt24(digest[9], digest[19], digest[29], 4)
	writeOpenLDAPCrypt24(0, digest[31], digest[30], 3)
	return output.String()
}

func deriveOpenLDAPSM3Yescrypt(password []byte, value string, verify bool) (string, error) {
	setting, yescryptDigest, err := deriveOpenLDAPNationalYescryptBase(
		password,
		value,
		"sm3y",
		verify,
	)
	if err != nil {
		return "", err
	}
	defer clear(yescryptDigest)

	passwordHash := sm3.Sum(password)
	defer clear(passwordHash[:])
	// libxcrypt v4.5.x exposes the sm3_hmac(data, key) argument order in
	// this format. Keep that wire-compatible behavior; the fixed vectors
	// are authoritative for stored hashes.
	innerMessageLength := len(setting) + 1 - (len("$sm3y$") - len("$y$"))
	inner := openLDAPCryptHMAC(sm3.New, []byte(setting[:innerMessageLength]), passwordHash[:])
	defer clear(inner)
	output := openLDAPCryptHMAC(sm3.New, yescryptDigest, inner)
	defer clear(output)
	return setting + "$" + encodeOpenLDAPCrypt64(output), nil
}

func deriveOpenLDAPGOSTYescrypt(password []byte, value string, verify bool) (string, error) {
	setting, yescryptDigest, err := deriveOpenLDAPNationalYescryptBase(
		password,
		value,
		"gy",
		verify,
	)
	if err != nil {
		return "", err
	}
	defer clear(yescryptDigest)

	passwordHash := streebog.Sum256(password)
	defer clear(passwordHash[:])
	innerMessageLength := len(setting) + 1 - (len("$gy$") - len("$y$"))
	inner := openLDAPCryptHMAC(
		streebog.New256,
		passwordHash[:],
		[]byte(setting[:innerMessageLength]),
	)
	defer clear(inner)
	output := openLDAPCryptHMAC(streebog.New256, inner, yescryptDigest)
	defer clear(output)
	return setting + "$" + encodeOpenLDAPCrypt64(output), nil
}

func deriveOpenLDAPNationalYescryptBase(
	password []byte,
	value, identifier string,
	verify bool,
) (string, []byte, error) {
	prefix := "$" + identifier + "$"
	if !strings.HasPrefix(value, prefix) {
		return "", nil, fmt.Errorf("invalid %s setting", identifier)
	}
	parts := strings.Split(value, "$")
	wantParts := 4
	if verify {
		wantParts = 5
	}
	if len(parts) != wantParts || parts[0] != "" || parts[1] != identifier {
		return "", nil, fmt.Errorf("invalid %s setting", identifier)
	}
	if verify {
		if len(parts[4]) != openLDAPCryptNationalDigest {
			return "", nil, fmt.Errorf("invalid %s digest", identifier)
		}
		decoded, err := decodeOpenLDAPCrypt64(parts[4])
		if err != nil || len(decoded) != 32 {
			clear(decoded)
			return "", nil, fmt.Errorf("invalid %s digest", identifier)
		}
		clear(decoded)
	}

	setting := prefix + parts[2] + "$" + parts[3]
	yescryptSetting := "$y$" + parts[2] + "$" + parts[3]
	derived, err := deriveOpenLDAPYescrypt(password, yescryptSetting, false)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", identifier, err)
	}
	derivedParts := strings.Split(derived, "$")
	if len(derivedParts) != 5 || derivedParts[1] != "y" ||
		derivedParts[2] != parts[2] || derivedParts[3] != parts[3] {
		return "", nil, fmt.Errorf("invalid %s yescrypt result", identifier)
	}
	yescryptDigest, err := decodeOpenLDAPCrypt64(derivedParts[4])
	if err != nil || len(yescryptDigest) != 32 {
		clear(yescryptDigest)
		return "", nil, fmt.Errorf("invalid %s yescrypt digest", identifier)
	}
	return setting, yescryptDigest, nil
}

func openLDAPCryptHMAC(newHash func() hash.Hash, key, message []byte) []byte {
	digest := hmac.New(newHash, key)
	_, _ = digest.Write(message)
	return digest.Sum(nil)
}
