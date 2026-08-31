package auth

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	yescrypt "github.com/openwall/yescrypt-go"
	cryptdes "github.com/sergeymakinen/go-crypt/des"
	cryptdesext "github.com/sergeymakinen/go-crypt/desext"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	cryptsha1 "github.com/sergeymakinen/go-crypt/sha1"
	cryptsunmd5 "github.com/sergeymakinen/go-crypt/sunmd5"
	//lint:ignore SA1019 OpenLDAP $3$ NT crypt verification requires the legacy MD4 primitive.
	"golang.org/x/crypto/md4"
)

const (
	MaxOpenLDAPCryptBSDIRounds   = 1_000_001
	MaxOpenLDAPCryptSHA1Rounds   = 1_000_000
	MaxOpenLDAPCryptSunMD5Rounds = 1_000_000
	MaxOpenLDAPCryptMemoryBytes  = 128 << 20
	MaxOpenLDAPCryptWorkUnits    = 1 << 20

	maxOpenLDAPCryptBigPassword = 128
	maxOpenLDAPCryptSaltBytes   = 64
	maxOpenLDAPCryptScryptSalt  = 86
	maxOpenLDAPCryptScryptP     = 16
)

func hashOpenLDAPExtendedCrypt(password []byte, setting string) (string, bool, error) {
	if hash, handled, err := hashOpenLDAPNationalCrypt(password, setting); handled {
		return hash, true, err
	}
	switch {
	case strings.HasPrefix(setting, "$y$"):
		hash, err := deriveOpenLDAPYescrypt(password, setting, false)
		return hash, true, err
	case strings.HasPrefix(setting, "$7$"):
		hash, err := deriveOpenLDAPScrypt(password, setting, false)
		return hash, true, err
	case strings.HasPrefix(setting, "_"):
		hash, err := deriveOpenLDAPBSDICrypt(password, setting, false)
		return hash, true, err
	case strings.HasPrefix(setting, "$sha1$"):
		hash, err := deriveOpenLDAPSHA1Crypt(password, setting, false)
		return hash, true, err
	case strings.HasPrefix(setting, "$md5"):
		hash, err := deriveOpenLDAPSunMD5(password, setting, false)
		return hash, true, err
	case strings.HasPrefix(setting, "$3$"):
		hash, err := deriveOpenLDAPNTCrypt(password, setting, false)
		return hash, true, err
	case isOpenLDAPBigCryptSetting(setting):
		hash, err := deriveOpenLDAPBigCrypt(password, setting[:2])
		return hash, true, err
	default:
		return "", false, nil
	}
}

func verifyOpenLDAPExtendedCrypt(hash string, password []byte) (bool, bool) {
	if matches, handled := verifyOpenLDAPNationalCrypt(hash, password); handled {
		return matches, true
	}
	var derived string
	var err error
	switch {
	case strings.HasPrefix(hash, "$y$"):
		derived, err = deriveOpenLDAPYescrypt(password, hash, true)
	case strings.HasPrefix(hash, "$7$"):
		derived, err = deriveOpenLDAPScrypt(password, hash, true)
	case strings.HasPrefix(hash, "_"):
		derived, err = deriveOpenLDAPBSDICrypt(password, hash, true)
	case strings.HasPrefix(hash, "$sha1$"):
		derived, err = deriveOpenLDAPSHA1Crypt(password, hash, true)
	case strings.HasPrefix(hash, "$md5"):
		derived, err = deriveOpenLDAPSunMD5(password, hash, true)
	case strings.HasPrefix(hash, "$3$"):
		derived, err = deriveOpenLDAPNTCrypt(password, hash, true)
	case isOpenLDAPBigCryptHash(hash):
		derived, err = deriveOpenLDAPBigCrypt(password, hash[:2])
	default:
		return false, false
	}
	if err != nil || len(derived) != len(hash) {
		return false, true
	}
	return subtle.ConstantTimeCompare([]byte(derived), []byte(hash)) == 1, true
}

func deriveOpenLDAPYescrypt(password []byte, value string, hash bool) (string, error) {
	parts := strings.Split(value, "$")
	wantParts := 4
	if hash {
		wantParts = 5
	}
	if len(parts) != wantParts || parts[0] != "" || parts[1] != "y" ||
		len(parts[2]) != 3 || parts[2][0] != 'j' {
		return "", errors.New("invalid yescrypt setting")
	}
	nLog, err := openLDAPCrypt64Value(parts[2][1])
	if err != nil {
		return "", errors.New("invalid yescrypt N parameter")
	}
	nLog++
	r, err := openLDAPCrypt64Value(parts[2][2])
	if err != nil {
		return "", errors.New("invalid yescrypt r parameter")
	}
	r++
	if nLog < 10 || nLog > 18 || r < 1 || r > 32 {
		return "", errors.New("unsupported yescrypt parameters")
	}
	n := uint64(1) << nLog
	if err := validateOpenLDAPMemoryHardCost(n, uint64(r), 1); err != nil {
		return "", fmt.Errorf("yescrypt: %w", err)
	}
	salt, err := decodeOpenLDAPCrypt64(parts[3])
	if err != nil || len(salt) > maxOpenLDAPCryptSaltBytes {
		return "", errors.New("invalid yescrypt salt")
	}
	clear(salt)
	if hash {
		if len(parts[4]) != 43 {
			return "", errors.New("invalid yescrypt digest")
		}
		digest, decodeErr := decodeOpenLDAPCrypt64(parts[4])
		if decodeErr != nil || len(digest) != 32 {
			clear(digest)
			return "", errors.New("invalid yescrypt digest")
		}
		clear(digest)
	}
	setting := strings.Join(parts[:4], "$")
	derived, err := yescrypt.Hash(password, []byte(setting))
	if err != nil {
		return "", err
	}
	defer clear(derived)
	return string(derived), nil
}

func deriveOpenLDAPScrypt(password []byte, value string, hash bool) (string, error) {
	if !strings.HasPrefix(value, "$7$") {
		return "", errors.New("invalid scrypt setting")
	}
	body := value[3:]
	digest := ""
	if separator := strings.IndexByte(body, '$'); separator >= 0 {
		if !hash || strings.IndexByte(body[separator+1:], '$') >= 0 {
			return "", errors.New("invalid scrypt setting")
		}
		digest = body[separator+1:]
		body = body[:separator]
	} else if hash {
		return "", errors.New("invalid scrypt hash")
	}
	if len(body) < 11 {
		return "", errors.New("invalid scrypt setting")
	}
	nLog, err := openLDAPCrypt64Value(body[0])
	if err != nil || nLog < 1 || nLog > 30 {
		return "", errors.New("invalid scrypt N parameter")
	}
	r, err := decodeOpenLDAPCryptUint30(body[1:6])
	if err != nil || r == 0 {
		return "", errors.New("invalid scrypt r parameter")
	}
	p, err := decodeOpenLDAPCryptUint30(body[6:11])
	if err != nil || p == 0 || p > maxOpenLDAPCryptScryptP {
		return "", errors.New("invalid scrypt p parameter")
	}
	n := uint64(1) << nLog
	if err := validateOpenLDAPMemoryHardCost(n, uint64(r), uint64(p)); err != nil {
		return "", fmt.Errorf("scrypt: %w", err)
	}
	saltText := body[11:]
	if len(saltText) > maxOpenLDAPCryptScryptSalt ||
		!validOpenLDAPCryptString(saltText) {
		return "", errors.New("invalid scrypt salt")
	}
	salt := []byte(saltText)
	defer clear(salt)
	if hash {
		decoded, decodeErr := decodeOpenLDAPCrypt64(digest)
		if decodeErr != nil || len(decoded) != 32 {
			clear(decoded)
			return "", errors.New("invalid scrypt digest")
		}
		clear(decoded)
	}
	key, err := yescrypt.ScryptKey(password, salt, int(n), int(r), int(p), 32)
	if err != nil {
		return "", err
	}
	defer clear(key)
	return "$7$" + body + "$" + encodeOpenLDAPCrypt64(key), nil
}

func validateOpenLDAPMemoryHardCost(n, r, p uint64) error {
	if n == 0 || r == 0 || p == 0 || n > ^uint64(0)/r {
		return errOpenLDAPCryptCostLimit
	}
	units := n * r
	if units > MaxOpenLDAPCryptMemoryBytes/128 {
		return fmt.Errorf(
			"%w: memory exceeds %d bytes",
			errOpenLDAPCryptCostLimit,
			MaxOpenLDAPCryptMemoryBytes,
		)
	}
	if units > ^uint64(0)/p || units*p > MaxOpenLDAPCryptWorkUnits {
		return fmt.Errorf(
			"%w: work factor exceeds %d",
			errOpenLDAPCryptCostLimit,
			MaxOpenLDAPCryptWorkUnits,
		)
	}
	return nil
}

func deriveOpenLDAPBSDICrypt(password []byte, value string, hash bool) (string, error) {
	if len(value) < 9 || value[0] != '_' {
		return "", errors.New("invalid BSDI crypt setting")
	}
	if hash && len(value) != 20 {
		return "", errors.New("invalid BSDI crypt hash")
	}
	setting := value[:9]
	rounds, err := decodeOpenLDAPCryptUint24(setting[1:5])
	if err != nil || rounds == 0 || rounds&1 == 0 {
		return "", errors.New("BSDI crypt rounds must be a positive odd number")
	}
	if rounds > MaxOpenLDAPCryptBSDIRounds {
		return "", fmt.Errorf(
			"%w: BSDI crypt rounds %d exceeds %d",
			errOpenLDAPCryptCostLimit,
			rounds,
			MaxOpenLDAPCryptBSDIRounds,
		)
	}
	if !validOpenLDAPCryptString(setting[5:9]) {
		return "", errors.New("invalid BSDI crypt salt")
	}
	key, err := cryptdesext.Key(password, []byte(setting[5:9]), rounds)
	if err != nil {
		return "", err
	}
	defer clear(key)
	encoded := make([]byte, 11)
	crypthash.BigEndianEncoding.Encode(encoded, key)
	defer clear(encoded)
	return setting + string(encoded), nil
}

func isOpenLDAPBigCryptSetting(setting string) bool {
	return len(setting) > 13 && setting[0] != '$' &&
		validOpenLDAPCryptString(setting[:2])
}

func isOpenLDAPBigCryptHash(hash string) bool {
	return len(hash) > 13 && len(hash) <= 178 && (len(hash)-2)%11 == 0 &&
		hash[0] != '$' && validOpenLDAPCryptString(hash)
}

func deriveOpenLDAPBigCrypt(password []byte, initialSalt string) (string, error) {
	if len(initialSalt) != 2 || !validOpenLDAPCryptString(initialSalt) {
		return "", errors.New("invalid bigcrypt salt")
	}
	if len(password) > maxOpenLDAPCryptBigPassword {
		password = password[:maxOpenLDAPCryptBigPassword]
	}
	var output strings.Builder
	output.Grow(2 + 11*((len(password)+7)/8))
	output.WriteString(initialSalt)
	salt := []byte(initialSalt)
	for offset := 0; offset < len(password); offset += 8 {
		end := min(offset+8, len(password))
		key, err := cryptdes.Key(password[offset:end], salt)
		if err != nil {
			return "", err
		}
		encoded := make([]byte, 11)
		crypthash.BigEndianEncoding.Encode(encoded, key)
		clear(key)
		output.Write(encoded)
		salt = encoded[:2]
	}
	return output.String(), nil
}

func deriveOpenLDAPSHA1Crypt(password []byte, value string, hash bool) (string, error) {
	parts := strings.Split(value, "$")
	wantParts := 4
	if hash {
		wantParts = 5
	}
	if len(parts) != wantParts || parts[0] != "" || parts[1] != "sha1" ||
		parts[2] == "" || parts[2][0] == '0' {
		return "", errors.New("invalid SHA1-crypt setting")
	}
	rounds64, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil || rounds64 < 4 {
		return "", errors.New("invalid SHA1-crypt rounds")
	}
	if rounds64 > MaxOpenLDAPCryptSHA1Rounds {
		return "", fmt.Errorf(
			"%w: SHA1-crypt rounds %d exceeds %d",
			errOpenLDAPCryptCostLimit,
			rounds64,
			MaxOpenLDAPCryptSHA1Rounds,
		)
	}
	if len(parts[3]) < 1 || len(parts[3]) > cryptsha1.MaxSaltLength ||
		!validOpenLDAPCryptString(parts[3]) {
		return "", errors.New("invalid SHA1-crypt salt")
	}
	if hash && (len(parts[4]) != 28 || !validOpenLDAPCryptString(parts[4])) {
		return "", errors.New("invalid SHA1-crypt digest")
	}
	key, err := cryptsha1.Key(password, []byte(parts[3]), uint32(rounds64))
	if err != nil {
		return "", err
	}
	defer clear(key)
	encoded := make([]byte, 28)
	crypthash.LittleEndianEncoding.Encode(encoded, key)
	defer clear(encoded)
	return strings.Join(parts[:4], "$") + "$" + string(encoded), nil
}

func deriveOpenLDAPSunMD5(password []byte, value string, hash bool) (string, error) {
	prefix := cryptsunmd5.PrefixZeroRounds
	rounds := uint64(0)
	remainder := ""
	switch {
	case strings.HasPrefix(value, cryptsunmd5.PrefixZeroRounds):
		remainder = value[len(cryptsunmd5.PrefixZeroRounds):]
	case strings.HasPrefix(value, cryptsunmd5.PrefixNonZeroRounds+"rounds="):
		prefix = cryptsunmd5.PrefixNonZeroRounds
		roundsEnd := strings.IndexByte(value[len(prefix)+len("rounds="):], '$')
		if roundsEnd < 0 {
			return "", errors.New("invalid SunMD5 rounds setting")
		}
		roundsEnd += len(prefix) + len("rounds=")
		roundsText := value[len(prefix)+len("rounds=") : roundsEnd]
		if roundsText == "" || roundsText[0] == '0' {
			return "", errors.New("invalid SunMD5 rounds")
		}
		var err error
		rounds, err = strconv.ParseUint(roundsText, 10, 32)
		if err != nil || rounds == 0 {
			return "", errors.New("invalid SunMD5 rounds")
		}
		if rounds > MaxOpenLDAPCryptSunMD5Rounds {
			return "", fmt.Errorf(
				"%w: SunMD5 rounds %d exceeds %d",
				errOpenLDAPCryptCostLimit,
				rounds,
				MaxOpenLDAPCryptSunMD5Rounds,
			)
		}
		remainder = value[roundsEnd+1:]
	default:
		return "", errors.New("invalid SunMD5 setting")
	}

	separator := false
	digest := ""
	if hash {
		i := strings.IndexByte(remainder, '$')
		if i < 1 {
			return "", errors.New("invalid SunMD5 hash")
		}
		digest = remainder[i+1:]
		remainder = remainder[:i]
		if strings.HasPrefix(digest, "$") {
			separator = true
			digest = digest[1:]
		}
		if strings.ContainsRune(digest, '$') || len(digest) != 22 ||
			!validOpenLDAPCryptString(digest) {
			return "", errors.New("invalid SunMD5 digest")
		}
	} else if strings.HasSuffix(remainder, "$") {
		separator = true
		remainder = strings.TrimSuffix(remainder, "$")
	}
	if len(remainder) < 1 || len(remainder) > cryptsunmd5.MaxSaltLength ||
		!validOpenLDAPCryptString(remainder) {
		return "", errors.New("invalid SunMD5 salt")
	}
	key, err := cryptsunmd5.Key(
		password,
		[]byte(remainder),
		uint32(rounds),
		&cryptsunmd5.CompatibilityOptions{
			Prefix:               prefix,
			DisableSaltSeparator: !separator,
		},
	)
	if err != nil {
		return "", err
	}
	defer clear(key)
	encoded := make([]byte, 22)
	crypthash.LittleEndianEncoding.Encode(encoded, key)
	defer clear(encoded)
	setting := prefix
	if rounds != 0 {
		setting += "rounds=" + strconv.FormatUint(rounds, 10) + "$"
	}
	setting += remainder + "$"
	if separator {
		setting += "$"
	}
	return setting + string(encoded), nil
}

func deriveOpenLDAPNTCrypt(password []byte, value string, hash bool) (string, error) {
	if !strings.HasPrefix(value, "$3$") {
		return "", errors.New("invalid NT crypt setting")
	}
	if hash && (len(value) != 36 || !strings.HasPrefix(value, "$3$$")) {
		return "", errors.New("invalid NT crypt hash")
	}
	encodedPassword := make([]byte, len(password)*2)
	defer clear(encodedPassword)
	for i, b := range password {
		binary.LittleEndian.PutUint16(encodedPassword[i*2:], uint16(b))
	}
	h := md4.New()
	_, _ = h.Write(encodedPassword)
	digest := h.Sum(nil)
	defer clear(digest)
	return "$3$$" + hex.EncodeToString(digest), nil
}

func openLDAPCrypt64Value(value byte) (uint64, error) {
	i := strings.IndexByte(openLDAPCryptAlphabet, value)
	if i < 0 {
		return 0, errors.New("invalid crypt base64 character")
	}
	return uint64(i), nil
}

func decodeOpenLDAPCryptUint24(value string) (uint32, error) {
	decoded, err := decodeOpenLDAPCryptUint(value, 4)
	return uint32(decoded), err
}

func decodeOpenLDAPCryptUint30(value string) (uint32, error) {
	decoded, err := decodeOpenLDAPCryptUint(value, 5)
	return uint32(decoded), err
}

func decodeOpenLDAPCryptUint(value string, length int) (uint64, error) {
	if len(value) != length {
		return 0, errors.New("invalid crypt integer length")
	}
	var decoded uint64
	for i := range length {
		part, err := openLDAPCrypt64Value(value[i])
		if err != nil {
			return 0, err
		}
		decoded |= part << (6 * i)
	}
	return decoded, nil
}

func decodeOpenLDAPCrypt64(value string) ([]byte, error) {
	decoded := make([]byte, 0, len(value)*3/4)
	var accumulator uint32
	bits := uint(0)
	for i := range len(value) {
		part, err := openLDAPCrypt64Value(value[i])
		if err != nil {
			clear(decoded)
			return nil, err
		}
		accumulator |= uint32(part) << bits
		bits += 6
		for bits >= 8 {
			decoded = append(decoded, byte(accumulator))
			accumulator >>= 8
			bits -= 8
		}
	}
	if accumulator != 0 {
		clear(decoded)
		return nil, errors.New("non-canonical crypt base64")
	}
	if encodeOpenLDAPCrypt64(decoded) != value {
		clear(decoded)
		return nil, errors.New("non-canonical crypt base64")
	}
	return decoded, nil
}

func encodeOpenLDAPCrypt64(value []byte) string {
	var encoded strings.Builder
	encoded.Grow((len(value)*8 + 5) / 6)
	var accumulator uint32
	bits := uint(0)
	for _, b := range value {
		accumulator |= uint32(b) << bits
		bits += 8
		for bits >= 6 {
			encoded.WriteByte(openLDAPCryptAlphabet[accumulator&0x3f])
			accumulator >>= 6
			bits -= 6
		}
	}
	if bits != 0 {
		encoded.WriteByte(openLDAPCryptAlphabet[accumulator&0x3f])
	}
	return encoded.String()
}
