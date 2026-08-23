package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	cryptbcrypt "github.com/sergeymakinen/go-crypt/bcrypt"
	cryptdes "github.com/sergeymakinen/go-crypt/des"
	crypthash "github.com/sergeymakinen/go-crypt/hash"
	cryptmd5 "github.com/sergeymakinen/go-crypt/md5"
	cryptsha256 "github.com/sergeymakinen/go-crypt/sha256"
	cryptsha512 "github.com/sergeymakinen/go-crypt/sha512"
)

const (
	OpenLDAPCryptHashScheme = "{CRYPT}"
	// DefaultOpenLDAPCryptSaltFormat is intentionally stronger than the
	// traditional two-character DES setting. Existing DES hashes remain
	// verifiable, but newly generated server passwords use SHA-512-crypt.
	DefaultOpenLDAPCryptSaltFormat = "$6$rounds=100000$%.16s"
	MaxOpenLDAPCryptPasswordLength = 4096
	MaxOpenLDAPCryptBcryptCost     = 16
	MaxOpenLDAPCryptSHA2Rounds     = 1_000_000
	openLDAPCryptEntropyLength     = 31
	maxOpenLDAPCryptSaltFormatSize = 64
	maxOpenLDAPCryptSettingSize    = 128
	maxOpenLDAPCryptHashSize       = 256
	maxOpenLDAPCryptBcryptPassword = 72
	openLDAPCryptAlphabet          = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	openLDAPCryptBcryptEncodedSize = 31
	openLDAPCryptDESPasswordLength = 8
)

var (
	errOpenLDAPCryptUnsupported = errors.New("unsupported crypt hash")
	errOpenLDAPCryptCostLimit   = errors.New("crypt cost exceeds configured limit")
)

type openLDAPCryptKind uint8

const (
	openLDAPCryptDES openLDAPCryptKind = iota + 1
	openLDAPCryptMD5
	openLDAPCryptBcrypt
	openLDAPCryptSHA256
	openLDAPCryptSHA512
)

type openLDAPCryptParameters struct {
	kind           openLDAPCryptKind
	prefix         string
	salt           []byte
	cost           uint8
	rounds         uint32
	explicitRounds bool
	digest         []byte
}

// HashPasswordOpenLDAPCrypt creates an OpenLDAP {CRYPT} value without calling
// crypt(3). saltFormat accepts the portable slappasswd -c forms used by DES,
// MD5-crypt, bcrypt, SHA-256-crypt, and SHA-512-crypt.
func HashPasswordOpenLDAPCrypt(
	password []byte,
	saltFormat string,
	random io.Reader,
) ([]byte, error) {
	if err := validateOpenLDAPCryptPassword(password); err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}

	entropy := make([]byte, openLDAPCryptEntropyLength)
	defer clear(entropy)
	if _, err := io.ReadFull(random, entropy); err != nil {
		return nil, fmt.Errorf("generate crypt salt: %w", err)
	}
	for i := range entropy {
		entropy[i] = openLDAPCryptAlphabet[int(entropy[i])%len(openLDAPCryptAlphabet)]
	}
	setting, err := renderOpenLDAPCryptSaltFormat(saltFormat, entropy)
	if err != nil {
		return nil, err
	}
	release, err := acquireOpenLDAPCryptResources(setting)
	if err != nil {
		return nil, err
	}
	defer release()
	if encoded, handled, err := hashOpenLDAPExtendedCrypt(password, setting); handled {
		if err != nil {
			return nil, fmt.Errorf("generate crypt password: %w", err)
		}
		return []byte(OpenLDAPCryptHashScheme + encoded), nil
	}
	params, err := parseOpenLDAPCryptSetting(setting)
	if err != nil {
		return nil, err
	}
	if params.kind == openLDAPCryptBcrypt && len(password) > maxOpenLDAPCryptBcryptPassword {
		return nil, fmt.Errorf(
			"bcrypt password length must not exceed %d bytes",
			maxOpenLDAPCryptBcryptPassword,
		)
	}

	digest, err := deriveOpenLDAPCryptDigest(params, password)
	if err != nil {
		return nil, fmt.Errorf("generate crypt password: %w", err)
	}
	defer clear(digest)
	encoded := encodeOpenLDAPCryptHash(params, digest)
	return []byte(OpenLDAPCryptHashScheme + encoded), nil
}

func verifyOpenLDAPCrypt(payload, supplied []byte) bool {
	if len(payload) == 0 || len(payload) > maxOpenLDAPCryptHashSize ||
		validateOpenLDAPCryptPassword(supplied) != nil {
		return false
	}
	release, err := acquireOpenLDAPCryptResources(string(payload))
	if err != nil {
		return false
	}
	defer release()
	if matches, handled := verifyOpenLDAPExtendedCrypt(string(payload), supplied); handled {
		return matches
	}
	params, err := parseOpenLDAPCryptHash(string(payload))
	if err != nil {
		return false
	}
	if params.kind == openLDAPCryptBcrypt && len(supplied) > maxOpenLDAPCryptBcryptPassword {
		return false
	}
	digest, err := deriveOpenLDAPCryptDigest(params, supplied)
	if err != nil {
		return false
	}
	defer clear(digest)
	return subtle.ConstantTimeCompare(digest, params.digest) == 1
}

func validateOpenLDAPCryptPassword(password []byte) error {
	if len(password) == 0 {
		return errors.New("password must not be empty")
	}
	if len(password) > MaxOpenLDAPCryptPasswordLength {
		return fmt.Errorf(
			"crypt password length must not exceed %d bytes",
			MaxOpenLDAPCryptPasswordLength,
		)
	}
	if bytes.IndexByte(password, 0) >= 0 {
		return errors.New("crypt password must not contain NUL")
	}
	return nil
}

func renderOpenLDAPCryptSaltFormat(format string, entropy []byte) (string, error) {
	if format == "" {
		return "", errors.New("crypt salt format must not be empty")
	}
	if len(format) > maxOpenLDAPCryptSaltFormatSize {
		return "", fmt.Errorf(
			"crypt salt format must not exceed %d bytes",
			maxOpenLDAPCryptSaltFormatSize,
		)
	}
	var output strings.Builder
	conversions := 0
	for i := 0; i < len(format); {
		if format[i] < 0x20 || format[i] > 0x7e {
			return "", errors.New("crypt salt format must contain printable ASCII")
		}
		if format[i] != '%' {
			output.WriteByte(format[i])
			i++
			continue
		}
		i++
		if i == len(format) {
			return "", errors.New("crypt salt format has an incomplete conversion")
		}
		if format[i] == '%' {
			output.WriteByte('%')
			i++
			continue
		}
		leftAligned := false
		if format[i] == '-' {
			leftAligned = true
			i++
			if i == len(format) {
				return "", errors.New("crypt salt format has an incomplete conversion")
			}
		}
		width := 0
		for i < len(format) && format[i] >= '0' && format[i] <= '9' {
			width = width*10 + int(format[i]-'0')
			if width > openLDAPCryptEntropyLength {
				return "", fmt.Errorf(
					"crypt salt width must not exceed %d",
					openLDAPCryptEntropyLength,
				)
			}
			i++
		}
		if i == len(format) {
			return "", errors.New("crypt salt format has an incomplete conversion")
		}
		precision := len(entropy)
		if format[i] == '.' {
			i++
			start := i
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
			if start == i {
				return "", errors.New("crypt salt precision is missing")
			}
			parsed, err := strconv.Atoi(format[start:i])
			if err != nil || parsed < 0 || parsed > len(entropy) {
				return "", fmt.Errorf(
					"crypt salt precision must be between 0 and %d",
					len(entropy),
				)
			}
			precision = parsed
		}
		if i == len(format) || format[i] != 's' {
			return "", errors.New(
				"crypt salt format only supports %% and one %[width][.precision]s conversion",
			)
		}
		i++
		conversions++
		if conversions > 1 {
			return "", errors.New("crypt salt format must contain exactly one conversion")
		}
		padding := width - precision
		if padding < 0 {
			padding = 0
		}
		if !leftAligned {
			for range padding {
				output.WriteByte(' ')
			}
		}
		output.Write(entropy[:precision])
		if leftAligned {
			for range padding {
				output.WriteByte(' ')
			}
		}
	}
	if output.Len() > maxOpenLDAPCryptSettingSize {
		return "", fmt.Errorf(
			"formatted crypt salt must not exceed %d bytes",
			maxOpenLDAPCryptSettingSize,
		)
	}
	if conversions != 1 {
		return "", errors.New("crypt salt format must contain exactly one conversion")
	}
	return output.String(), nil
}

// ValidateOpenLDAPCryptSaltFormat validates the controlled printf subset used
// by olcPasswordCryptSaltFormat without running a password derivation.
func ValidateOpenLDAPCryptSaltFormat(format string) error {
	entropy := make([]byte, openLDAPCryptEntropyLength)
	for index := range entropy {
		entropy[index] = '.'
	}
	defer clear(entropy)
	setting, err := renderOpenLDAPCryptSaltFormat(format, entropy)
	if err != nil {
		return err
	}
	if !recognizedOpenLDAPCryptSetting(setting) {
		return fmt.Errorf("%w: setting %q", errOpenLDAPCryptUnsupported, setting)
	}
	return nil
}

func parseOpenLDAPCryptSetting(setting string) (openLDAPCryptParameters, error) {
	if len(setting) == 2 && validOpenLDAPCryptString(setting) {
		return openLDAPCryptParameters{
			kind: openLDAPCryptDES,
			salt: []byte(setting),
		}, nil
	}
	if strings.HasPrefix(setting, "$y$") {
		return openLDAPCryptParameters{}, fmt.Errorf(
			"%w: yescrypt is not supported",
			errOpenLDAPCryptUnsupported,
		)
	}
	if strings.HasPrefix(setting, "$1$") {
		salt := strings.TrimSuffix(strings.TrimPrefix(setting, "$1$"), "$")
		if len(salt) > cryptmd5.MaxSaltLength || !validOpenLDAPCryptString(salt) {
			return openLDAPCryptParameters{}, errors.New("invalid MD5-crypt salt")
		}
		return openLDAPCryptParameters{
			kind:   openLDAPCryptMD5,
			prefix: cryptmd5.Prefix,
			salt:   []byte(salt),
		}, nil
	}
	if strings.HasPrefix(setting, "$2") {
		return parseOpenLDAPCryptBcryptSetting(setting)
	}
	if strings.HasPrefix(setting, "$5$") {
		return parseOpenLDAPCryptSHA2Setting(setting, openLDAPCryptSHA256)
	}
	if strings.HasPrefix(setting, "$6$") {
		return parseOpenLDAPCryptSHA2Setting(setting, openLDAPCryptSHA512)
	}
	return openLDAPCryptParameters{}, fmt.Errorf(
		"%w: setting %q",
		errOpenLDAPCryptUnsupported,
		setting,
	)
}

func parseOpenLDAPCryptBcryptSetting(setting string) (openLDAPCryptParameters, error) {
	if len(setting) != 29 || setting[0] != '$' || setting[1] != '2' ||
		(setting[2] != 'a' && setting[2] != 'b' && setting[2] != 'y') ||
		setting[3] != '$' || setting[6] != '$' {
		return openLDAPCryptParameters{}, errors.New("invalid bcrypt salt setting")
	}
	cost64, err := strconv.ParseUint(setting[4:6], 10, 8)
	if err != nil || cost64 < cryptbcrypt.MinCost {
		return openLDAPCryptParameters{}, errors.New("invalid bcrypt cost")
	}
	if cost64 > MaxOpenLDAPCryptBcryptCost {
		return openLDAPCryptParameters{}, fmt.Errorf(
			"%w: bcrypt cost %d exceeds %d",
			errOpenLDAPCryptCostLimit,
			cost64,
			MaxOpenLDAPCryptBcryptCost,
		)
	}
	salt := setting[7:]
	if len(salt) != cryptbcrypt.SaltLength || !validOpenLDAPCryptString(salt) {
		return openLDAPCryptParameters{}, errors.New("invalid bcrypt salt")
	}
	decodedSalt := make([]byte, cryptbcrypt.Encoding.DecodedLen(len(salt)))
	defer clear(decodedSalt)
	decodedLength, err := cryptbcrypt.Encoding.Decode(decodedSalt, []byte(salt))
	if err != nil || decodedLength != 16 {
		return openLDAPCryptParameters{}, errors.New("invalid bcrypt salt encoding")
	}
	canonicalSalt := make([]byte, cryptbcrypt.SaltLength)
	cryptbcrypt.Encoding.Encode(canonicalSalt, decodedSalt[:decodedLength])
	return openLDAPCryptParameters{
		kind:   openLDAPCryptBcrypt,
		prefix: setting[:4],
		cost:   uint8(cost64),
		salt:   canonicalSalt,
	}, nil
}

func parseOpenLDAPCryptSHA2Setting(
	setting string,
	kind openLDAPCryptKind,
) (openLDAPCryptParameters, error) {
	prefix := setting[:3]
	remainder := setting[3:]
	rounds := uint32(cryptsha256.ImplicitRounds)
	explicitRounds := false
	if strings.HasPrefix(remainder, "rounds=") {
		separator := strings.IndexByte(remainder, '$')
		if separator < 0 {
			return openLDAPCryptParameters{}, errors.New("invalid SHA-crypt rounds setting")
		}
		parsed, err := strconv.ParseUint(remainder[len("rounds="):separator], 10, 32)
		if err != nil || parsed < cryptsha256.MinRounds {
			return openLDAPCryptParameters{}, errors.New("invalid SHA-crypt rounds")
		}
		if parsed > MaxOpenLDAPCryptSHA2Rounds {
			return openLDAPCryptParameters{}, fmt.Errorf(
				"%w: SHA-crypt rounds %d exceeds %d",
				errOpenLDAPCryptCostLimit,
				parsed,
				MaxOpenLDAPCryptSHA2Rounds,
			)
		}
		rounds = uint32(parsed)
		explicitRounds = true
		remainder = remainder[separator+1:]
	}
	salt := strings.TrimSuffix(remainder, "$")
	if len(salt) > cryptsha256.MaxSaltLength || !validOpenLDAPCryptString(salt) {
		return openLDAPCryptParameters{}, errors.New("invalid SHA-crypt salt")
	}
	return openLDAPCryptParameters{
		kind:           kind,
		prefix:         prefix,
		salt:           []byte(salt),
		rounds:         rounds,
		explicitRounds: explicitRounds,
	}, nil
}

func parseOpenLDAPCryptHash(hash string) (openLDAPCryptParameters, error) {
	if len(hash) == 13 && hash[0] != '$' && validOpenLDAPCryptString(hash) {
		params, err := parseOpenLDAPCryptSetting(hash[:2])
		if err == nil {
			params.digest = []byte(hash[2:])
		}
		return params, err
	}
	if strings.HasPrefix(hash, "$y$") {
		return openLDAPCryptParameters{}, fmt.Errorf(
			"%w: yescrypt is not supported",
			errOpenLDAPCryptUnsupported,
		)
	}
	parts := strings.Split(hash, "$")
	if len(parts) < 4 || parts[0] != "" {
		return openLDAPCryptParameters{}, errOpenLDAPCryptUnsupported
	}
	switch parts[1] {
	case "1":
		if len(parts) != 4 || len(parts[3]) != 22 || !validOpenLDAPCryptString(parts[3]) {
			return openLDAPCryptParameters{}, errors.New("invalid MD5-crypt hash")
		}
		params, err := parseOpenLDAPCryptSetting("$1$" + parts[2])
		if err == nil {
			params.digest = []byte(parts[3])
		}
		return params, err
	case "2a", "2b", "2y":
		if len(parts) != 4 || len(parts[3]) != cryptbcrypt.SaltLength+openLDAPCryptBcryptEncodedSize {
			return openLDAPCryptParameters{}, errors.New("invalid bcrypt hash")
		}
		storedSalt := parts[3][:cryptbcrypt.SaltLength]
		params, err := parseOpenLDAPCryptBcryptSetting(
			"$" + parts[1] + "$" + parts[2] + "$" + storedSalt,
		)
		if err == nil {
			if string(params.salt) != storedSalt {
				return openLDAPCryptParameters{}, errors.New("non-canonical bcrypt salt")
			}
			params.digest = []byte(parts[3][cryptbcrypt.SaltLength:])
			if !validOpenLDAPCryptString(string(params.digest)) {
				return openLDAPCryptParameters{}, errors.New("invalid bcrypt digest")
			}
		}
		return params, err
	case "5", "6":
		return parseOpenLDAPCryptSHA2Hash(parts)
	default:
		return openLDAPCryptParameters{}, fmt.Errorf(
			"%w: prefix $%s$",
			errOpenLDAPCryptUnsupported,
			parts[1],
		)
	}
}

func parseOpenLDAPCryptSHA2Hash(parts []string) (openLDAPCryptParameters, error) {
	kind := openLDAPCryptSHA256
	digestLength := 43
	if parts[1] == "6" {
		kind = openLDAPCryptSHA512
		digestLength = 86
	}
	var setting, digest string
	switch {
	case len(parts) == 4:
		setting = "$" + parts[1] + "$" + parts[2]
		digest = parts[3]
	case len(parts) == 5 && strings.HasPrefix(parts[2], "rounds="):
		setting = "$" + parts[1] + "$" + parts[2] + "$" + parts[3]
		digest = parts[4]
	default:
		return openLDAPCryptParameters{}, errors.New("invalid SHA-crypt hash")
	}
	if len(digest) != digestLength || !validOpenLDAPCryptString(digest) {
		return openLDAPCryptParameters{}, errors.New("invalid SHA-crypt digest")
	}
	params, err := parseOpenLDAPCryptSHA2Setting(setting, kind)
	if err == nil {
		params.digest = []byte(digest)
	}
	return params, err
}

func deriveOpenLDAPCryptDigest(
	params openLDAPCryptParameters,
	password []byte,
) ([]byte, error) {
	switch params.kind {
	case openLDAPCryptDES:
		keyPassword := password
		if len(keyPassword) > openLDAPCryptDESPasswordLength {
			keyPassword = keyPassword[:openLDAPCryptDESPasswordLength]
		}
		key, err := cryptdes.Key(keyPassword, params.salt)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		encoded := make([]byte, 11)
		crypthash.BigEndianEncoding.Encode(encoded, key)
		return encoded, nil
	case openLDAPCryptMD5:
		key, err := cryptmd5.Key(password, params.salt)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		encoded := make([]byte, 22)
		crypthash.LittleEndianEncoding.Encode(encoded, key)
		return encoded, nil
	case openLDAPCryptBcrypt:
		prefix := params.prefix
		if prefix == "$2y$" {
			prefix = cryptbcrypt.Prefix2b
		}
		key, err := cryptbcrypt.Key(
			password,
			params.salt,
			params.cost,
			&cryptbcrypt.CompatibilityOptions{Prefix: prefix},
		)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		encoded := make([]byte, openLDAPCryptBcryptEncodedSize)
		cryptbcrypt.Encoding.Encode(encoded, key)
		return encoded, nil
	case openLDAPCryptSHA256:
		key, err := cryptsha256.Key(password, params.salt, params.rounds)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		encoded := make([]byte, 43)
		crypthash.LittleEndianEncoding.Encode(encoded, key)
		return encoded, nil
	case openLDAPCryptSHA512:
		key, err := cryptsha512.Key(password, params.salt, params.rounds)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		encoded := make([]byte, 86)
		crypthash.LittleEndianEncoding.Encode(encoded, key)
		return encoded, nil
	default:
		return nil, errOpenLDAPCryptUnsupported
	}
}

func encodeOpenLDAPCryptHash(params openLDAPCryptParameters, digest []byte) string {
	switch params.kind {
	case openLDAPCryptDES:
		return string(params.salt) + string(digest)
	case openLDAPCryptMD5:
		return params.prefix + string(params.salt) + "$" + string(digest)
	case openLDAPCryptBcrypt:
		return fmt.Sprintf(
			"%s%02d$%s%s",
			params.prefix,
			params.cost,
			params.salt,
			digest,
		)
	case openLDAPCryptSHA256, openLDAPCryptSHA512:
		if params.explicitRounds {
			return fmt.Sprintf(
				"%srounds=%d$%s$%s",
				params.prefix,
				params.rounds,
				params.salt,
				digest,
			)
		}
		return params.prefix + string(params.salt) + "$" + string(digest)
	default:
		panic("validated crypt kind was not handled")
	}
}

func validOpenLDAPCryptString(value string) bool {
	for i := range len(value) {
		if !strings.ContainsRune(openLDAPCryptAlphabet, rune(value[i])) {
			return false
		}
	}
	return true
}
