package server

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

var errTOTPPasswordStateUpdate = errors.New("update TOTP authentication state")

type totpPasswordRuntimeConfiguration struct {
	configDNKey string
	disabled    bool
}

func loadTOTPPasswordRuntimeConfiguration(
	entry directory.Entry,
) (totpPasswordRuntimeConfiguration, error) {
	allowed := map[string]struct{}{
		"objectclass":           {},
		"olcoverlay":            {},
		"olcdisabled":           {},
		"entryuuid":             {},
		"entrycsn":              {},
		"createtimestamp":       {},
		"modifytimestamp":       {},
		"creatorsname":          {},
		"modifiersname":         {},
		"structuralobjectclass": {},
		"subschemasubentry":     {},
	}
	for _, attribute := range entry.Attributes {
		if _, ok := allowed[strings.ToLower(attribute.Description)]; !ok {
			return totpPasswordRuntimeConfiguration{}, fmt.Errorf(
				"%s has unsupported totp configuration attribute %q",
				entry.DN,
				attribute.Description,
			)
		}
	}
	disabled, _, err := singleBoolean(entry, "olcDisabled")
	if err != nil {
		return totpPasswordRuntimeConfiguration{}, err
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return totpPasswordRuntimeConfiguration{}, err
	}
	return totpPasswordRuntimeConfiguration{
		configDNKey: dn.Key(),
		disabled:    disabled,
	}, nil
}

func activeTOTPPasswordConfiguration(
	runtime *runtimeState,
	database *runtimeDatabase,
) *totpPasswordRuntimeConfiguration {
	if runtime == nil || database == nil {
		return nil
	}
	if databaseType(database.name) != "frontend" {
		for index := range database.totpPasswords {
			if !database.totpPasswords[index].disabled {
				return &database.totpPasswords[index]
			}
		}
	}
	for databaseIndex := range runtime.databases {
		candidate := &runtime.databases[databaseIndex]
		if databaseType(candidate.name) != "frontend" {
			continue
		}
		for index := range candidate.totpPasswords {
			if !candidate.totpPasswords[index].disabled {
				return &candidate.totpPasswords[index]
			}
		}
	}
	return nil
}

func totpPasswordLastAuthentication(
	registry *schema.Registry,
	entry directory.Entry,
) time.Time {
	values := entry.Values("authTimestamp")
	if len(values) != 1 {
		return time.Time{}
	}
	normalized, err := registry.NormalizeEqualityValue(
		"authTimestamp",
		values[0],
	)
	if err != nil {
		return time.Time{}
	}
	parsed, err := parseTOTPPasswordAuthenticationTime(normalized)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func parseTOTPPasswordAuthenticationTime(normalized []byte) (time.Time, error) {
	const wholeSecondsLength = len("YYYYmmddHHMMSS")
	if len(normalized) < wholeSecondsLength+1 ||
		normalized[len(normalized)-1] != 'Z' {
		return time.Time{}, errors.New("invalid normalized authentication time")
	}
	for _, value := range normalized[:wholeSecondsLength] {
		if value < '0' || value > '9' {
			return time.Time{}, errors.New("invalid normalized authentication time")
		}
	}
	if len(normalized) > wholeSecondsLength+1 {
		if len(normalized) < wholeSecondsLength+3 ||
			normalized[wholeSecondsLength] != '.' {
			return time.Time{}, errors.New("invalid normalized authentication time")
		}
		for _, value := range normalized[wholeSecondsLength+1 : len(normalized)-1] {
			if value < '0' || value > '9' {
				return time.Time{}, errors.New("invalid normalized authentication time")
			}
		}
	}
	second := int(normalized[12]-'0')*10 + int(normalized[13]-'0')
	if second > 60 {
		return time.Time{}, errors.New("invalid normalized authentication time")
	}
	base := append([]byte(nil), normalized[:wholeSecondsLength]...)
	base[12] = '0'
	base[13] = '0'
	base = append(base, 'Z')
	parsed, err := time.Parse("20060102150405Z", string(base))
	if err != nil {
		return time.Time{}, err
	}
	return parsed.Add(time.Duration(second) * time.Second), nil
}
