package server

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var openLDAPReferralSchemes = [...]string{
	"ldap",
	"ldaps",
	"ldapi",
	"pldap",
	"pldaps",
}

func loadDefaultReferralConfiguration(reader storage.Reader) ([]string, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load global referral configuration: %w", err)
	}

	values := entry.Values("olcReferral")
	referrals := make([]string, 0, len(values))
	for index, value := range values {
		referral := string(value)
		if err := validateOpenLDAPGlobalReferral(referral); err != nil {
			return nil, fmt.Errorf(
				"%s olcReferral value #%d %q: %w",
				entry.DN,
				index,
				referral,
				err,
			)
		}
		referrals = append(referrals, referral)
	}
	return referrals, nil
}

func validateDefaultReferralOnlineChanges(
	entry directory.Entry,
	changes []ldapwire.Modification,
) error {
	current := make([]string, 0)
	for _, value := range entry.Values("olcReferral") {
		current = append(current, string(value))
	}
	touched := false
	for _, change := range changes {
		attribute := strings.SplitN(change.Attribute.Description, ";", 2)[0]
		if !strings.EqualFold(attribute, "olcReferral") {
			continue
		}
		touched = true
		values := make([]string, len(change.Attribute.Values))
		for index := range change.Attribute.Values {
			values[index] = string(change.Attribute.Values[index])
		}
		switch change.Operation {
		case ldapwire.ModificationAdd:
			for _, value := range values {
				if containsCaseInsensitive(current, value) {
					return operationFailed(
						ldapwire.ResultAttributeOrValueExists,
						"modify/add: olcReferral: value #0 already exists",
					)
				}
				current = append(current, value)
			}
		case ldapwire.ModificationDelete:
			if len(values) == 0 {
				current = nil
				continue
			}
			for _, value := range values {
				for index, existing := range current {
					if !strings.EqualFold(existing, value) {
						continue
					}
					current = append(current[:index], current[index+1:]...)
					break
				}
			}
		case ldapwire.ModificationReplace:
			current = append(current[:0], values...)
		}
	}
	if touched && !isGlobalReferralConfigurationEntry(entry.DN) {
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			"olcReferral is only allowed on cn=config",
		)
	}
	if len(current) > 1 {
		return operationFailed(
			ldapwire.ResultConstraintViolation,
			"olcReferral: multiple values provided",
		)
	}
	for _, value := range current {
		if err := validateOpenLDAPGlobalReferral(value); err != nil {
			return operationFailed(
				ldapwire.ResultOther,
				"<olcReferral> invalid URL",
			)
		}
	}
	return nil
}

func containsCaseInsensitive(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func isGlobalReferralConfigurationEntry(value string) bool {
	dn, err := directory.ParseDN(value)
	if err != nil {
		return false
	}
	return configurationSuffix.Equal(dn)
}

func validateOpenLDAPGlobalReferral(value string) error {
	candidate, scheme, recognized, err := openLDAPReferralURL(value)
	if err != nil {
		return err
	}
	if !recognized {
		return nil
	}

	rest := candidate[len(scheme)+len("://"):]
	authority := rest
	pathAndQuery := ""
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		authority = rest[:slash]
		pathAndQuery = rest[slash+1:]
	} else if strings.ContainsRune(rest, '?') {
		return errors.New("invalid LDAP URL: query requires a DN separator")
	}
	if err := validateOpenLDAPReferralAuthority(scheme, authority); err != nil {
		return err
	}
	if pathAndQuery == "" {
		return nil
	}

	components := strings.Split(pathAndQuery, "?")
	if len(components) > 5 {
		return errors.New("invalid LDAP URL: too many query components")
	}
	decoded := make([]string, len(components))
	for index, component := range components {
		decoded[index], err = url.PathUnescape(component)
		if err != nil {
			return fmt.Errorf("invalid LDAP URL component #%d: %w", index, err)
		}
	}
	if decoded[0] != "" {
		return errors.New("LDAP URL contains a DN")
	}
	if len(decoded) > 1 && decoded[1] != "" {
		return errors.New("LDAP URL requests attributes")
	}
	if len(decoded) > 2 && decoded[2] != "" {
		if !validOpenLDAPReferralScope(decoded[2]) {
			return fmt.Errorf("invalid LDAP URL scope %q", decoded[2])
		}
		return errors.New("LDAP URL contains an explicit scope")
	}
	if len(decoded) > 3 && decoded[3] != "" {
		return errors.New("LDAP URL contains a filter")
	}
	if len(decoded) == 5 && !hasOpenLDAPReferralExtension(decoded[4]) {
		return errors.New("invalid LDAP URL: empty extensions")
	}
	return nil
}

func openLDAPReferralURL(value string) (
	candidate string,
	scheme string,
	recognized bool,
	err error,
) {
	candidate = value
	enclosed := strings.HasPrefix(candidate, "<")
	if enclosed {
		candidate = candidate[1:]
	}
	if len(candidate) >= len("URL:") &&
		strings.EqualFold(candidate[:len("URL:")], "URL:") {
		candidate = candidate[len("URL:"):]
	}

	for _, supported := range openLDAPReferralSchemes {
		prefix := supported + "://"
		if len(candidate) < len(prefix) ||
			!strings.EqualFold(candidate[:len(prefix)], prefix) {
			continue
		}
		if enclosed {
			if !strings.HasSuffix(candidate, ">") {
				return "", "", true, errors.New("invalid enclosed LDAP URL")
			}
			candidate = candidate[:len(candidate)-1]
		}
		return candidate, supported, true, nil
	}
	return value, "", false, nil
}

func validateOpenLDAPReferralAuthority(scheme, authority string) error {
	if scheme == "ldapi" || authority == "" {
		return nil
	}
	if strings.HasPrefix(authority, "[") {
		closing := strings.IndexByte(authority, ']')
		if closing < 0 {
			return errors.New("invalid LDAP URL: unterminated IPv6 address")
		}
		remainder := authority[closing+1:]
		if remainder == "" {
			return nil
		}
		if !strings.HasPrefix(remainder, ":") {
			return errors.New("invalid LDAP URL authority")
		}
		return validateOpenLDAPReferralPort(remainder[1:])
	}
	if colon := strings.IndexByte(authority, ':'); colon >= 0 {
		return validateOpenLDAPReferralPort(authority[colon+1:])
	}
	return nil
}

func validateOpenLDAPReferralPort(port string) error {
	if port == "" {
		return errors.New("invalid LDAP URL: empty port")
	}
	if _, err := strconv.ParseInt(port, 10, 64); err != nil {
		return fmt.Errorf("invalid LDAP URL port %q", port)
	}
	return nil
}

func validOpenLDAPReferralScope(scope string) bool {
	switch strings.ToLower(scope) {
	case "base", "one", "onelevel", "sub", "subtree",
		"subord", "subordinate", "children":
		return true
	default:
		return false
	}
}

func hasOpenLDAPReferralExtension(extensions string) bool {
	for _, extension := range strings.Split(extensions, ",") {
		if extension != "" {
			return true
		}
	}
	return false
}
