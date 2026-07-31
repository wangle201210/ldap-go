package server

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"
)

type syncConsumerGSSAPICredentialSource uint8

const (
	syncConsumerGSSAPIPassword syncConsumerGSSAPICredentialSource = iota
	syncConsumerGSSAPIKeytab
	syncConsumerGSSAPICCache
)

type syncConsumerGSSAPISettings struct {
	source           syncConsumerGSSAPICredentialSource
	username         string
	realm            string
	password         string
	credentialPath   string
	configuration    string
	servicePrincipal string
	authorizationID  string
}

type syncConsumerGSSAPIClient interface {
	ldap.GSSAPIClient
	Close() error
}

type syncConsumerGSSAPIBinder interface {
	GSSAPIBind(ldap.GSSAPIClient, string, string) error
}

type syncConsumerGSSAPIClientFactory func(
	syncConsumerGSSAPISettings,
) (syncConsumerGSSAPIClient, error)

func bindSyncConsumerGSSAPI(
	connection syncConsumerGSSAPIBinder,
	config syncConsumerConfig,
	provider string,
) error {
	settings, err := resolveSyncConsumerGSSAPISettings(
		config,
		provider,
		os.LookupEnv,
	)
	if err != nil {
		return err
	}
	return executeSyncConsumerGSSAPIBind(
		connection,
		settings,
		newSyncConsumerGSSAPIClient,
	)
}

func resolveSyncConsumerGSSAPISettings(
	config syncConsumerConfig,
	provider string,
	lookupEnv func(string) (string, bool),
) (syncConsumerGSSAPISettings, error) {
	parsedProvider, err := parseSyncConsumerProviderURL(provider)
	if err != nil {
		return syncConsumerGSSAPISettings{}, err
	}
	host := parsedProvider.Hostname()
	if host == "" {
		return syncConsumerGSSAPISettings{}, errors.New(
			"SASL GSSAPI provider has no hostname",
		)
	}

	configuration := syncConsumerKerberosConfigurationPath(lookupEnv)
	settings := syncConsumerGSSAPISettings{
		configuration:    configuration,
		servicePrincipal: "ldap/" + host,
		authorizationID:  config.authorizationID,
	}

	if config.credentialsSet {
		username, realm, err := normalizeSyncConsumerKerberosPrincipal(
			config.authenticationID,
			config.realm,
		)
		if err != nil {
			return syncConsumerGSSAPISettings{}, err
		}
		if username == "" {
			return syncConsumerGSSAPISettings{}, errors.New(
				"SASL GSSAPI password credentials require authcid",
			)
		}
		settings.source = syncConsumerGSSAPIPassword
		settings.username = username
		settings.realm = realm
		settings.password = string(config.credentials)
		return settings, nil
	}

	keytab, keytabVariable := firstSyncConsumerEnvironment(
		lookupEnv,
		"KRB5_CLIENT_KTNAME",
		"KRB5_KTNAME",
	)
	if keytab != "" {
		keytab, err = parseSyncConsumerKerberosFileCredential(
			keytab,
			keytabVariable,
			true,
		)
		if err != nil {
			return syncConsumerGSSAPISettings{}, err
		}
		username, realm, normalizeErr :=
			normalizeSyncConsumerKerberosPrincipal(
				config.authenticationID,
				config.realm,
			)
		if normalizeErr != nil {
			return syncConsumerGSSAPISettings{}, normalizeErr
		}
		if username == "" {
			return syncConsumerGSSAPISettings{}, errors.New(
				"SASL GSSAPI keytab credentials require authcid",
			)
		}
		settings.source = syncConsumerGSSAPIKeytab
		settings.username = username
		settings.realm = realm
		settings.credentialPath = keytab
		return settings, nil
	}

	cache, cacheSet := lookupEnv("KRB5CCNAME")
	if cacheSet && strings.TrimSpace(cache) != "" {
		cache, err = parseSyncConsumerKerberosFileCredential(
			cache,
			"KRB5CCNAME",
			false,
		)
		if err != nil {
			return syncConsumerGSSAPISettings{}, err
		}
	} else {
		cache, err = defaultSyncConsumerKerberosCCache()
		if err != nil {
			return syncConsumerGSSAPISettings{}, err
		}
	}
	settings.source = syncConsumerGSSAPICCache
	settings.credentialPath = cache
	return settings, nil
}

func executeSyncConsumerGSSAPIBind(
	connection syncConsumerGSSAPIBinder,
	settings syncConsumerGSSAPISettings,
	factory syncConsumerGSSAPIClientFactory,
) error {
	client, err := factory(settings)
	if err != nil {
		return fmt.Errorf("initialize SASL GSSAPI credentials: %w", err)
	}
	bindErr := connection.GSSAPIBind(
		client,
		settings.servicePrincipal,
		settings.authorizationID,
	)
	closeErr := client.Close()
	if bindErr != nil {
		return fmt.Errorf("SASL GSSAPI bind: %w", bindErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close SASL GSSAPI credentials: %w", closeErr)
	}
	return nil
}

func newSyncConsumerGSSAPIClient(
	settings syncConsumerGSSAPISettings,
) (syncConsumerGSSAPIClient, error) {
	switch settings.source {
	case syncConsumerGSSAPIPassword:
		return ldapgssapi.NewClientWithPassword(
			settings.username,
			settings.realm,
			settings.password,
			settings.configuration,
		)
	case syncConsumerGSSAPIKeytab:
		return ldapgssapi.NewClientWithKeytab(
			settings.username,
			settings.realm,
			settings.credentialPath,
			settings.configuration,
		)
	case syncConsumerGSSAPICCache:
		return ldapgssapi.NewClientFromCCache(
			settings.credentialPath,
			settings.configuration,
		)
	default:
		return nil, errors.New("unknown GSSAPI credential source")
	}
}

func normalizeSyncConsumerKerberosPrincipal(
	authenticationID string,
	configuredRealm string,
) (string, string, error) {
	authenticationID = strings.TrimSpace(authenticationID)
	configuredRealm = strings.TrimSpace(configuredRealm)
	at := strings.LastIndexByte(authenticationID, '@')
	if at <= 0 || at == len(authenticationID)-1 {
		return authenticationID, configuredRealm, nil
	}

	principalRealm := authenticationID[at+1:]
	if configuredRealm != "" &&
		!strings.EqualFold(configuredRealm, principalRealm) {
		return "", "", fmt.Errorf(
			"SASL GSSAPI authcid realm %q conflicts with realm %q",
			principalRealm,
			configuredRealm,
		)
	}
	return authenticationID[:at], principalRealm, nil
}

func syncConsumerKerberosConfigurationPath(
	lookupEnv func(string) (string, bool),
) string {
	if configured, ok := lookupEnv("KRB5_CONFIG"); ok {
		for _, candidate := range filepath.SplitList(configured) {
			candidate = strings.TrimSpace(candidate)
			if candidate != "" {
				return candidate
			}
		}
	}
	if runtime.GOOS == "windows" {
		if systemRoot, ok := lookupEnv("SystemRoot"); ok &&
			strings.TrimSpace(systemRoot) != "" {
			return filepath.Join(systemRoot, "krb5.ini")
		}
		return `C:\Windows\krb5.ini`
	}
	if runtime.GOOS == "darwin" {
		const macOSConfiguration = "/Library/Preferences/edu.mit.Kerberos"
		if _, err := os.Stat(macOSConfiguration); err == nil {
			return macOSConfiguration
		}
	}
	return "/etc/krb5.conf"
}

func firstSyncConsumerEnvironment(
	lookupEnv func(string) (string, bool),
	names ...string,
) (string, string) {
	for _, name := range names {
		value, ok := lookupEnv(name)
		if ok && strings.TrimSpace(value) != "" {
			return value, name
		}
	}
	return "", ""
}

func parseSyncConsumerKerberosFileCredential(
	value string,
	variable string,
	allowWritableFile bool,
) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is empty", variable)
	}
	if isWindowsDrivePath(value) {
		return value, nil
	}

	kind, path, hasKind := strings.Cut(value, ":")
	if !hasKind {
		return value, nil
	}
	switch strings.ToUpper(kind) {
	case "FILE":
		if path == "" {
			return "", fmt.Errorf("%s FILE credential path is empty", variable)
		}
		return path, nil
	case "WRFILE":
		if !allowWritableFile {
			break
		}
		if path == "" {
			return "", fmt.Errorf("%s WRFILE credential path is empty", variable)
		}
		return path, nil
	}
	return "", fmt.Errorf(
		"%s credential type %q is unsupported; use a FILE credential",
		variable,
		kind,
	)
}

func isWindowsDrivePath(value string) bool {
	if len(value) < 3 || value[1] != ':' {
		return false
	}
	drive := value[0]
	return ((drive >= 'a' && drive <= 'z') ||
		(drive >= 'A' && drive <= 'Z')) &&
		(value[2] == '\\' || value[2] == '/')
}

func defaultSyncConsumerKerberosCCache() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf(
			"resolve default Kerberos credential cache: %w",
			err,
		)
	}
	uid := strings.TrimSpace(current.Uid)
	if _, err := strconv.ParseUint(uid, 10, 64); err != nil {
		return "", errors.New(
			"KRB5CCNAME is required when the operating system has no numeric UID",
		)
	}
	return filepath.Join(os.TempDir(), "krb5cc_"+uid), nil
}
