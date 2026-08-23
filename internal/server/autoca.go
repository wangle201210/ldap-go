package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	autoCAProfileOpenLDAPRSA = "openldap-rsa"
	autoCAProfileSM2SM3      = "sm2-sm3"

	autoCADefaultKeyBits    = 2048
	autoCADefaultUserDays   = 365
	autoCADefaultServerDays = 1826
	autoCADefaultCADays     = 3652
)

type autoCARuntimeConfiguration struct {
	configDNKey           string
	disabled              bool
	profile               string
	userClass             string
	userClassConfigured   bool
	serverClass           string
	serverClassConfigured bool
	userKeyBits           int
	serverKeyBits         int
	caKeyBits             int
	userDays              int
	serverDays            int
	caDays                int
	localDN               *directory.DN
	authority             autoCACertificatePair
}

func loadAutoCARuntimeConfiguration(
	entry directory.Entry,
) (autoCARuntimeConfiguration, error) {
	allowed := map[string]struct{}{
		"objectclass":            {},
		"olcoverlay":             {},
		"olcdisabled":            {},
		"olcautocaprofile":       {},
		"olcautocauserclass":     {},
		"olcautocaserverclass":   {},
		"olcautocauserkeybits":   {},
		"olcautocaserverkeybits": {},
		"olcautocakeybits":       {},
		"olcautocauserdays":      {},
		"olcautocaserverdays":    {},
		"olcautocadays":          {},
		"olcautocalocaldn":       {},
		"entryuuid":              {},
		"entrycsn":               {},
		"createtimestamp":        {},
		"modifytimestamp":        {},
		"creatorsname":           {},
		"modifiersname":          {},
		"structuralobjectclass":  {},
		"subschemasubentry":      {},
	}
	for _, attribute := range entry.Attributes {
		name := strings.ToLower(strings.Split(attribute.Description, ";")[0])
		if _, ok := allowed[name]; !ok {
			return autoCARuntimeConfiguration{}, fmt.Errorf(
				"%s has unsupported autoca configuration attribute %q",
				entry.DN,
				attribute.Description,
			)
		}
	}

	disabled, _, err := singleBoolean(entry, "olcDisabled")
	if err != nil {
		return autoCARuntimeConfiguration{}, err
	}
	configDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return autoCARuntimeConfiguration{}, err
	}
	configuration := autoCARuntimeConfiguration{
		configDNKey:   configDN.Key(),
		disabled:      disabled,
		profile:       autoCAProfileOpenLDAPRSA,
		userClass:     "person",
		serverClass:   "ipHost",
		userKeyBits:   autoCADefaultKeyBits,
		serverKeyBits: autoCADefaultKeyBits,
		caKeyBits:     autoCADefaultKeyBits,
		userDays:      autoCADefaultUserDays,
		serverDays:    autoCADefaultServerDays,
		caDays:        autoCADefaultCADays,
	}

	if raw, present, err := autoCASingleString(entry, "olcAutoCAProfile"); err != nil {
		return autoCARuntimeConfiguration{}, err
	} else if present {
		switch strings.ToLower(raw) {
		case "rsa", autoCAProfileOpenLDAPRSA:
			configuration.profile = autoCAProfileOpenLDAPRSA
		case "sm2", autoCAProfileSM2SM3:
			configuration.profile = autoCAProfileSM2SM3
			configuration.userKeyBits = autoCASM2KeyBits
			configuration.serverKeyBits = autoCASM2KeyBits
			configuration.caKeyBits = autoCASM2KeyBits
		default:
			return autoCARuntimeConfiguration{}, fmt.Errorf(
				"%s olcAutoCAProfile must be %q or %q",
				entry.DN,
				autoCAProfileOpenLDAPRSA,
				autoCAProfileSM2SM3,
			)
		}
	}
	if value, present, err := autoCASingleString(entry, "olcAutoCAuserClass"); err != nil {
		return autoCARuntimeConfiguration{}, err
	} else if present {
		configuration.userClass = value
		configuration.userClassConfigured = true
	}
	if value, present, err := autoCASingleString(entry, "olcAutoCAserverClass"); err != nil {
		return autoCARuntimeConfiguration{}, err
	} else if present {
		configuration.serverClass = value
		configuration.serverClassConfigured = true
	}

	integerFields := []struct {
		attribute string
		target    *int
	}{
		{"olcAutoCAuserKeybits", &configuration.userKeyBits},
		{"olcAutoCAserverKeybits", &configuration.serverKeyBits},
		{"olcAutoCAKeybits", &configuration.caKeyBits},
		{"olcAutoCAuserDays", &configuration.userDays},
		{"olcAutoCAserverDays", &configuration.serverDays},
		{"olcAutoCADays", &configuration.caDays},
	}
	for _, field := range integerFields {
		value, present, parseErr := autoCASingleInteger(entry, field.attribute)
		if parseErr != nil {
			return autoCARuntimeConfiguration{}, parseErr
		}
		if present {
			*field.target = value
		}
	}
	if raw, present, err := autoCASingleString(entry, "olcAutoCAlocalDN"); err != nil {
		return autoCARuntimeConfiguration{}, err
	} else if present {
		localDN, parseErr := directory.ParseDN(raw)
		if parseErr != nil {
			return autoCARuntimeConfiguration{}, fmt.Errorf(
				"%s olcAutoCAlocalDN: %w",
				entry.DN,
				parseErr,
			)
		}
		configuration.localDN = &localDN
	}
	if err := configuration.validateKeySizes(entry.DN); err != nil {
		return autoCARuntimeConfiguration{}, err
	}
	if configuration.userDays <= 0 || configuration.serverDays <= 0 || configuration.caDays <= 0 {
		return autoCARuntimeConfiguration{}, fmt.Errorf(
			"%s AutoCA certificate lifetimes must be positive",
			entry.DN,
		)
	}
	return configuration, nil
}

func (configuration autoCARuntimeConfiguration) validateKeySizes(configDN string) error {
	for name, value := range map[string]int{
		"olcAutoCAuserKeybits":   configuration.userKeyBits,
		"olcAutoCAserverKeybits": configuration.serverKeyBits,
		"olcAutoCAKeybits":       configuration.caKeyBits,
	} {
		switch configuration.profile {
		case autoCAProfileSM2SM3:
			if value != autoCASM2KeyBits {
				return fmt.Errorf(
					"%s %s must be %d for profile %s",
					configDN,
					name,
					autoCASM2KeyBits,
					configuration.profile,
				)
			}
		case autoCAProfileOpenLDAPRSA:
			if value < autoCAMinRSAKeyBits || value > autoCAMaxRSAKeyBits {
				return fmt.Errorf(
					"%s %s must be between %d and %d",
					configDN,
					name,
					autoCAMinRSAKeyBits,
					autoCAMaxRSAKeyBits,
				)
			}
		}
	}
	return nil
}

func validateAutoCASchema(
	registry *schema.Registry,
	configuration *autoCARuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	if _, found := registry.ObjectClass(configuration.userClass); !found {
		return fmt.Errorf("unknown user objectClass %q", configuration.userClass)
	}
	if _, found := registry.ObjectClass(configuration.serverClass); !found &&
		configuration.serverClassConfigured {
		return fmt.Errorf("unknown server objectClass %q", configuration.serverClass)
	}
	return nil
}

func validateAutoCADatabase(
	database runtimeDatabase,
	configuration autoCARuntimeConfiguration,
) error {
	if len(database.suffixes) == 0 || database.partition == "" ||
		databaseType(database.name) == "frontend" ||
		isConfigDatabase(database) || isMonitorDatabase(database) ||
		isNullDatabase(database) || database.relay != nil ||
		database.ldapBackend != nil || database.readOnly || database.shadow {
		return fmt.Errorf(
			"%s autoca overlay requires a writable local database naming context",
			configuration.configDNKey,
		)
	}
	if configuration.localDN != nil {
		inSuffix := false
		for _, suffix := range database.suffixes {
			if databaseDNAtOrBelow(database, *configuration.localDN, suffix) {
				inSuffix = true
				break
			}
		}
		if !inSuffix {
			return fmt.Errorf(
				"%s olcAutoCAlocalDN is outside the database suffix",
				configuration.configDNKey,
			)
		}
	}
	return nil
}

func activeAutoCAConfiguration(
	database *runtimeDatabase,
) *autoCARuntimeConfiguration {
	if database == nil || database.autoca == nil || database.autoca.disabled {
		return nil
	}
	return database.autoca
}

func loadAutoCAAuthorities(
	reader storage.Reader,
	runtime *runtimeState,
) error {
	for index := range runtime.databases {
		database := &runtime.databases[index]
		configuration := activeAutoCAConfiguration(database)
		if configuration == nil {
			continue
		}
		base := database.suffixes[0]
		entry, err := readerForDatabase(reader, *database).Get(base)
		if errors.Is(err, storage.ErrEntryNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("load AutoCA suffix %s: %w", base.String(), err)
		}
		pair, present, err := autoCAStoredAuthority(
			runtime.schema,
			entry,
			configuration.profile,
		)
		if err != nil {
			return fmt.Errorf("load AutoCA authority at %s: %w", entry.DN, err)
		}
		if present {
			configuration.authority = cloneAutoCACertificatePair(pair)
		}
	}
	return nil
}

func (server *Server) ensureAutoCAAuthorities(
	writer storage.Writer,
	runtime *runtimeState,
) error {
	for index := range runtime.databases {
		database := &runtime.databases[index]
		configuration := activeAutoCAConfiguration(database)
		if configuration == nil {
			continue
		}
		base := database.suffixes[0]
		tx := writerForDatabase(writer, *database)
		entry, err := tx.Get(base)
		if errors.Is(err, storage.ErrEntryNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("load AutoCA suffix %s: %w", base.String(), err)
		}
		pair, present, err := autoCAStoredAuthority(runtime.schema, entry, configuration.profile)
		if err != nil {
			return fmt.Errorf("load AutoCA authority at %s: %w", entry.DN, err)
		}
		if !present {
			pair, err = generateAutoCAAuthority(*configuration, entry.DN, time.Now())
			if err != nil {
				return fmt.Errorf("generate AutoCA authority at %s: %w", entry.DN, err)
			}
			if !runtime.schema.EntryHasObjectClass(entry, "autoCA") {
				if err := entry.AddValues("objectClass", stringValues("autoCA")); err != nil {
					return fmt.Errorf("add AutoCA objectClass at %s: %w", entry.DN, err)
				}
			}
			entry.ReplaceValues("cACertificate;binary", [][]byte{pair.CertificateDER})
			entry.ReplaceValues("cAPrivateKey;binary", [][]byte{pair.PrivateKeyDER})
			if err := runtime.schema.ValidateEntry(entry); err != nil {
				return fmt.Errorf("validate AutoCA authority at %s: %w", entry.DN, err)
			}
			if err := tx.Put(entry, true); err != nil {
				return fmt.Errorf("store AutoCA authority at %s: %w", entry.DN, err)
			}
		}
		configuration.authority = cloneAutoCACertificatePair(pair)
	}
	return server.ensureAutoCALocalTLS(writer, runtime)
}

func autoCAStoredAuthority(
	registry *schema.Registry,
	entry directory.Entry,
	profile string,
) (autoCACertificatePair, bool, error) {
	certificates := registry.AttributeValues(entry, "cACertificate;binary")
	privateKeys := registry.AttributeValues(entry, "cAPrivateKey;binary")
	if len(certificates) == 0 && len(privateKeys) == 0 {
		return autoCACertificatePair{}, false, nil
	}
	if len(certificates) != 1 || len(privateKeys) != 1 {
		return autoCACertificatePair{}, false, errors.New(
			"authority requires one cACertificate;binary and one cAPrivateKey;binary",
		)
	}
	pair := autoCACertificatePair{
		CertificateDER: bytes.Clone(certificates[0]),
		PrivateKeyDER:  bytes.Clone(privateKeys[0]),
	}
	var err error
	switch profile {
	case autoCAProfileSM2SM3:
		_, _, err = parseAutoCASM2Issuer(pair)
	default:
		_, _, err = autoCAParseIssuer(pair)
	}
	if err != nil {
		return autoCACertificatePair{}, false, err
	}
	return pair, true, nil
}

func generateAutoCAAuthority(
	configuration autoCARuntimeConfiguration,
	dn string,
	now time.Time,
) (autoCACertificatePair, error) {
	config := autoCACertificateConfig{
		DN:      dn,
		KeyBits: configuration.caKeyBits,
		Days:    configuration.caDays,
		Now:     now,
		Random:  rand.Reader,
	}
	if configuration.profile == autoCAProfileSM2SM3 {
		return generateAutoCASM2SelfSignedCA(config)
	}
	return generateAutoCASelfSignedCA(config)
}

func cloneAutoCACertificatePair(pair autoCACertificatePair) autoCACertificatePair {
	return autoCACertificatePair{
		CertificateDER: bytes.Clone(pair.CertificateDER),
		PrivateKeyDER:  bytes.Clone(pair.PrivateKeyDER),
	}
}

func autoCASearchRequested(
	registry *schema.Registry,
	attributes []string,
) bool {
	return len(attributes) == 2 &&
		autoCAAttributeDescriptionEqual(registry, attributes[0], "userCertificate;binary") &&
		autoCAAttributeDescriptionEqual(registry, attributes[1], "userPrivateKey;binary")
}

func autoCAAttributeDescriptionEqual(
	registry *schema.Registry,
	left,
	right string,
) bool {
	leftType, leftOptions := splitAutoCAAttributeDescription(left)
	rightType, rightOptions := splitAutoCAAttributeDescription(right)
	if len(leftOptions) != len(rightOptions) {
		return false
	}
	for option := range leftOptions {
		if _, ok := rightOptions[option]; !ok {
			return false
		}
	}
	leftAttribute, leftFound := registry.AttributeType(leftType)
	rightAttribute, rightFound := registry.AttributeType(rightType)
	return leftFound && rightFound && strings.EqualFold(leftAttribute.OID, rightAttribute.OID)
}

func splitAutoCAAttributeDescription(raw string) (string, map[string]struct{}) {
	parts := strings.Split(raw, ";")
	options := make(map[string]struct{}, len(parts)-1)
	for _, option := range parts[1:] {
		option = strings.ToLower(strings.TrimSpace(option))
		if option != "" {
			options[option] = struct{}{}
		}
	}
	return strings.TrimSpace(parts[0]), options
}

func (server *Server) prepareAutoCASearch(
	ctx context.Context,
	state *connectionState,
	request ldapwire.SearchRequest,
	routes []databaseSearchRoute,
) {
	if !autoCASearchRequested(state.runtime.schema, request.Attributes) || len(routes) == 0 {
		return
	}
	subject, err := directory.ParseDN(state.boundDN)
	if err != nil || subject.Depth() == 0 {
		return
	}

	err = server.updateStorage(ctx, func(writer storage.Writer) error {
		seen := make(map[string]struct{})
		for _, route := range routes {
			if route.databaseIndex < 0 || route.databaseIndex >= len(state.runtime.databases) {
				continue
			}
			database := &state.runtime.databases[route.databaseIndex]
			configuration := activeAutoCAConfiguration(database)
			if configuration == nil || len(configuration.authority.CertificateDER) == 0 {
				continue
			}
			tx := writerForDatabase(writer, *database)
			candidates, err := autoCASearchCandidates(
				tx,
				database.partition,
				route.base,
				route.scope,
				seen,
			)
			if err != nil {
				return err
			}
			for _, dn := range candidates {
				entry, getErr := tx.Get(dn)
				if getErr != nil {
					return getErr
				}
				if !databaseRootMatches(state.runtime, *database, subject) &&
					!databaseDNEqual(*database, subject, dn) {
					continue
				}
				if !server.allowed(
					state.runtime,
					tx,
					state.boundDN,
					entry,
					"entry",
					nil,
					acl.Search,
				) {
					continue
				}
				matches, matchErr := server.filterMatches(
					state.runtime,
					tx,
					state.boundDN,
					entry,
					request.Filter,
				)
				if matchErr != nil || !matches {
					continue
				}
				if err := server.issueAutoCAEntry(
					state.runtime,
					tx,
					*configuration,
					entry,
				); err != nil {
					server.config.Logger.Debug(
						"AutoCA entry issuance skipped",
						"dn", entry.DN,
						"error", err,
					)
				}
			}
		}
		return nil
	})
	if err != nil {
		server.config.Logger.Debug("AutoCA Search preparation failed", "error", err)
	}
}

func autoCASearchCandidates(
	reader storage.Reader,
	partition string,
	base directory.DN,
	scope directory.Scope,
	seen map[string]struct{},
) ([]directory.DN, error) {
	base, err := storage.NormalizeReaderDN(reader, base)
	if err != nil {
		return nil, err
	}
	var candidates []directory.DN
	err = reader.ForEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		dn, err = storage.NormalizeReaderDN(reader, dn)
		if err != nil {
			return err
		}
		if !directory.InScope(base, dn, scope) {
			return nil
		}
		key := partition + "\x00" + dn.Key()
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		candidates = append(candidates, dn)
		return nil
	})
	return candidates, err
}

func (server *Server) issueAutoCAEntry(
	runtime *runtimeState,
	tx storage.Writer,
	configuration autoCARuntimeConfiguration,
	entry directory.Entry,
) error {
	if configuration.localDN != nil {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		if runtimeDNEqual(runtime, entryDN, *configuration.localDN) {
			// The listener key is held in storage metadata and is never exposed
			// through the LDAP Search-triggered certificate issuance path.
			return nil
		}
	}
	if runtime.schema.HasAttributeDescription(entry, "userPrivateKey;binary") {
		return nil
	}
	isUser := runtime.schema.EntryHasObjectClass(entry, configuration.userClass)
	isServer := runtime.schema.EntryHasObjectClass(entry, configuration.serverClass)
	if !isUser && !isServer {
		return nil
	}

	var pair autoCACertificatePair
	var err error
	if isUser {
		mail := autoCAFirstString(runtime.schema.AttributeValues(entry, "mail"))
		userConfig := autoCAUserCertificateConfig{
			DN:      entry.DN,
			Mail:    mail,
			KeyBits: configuration.userKeyBits,
			Days:    configuration.userDays,
			Now:     time.Now(),
			Random:  rand.Reader,
		}
		if configuration.profile == autoCAProfileSM2SM3 {
			pair, err = generateAutoCASM2UserCertificate(configuration.authority, userConfig)
		} else {
			pair, err = generateAutoCAUserCertificate(configuration.authority, userConfig)
		}
	} else {
		serverConfig := autoCAServerCertificateConfig{
			DN: entry.DN,
			IPHostNumber: autoCAFirstString(
				runtime.schema.AttributeValues(entry, "ipHostNumber"),
			),
			KeyBits: configuration.serverKeyBits,
			Days:    configuration.serverDays,
			Now:     time.Now(),
			Random:  rand.Reader,
		}
		if configuration.profile == autoCAProfileSM2SM3 {
			pair, err = generateAutoCASM2ServerCertificate(
				configuration.authority,
				serverConfig,
			)
		} else {
			pair, err = generateAutoCAServerCertificate(
				configuration.authority,
				serverConfig,
			)
		}
	}
	if err != nil {
		return err
	}
	before := entry.Clone()
	if !runtime.schema.EntryHasObjectClass(entry, "autoCAuser") {
		if err := entry.AddValues("objectClass", stringValues("autoCAuser")); err != nil {
			return err
		}
	}
	entry.ReplaceValues("userCertificate;binary", [][]byte{pair.CertificateDER})
	entry.ReplaceValues("userPrivateKey;binary", [][]byte{pair.PrivateKeyDER})
	if err := runtime.schema.ValidateEntry(entry); err != nil {
		return err
	}
	if before.Equal(entry) {
		return nil
	}
	return tx.Put(entry, true)
}

func autoCAFirstString(values [][]byte) string {
	if len(values) == 0 {
		return ""
	}
	return string(values[0])
}

func autoCASingleString(
	entry directory.Entry,
	attribute string,
) (string, bool, error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", false, fmt.Errorf("%s %s must be single-valued", entry.DN, attribute)
	}
	value := strings.TrimSpace(string(values[0]))
	if value == "" {
		return "", false, fmt.Errorf("%s %s must not be empty", entry.DN, attribute)
	}
	return value, true, nil
}

func autoCASingleInteger(
	entry directory.Entry,
	attribute string,
) (int, bool, error) {
	raw, present, err := autoCASingleString(entry, attribute)
	if err != nil || !present {
		return 0, present, err
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false, fmt.Errorf("%s %s must be an integer", entry.DN, attribute)
	}
	return value, true, nil
}
