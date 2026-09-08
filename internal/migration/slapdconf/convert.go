package slapdconf

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/mdbentry"
)

// ConvertFile parses a slapd.conf tree and converts it to deterministic
// cn=config LDIF entries, validated by ldap-go before any output is returned.
func ConvertFile(path string, options ParseOptions) (Document, error) {
	return ConvertFileContext(context.Background(), path, options)
}

// ConvertFileContext is ConvertFile with cancellation during conversion and
// runtime validation. File reads remain bounded by ParseOptions.
func ConvertFileContext(ctx context.Context, path string, options ParseOptions) (Document, error) {
	if ctx == nil {
		return Document{}, errors.New("conversion context is required")
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	directives, err := ParseFileContext(ctx, path, options)
	if err != nil {
		return Document{}, err
	}
	converter := newConverter()
	converter.global.position = Position{Path: path, Line: 1}
	for _, directive := range directives {
		if err := ctx.Err(); err != nil {
			return Document{}, err
		}
		if err := converter.apply(directive); err != nil {
			return Document{}, err
		}
	}
	document, err := converter.document()
	if err != nil {
		return Document{}, err
	}
	if err := document.Validate(ctx); err != nil {
		return Document{}, err
	}
	return document, nil
}

type directiveSpec struct {
	attribute    string
	minimumArgs  int
	maximumArgs  int
	multiple     bool
	ordered      bool
	boolean      bool
	defaultValue string
	prefix       string
	literal      bool
}

func single(attribute string) directiveSpec {
	return directiveSpec{attribute: attribute, minimumArgs: 1, maximumArgs: 1, literal: true}
}

func joined(attribute string, minimum, maximum int) directiveSpec {
	return directiveSpec{attribute: attribute, minimumArgs: minimum, maximumArgs: maximum}
}

func multi(attribute string, minimum, maximum int) directiveSpec {
	return directiveSpec{
		attribute: attribute, minimumArgs: minimum, maximumArgs: maximum, multiple: true,
	}
}

func ordered(attribute string, minimum, maximum int) directiveSpec {
	return directiveSpec{
		attribute: attribute, minimumArgs: minimum, maximumArgs: maximum,
		multiple: true, ordered: true,
	}
}

func boolean(attribute string, optional bool) directiveSpec {
	minimum := 1
	defaultValue := ""
	if optional {
		minimum = 0
		defaultValue = "TRUE"
	}
	return directiveSpec{
		attribute: attribute, minimumArgs: minimum, maximumArgs: 1,
		boolean: true, defaultValue: defaultValue,
	}
}

type databaseEntry struct {
	name     string
	entry    *mutableEntry
	overlays []*mutableEntry
}

type schemaEntry struct {
	path  string
	entry *mutableEntry
}

type converter struct {
	global             *mutableEntry
	frontend           *databaseEntry
	config             *databaseEntry
	configDeclared     bool
	frontendDeclared   bool
	backends           []*mutableEntry
	currentBackend     *mutableEntry
	databases          []*databaseEntry
	currentDatabase    *databaseEntry
	currentOverlay     *mutableEntry
	currentOverlayName string
	module             *mutableEntry
	schemaOrder        []*schemaEntry
	nextDatabase       int
}

func newConverter() *converter {
	global := newMutableEntry("cn=config", "olcGlobal")
	global.add("cn", "config", false)
	frontendEntry := newMutableEntry(
		"olcDatabase={-1}frontend,cn=config",
		"olcDatabaseConfig", "olcFrontendConfig",
	)
	frontendEntry.add("olcDatabase", "{-1}frontend", false)
	configEntry := newMutableEntry(
		"olcDatabase={0}config,cn=config", "olcDatabaseConfig",
	)
	configEntry.add("olcDatabase", "{0}config", false)
	return &converter{
		global:       global,
		frontend:     &databaseEntry{name: "frontend", entry: frontendEntry},
		config:       &databaseEntry{name: "config", entry: configEntry},
		nextDatabase: 1,
	}
}

func (converter *converter) apply(directive Directive) error {
	if schemaAttribute, schema := schemaDirectives[directive.Name]; schema {
		return converter.applySchema(directive, schemaAttribute)
	}
	switch directive.Name {
	case "database":
		return converter.startDatabase(directive)
	case "backend":
		return converter.startBackend(directive)
	case "overlay":
		return converter.startOverlay(directive)
	case "modulepath":
		return converter.applyModulePath(directive)
	case "moduleload":
		return converter.applyModuleLoad(directive)
	}
	if spec, exists := rootDirectiveSpecs[directive.Name]; exists {
		return applySpec(converter.global, directive, spec)
	}
	if directive.Name == "monitoring" {
		if converter.currentDatabase == nil {
			return sourceError(directive.Position, errors.New("monitoring requires a database declaration"))
		}
		return applySpec(converter.currentDatabase.entry, directive, boolean("olcMonitoring", false))
	}
	if converter.currentBackend != nil {
		return sourceError(directive.Position, fmt.Errorf("unsupported backend-wide directive %q", directive.Name))
	}
	if spec, exists := databaseDirectiveSpecs[directive.Name]; exists {
		if converter.currentDatabase == nil || converter.currentDatabase == converter.frontend {
			return sourceError(directive.Position, fmt.Errorf("%s requires a database declaration", directive.Name))
		}
		return applySpec(converter.currentDatabase.entry, directive, spec)
	}
	if spec, exists := frontendOrDatabaseDirectiveSpecs[directive.Name]; exists {
		target := converter.frontend.entry
		if converter.currentDatabase != nil {
			target = converter.currentDatabase.entry
		}
		return applySpec(target, directive, spec)
	}
	if converter.currentOverlay != nil {
		if converter.currentOverlayName == "rwm" && isRWMCommonRewriteDirective(directive.Name) &&
			(converter.currentDatabase == nil ||
				(converter.currentDatabase.name != "ldap" && converter.currentDatabase.name != "relay")) {
			backend := "unknown"
			if converter.currentDatabase != nil {
				backend = converter.currentDatabase.name
			}
			return sourceError(directive.Position, fmt.Errorf(
				"%s is not supported on local backend %s; use an ldap or relay database, or use rwm-suffixmassage/olcRwmMap",
				directive.Name, backend,
			))
		}
		if converter.currentOverlayName == "dynlist" && (directive.Name == "attrpair" || directive.Name == "dynlist-attrpair") {
			if len(directive.Arguments) != 2 {
				return sourceError(directive.Position, errors.New("dynlist attribute pair requires member and URL attributes"))
			}
			directive.Arguments = []string{"groupOfURLs", directive.Arguments[1], directive.Arguments[0]}
			return applySpec(converter.currentOverlay, directive, ordered("olcDynListAttrSet", 3, 3))
		}
		if specs := overlayDirectiveSpecs[converter.currentOverlayName]; specs != nil {
			if spec, exists := specs[directive.Name]; exists {
				return applySpec(converter.currentOverlay, directive, spec)
			}
		}
	}
	if converter.currentDatabase != nil {
		if spec, exists := backendDirectiveSpecs[converter.currentDatabase.name][directive.Name]; exists {
			return applySpec(converter.currentDatabase.entry, directive, spec)
		}
	}
	if reason, exists := unsupportedDirectives[directive.Name]; exists {
		return sourceError(directive.Position, fmt.Errorf(
			"directive %q is not supported by ldap-go: %s", directive.Name, reason,
		))
	}
	if converter.currentOverlay != nil {
		return sourceError(directive.Position, fmt.Errorf(
			"unknown or unsupported %s overlay directive %q",
			converter.currentOverlayName, directive.Name,
		))
	}
	if converter.currentDatabase != nil {
		return sourceError(directive.Position, fmt.Errorf(
			"unknown or unsupported %s database directive %q",
			converter.currentDatabase.name, directive.Name,
		))
	}
	return sourceError(directive.Position, fmt.Errorf(
		"unknown or unsupported global directive %q", directive.Name,
	))
}

func isRWMCommonRewriteDirective(name string) bool {
	switch name {
	case "rwm-rewriteengine", "rwm-rewritecontext", "rwm-rewriterule",
		"rwm-rewritemap", "rwm-rewriteparam", "rwm-rewritemaxpasses", "rwm-rewrite":
		return true
	default:
		return false
	}
}

func (converter *converter) applySchema(directive Directive, attribute string) error {
	if len(directive.Arguments) == 0 {
		return sourceError(directive.Position, fmt.Errorf(
			"%s requires a schema description", directive.Name,
		))
	}
	key := directive.Position.Path
	// A parent may resume after a nested schema include. Preserve encounter
	// order so later definitions are not moved ahead of their dependencies.
	var schema *schemaEntry
	if len(converter.schemaOrder) > 0 && converter.schemaOrder[len(converter.schemaOrder)-1].path == key {
		schema = converter.schemaOrder[len(converter.schemaOrder)-1]
	}
	if schema == nil {
		base := filepath.Base(key)
		name := strings.TrimSuffix(base, filepath.Ext(base))
		if name == "" {
			name = "schema"
		}
		orderedName := fmt.Sprintf("{%d}%s", len(converter.schemaOrder), name)
		entry := newMutableEntry(
			"cn="+escapeDNValue(orderedName)+",cn=schema,cn=config",
			"olcSchemaConfig",
		)
		entry.add("cn", orderedName, false)
		entry.position = directive.Position
		schema = &schemaEntry{path: key, entry: entry}
		converter.schemaOrder = append(converter.schemaOrder, schema)
	}
	orderedValue := attribute == "olcAttributeTypes" ||
		attribute == "olcObjectClasses" || attribute == "olcDitContentRules" ||
		attribute == "olcLdapSyntaxes"
	schema.entry.add(attribute, strings.Join(directive.Arguments, " "), orderedValue)
	schema.entry.source(attribute, directive.Position)
	return nil
}

func (converter *converter) startDatabase(directive Directive) error {
	if len(directive.Arguments) != 1 {
		return sourceError(directive.Position, errors.New(
			"database requires exactly one backend name",
		))
	}
	name := strings.ToLower(directive.Arguments[0])
	converter.currentBackend = nil
	converter.currentOverlay = nil
	converter.currentOverlayName = ""
	switch name {
	case "frontend":
		if converter.frontendDeclared {
			return sourceError(directive.Position, errors.New("database frontend is declared more than once"))
		}
		converter.frontendDeclared = true
		converter.frontend.entry.position = directive.Position
		converter.currentDatabase = converter.frontend
		return nil
	case "config":
		if converter.configDeclared {
			return sourceError(directive.Position, errors.New(
				"database config is declared more than once",
			))
		}
		converter.configDeclared = true
		converter.config.entry.position = directive.Position
		converter.currentDatabase = converter.config
		return nil
	case "mdb", "monitor", "ldap", "ldif", "null", "relay":
		index := converter.nextDatabase
		converter.nextDatabase++
		value := fmt.Sprintf("{%d}%s", index, name)
		classes := []string{"olcDatabaseConfig"}
		if class := databaseObjectClasses[name]; class != "" {
			classes = append(classes, class)
		}
		entry := newMutableEntry(
			"olcDatabase="+escapeDNValue(value)+",cn=config", classes...,
		)
		entry.add("olcDatabase", value, false)
		entry.position = directive.Position
		database := &databaseEntry{name: name, entry: entry}
		converter.databases = append(converter.databases, database)
		converter.currentDatabase = database
		return nil
	default:
		return sourceError(directive.Position, fmt.Errorf(
			"database backend %q is not supported by this converter", name,
		))
	}
}

func (converter *converter) startOverlay(directive Directive) error {
	if converter.currentDatabase == nil {
		return sourceError(directive.Position, errors.New(
			"overlay must follow a database declaration",
		))
	}
	if len(directive.Arguments) != 1 {
		return sourceError(directive.Position, errors.New(
			"overlay requires exactly one overlay name",
		))
	}
	name := strings.ToLower(directive.Arguments[0])
	if name == "proxycache" {
		name = "pcache"
	}
	class, supported := overlayObjectClasses[name]
	if !supported {
		return sourceError(directive.Position, fmt.Errorf(
			"overlay %q is not implemented by ldap-go", name,
		))
	}
	index := len(converter.currentDatabase.overlays)
	value := fmt.Sprintf("{%d}%s", index, name)
	classes := []string{"olcOverlayConfig"}
	if class != "" {
		classes = append(classes, class)
	}
	entry := newMutableEntry(
		"olcOverlay="+escapeDNValue(value)+","+converter.currentDatabase.entry.dn,
		classes...,
	)
	entry.add("olcOverlay", value, false)
	entry.position = directive.Position
	converter.currentDatabase.overlays = append(converter.currentDatabase.overlays, entry)
	converter.currentOverlay = entry
	converter.currentOverlayName = name
	return nil
}

func (converter *converter) applyModulePath(directive Directive) error {
	if len(directive.Arguments) != 1 {
		return sourceError(directive.Position, errors.New(
			"modulepath requires exactly one path",
		))
	}
	module := converter.moduleEntry()
	if err := module.set("olcModulePath", directive.Arguments[0]); err != nil {
		return sourceError(directive.Position, err)
	}
	return nil
}

func (converter *converter) applyModuleLoad(directive Directive) error {
	if len(directive.Arguments) != 1 {
		return sourceError(directive.Position, errors.New(
			"moduleload requires one module name; native module arguments are unsupported",
		))
	}
	if !compatibleModule(directive.Arguments[0]) {
		return sourceError(directive.Position, fmt.Errorf(
			"module %q requires OpenLDAP native loading and is not available in pure Go",
			directive.Arguments[0],
		))
	}
	converter.moduleEntry().add(
		"olcModuleLoad", joinArguments(directive.Arguments), true,
	)
	converter.moduleEntry().source("olcModuleLoad", directive.Position)
	return nil
}

func (converter *converter) moduleEntry() *mutableEntry {
	if converter.module == nil {
		converter.module = newMutableEntry("cn=module{0},cn=config", "olcModuleList")
		converter.module.add("cn", "module{0}", false)
	}
	return converter.module
}

func (converter *converter) document() (Document, error) {
	for _, database := range converter.databases {
		if database.name == "mdb" {
			if _, configured := database.entry.byName["olcdbdirectory"]; !configured {
				return Document{}, sourceError(database.entry.position, errors.New("mdb database requires directory"))
			}
		}
	}
	for _, database := range converter.databases {
		if database.name != "monitor" {
			if _, configured := database.entry.byName["olcsuffix"]; !configured {
				return Document{}, sourceError(database.entry.position, errors.New("database requires suffix"))
			}
		}
	}
	entries := []Entry{converter.global.freeze()}
	if converter.module != nil {
		entries = append(entries, converter.module.freeze())
	}
	schemaRoot := newMutableEntry("cn=schema,cn=config", "olcSchemaConfig")
	schemaRoot.add("cn", "schema", false)
	entries = append(entries, schemaRoot.freeze())
	for _, schema := range converter.schemaOrder {
		entries = append(entries, schema.entry.freeze())
	}
	for _, backend := range converter.backends {
		entries = append(entries, backend.freeze())
	}
	for _, database := range append([]*databaseEntry{converter.frontend, converter.config}, converter.databases...) {
		entries = append(entries, database.entry.freeze())
		for _, overlay := range database.overlays {
			entries = append(entries, overlay.freeze())
		}
	}
	return Document{Entries: entries}, nil
}

func applySpec(entry *mutableEntry, directive Directive, spec directiveSpec) error {
	count := len(directive.Arguments)
	if count < spec.minimumArgs || (spec.maximumArgs >= 0 && count > spec.maximumArgs) {
		expected := fmt.Sprintf("%d", spec.minimumArgs)
		if spec.maximumArgs < 0 {
			expected = fmt.Sprintf("at least %d", spec.minimumArgs)
		} else if spec.minimumArgs != spec.maximumArgs {
			expected = fmt.Sprintf("%d..%d", spec.minimumArgs, spec.maximumArgs)
		}
		return sourceError(directive.Position, fmt.Errorf(
			"%s requires %s argument(s); got %d", directive.Name, expected, count,
		))
	}
	value := spec.defaultValue
	if count > 0 {
		if spec.boolean {
			var err error
			value, err = canonicalBoolean(directive.Arguments[0])
			if err != nil {
				return sourceError(directive.Position, fmt.Errorf("%s: %w", directive.Name, err))
			}
		} else if spec.literal || spec.maximumArgs == 1 {
			value = directive.Arguments[0]
		} else if directive.Name == "access" {
			var err error
			value, err = joinACLArguments(directive.Arguments)
			if err != nil {
				return sourceError(directive.Position, err)
			}
		} else {
			value = joinArguments(directive.Arguments)
		}
	}
	if spec.prefix != "" {
		value = spec.prefix + " " + value
	}
	if directive.Name == "subordinate" && count == 0 {
		value = "TRUE"
	}
	if strings.TrimSpace(value) == "" {
		return sourceError(directive.Position, fmt.Errorf("%s has an empty value", directive.Name))
	}
	if directive.Name == "maxentrysize" {
		size, err := mdbentry.ParseDirective(value)
		if err != nil {
			return sourceError(directive.Position, fmt.Errorf("maxentrysize requires an unsigned byte count: %w", err))
		}
		value = strconv.FormatUint(size, 10)
	}
	if directive.Name == "maxsize" {
		if size, err := strconv.ParseUint(value, 10, 64); err != nil || size == 0 {
			return sourceError(directive.Position, errors.New("maxsize requires a positive byte count"))
		}
	}
	if directive.Name == "syncrepl" {
		seen := make(map[string]bool)
		for _, argument := range directive.Arguments {
			key, _, _ := strings.Cut(argument, "=")
			key = strings.ToLower(key)
			if seen[key] {
				return sourceError(directive.Position, fmt.Errorf("duplicate syncrepl option %q", key))
			}
			seen[key] = true
		}
	}
	if spec.multiple || spec.ordered {
		entry.add(spec.attribute, value, spec.ordered)
		entry.source(spec.attribute, directive.Position)
		return nil
	}
	if err := entry.set(spec.attribute, value); err != nil {
		return sourceError(directive.Position, fmt.Errorf("%s: %w", directive.Name, err))
	}
	entry.source(spec.attribute, directive.Position)
	return nil
}

func canonicalBoolean(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "yes", "true", "1":
		return "TRUE", nil
	case "off", "no", "false", "0":
		return "FALSE", nil
	default:
		return "", fmt.Errorf("expected on/off or true/false, got %q", value)
	}
}

func compatibleModule(raw string) bool {
	if raw == "" || filepath.Base(raw) != raw || strings.ContainsRune(raw, '\\') {
		return false
	}
	name := raw
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "back_") {
		_, supported := databaseObjectClasses[strings.TrimPrefix(name, "back_")]
		return supported
	}
	if _, supported := overlayObjectClasses[name]; supported {
		return true
	}
	_, supported := map[string]struct{}{
		"argon2": {}, "pw-apr1": {}, "pw-netscape": {}, "pw-pbkdf2": {},
		"pw-radius": {}, "pw-sha2": {}, "pw-totp": {},
	}[name]
	return supported
}

var schemaDirectives = map[string]string{
	"attributetype":    "olcAttributeTypes",
	"ditcontentrule":   "olcDitContentRules",
	"ldapsyntax":       "olcLdapSyntaxes",
	"objectclass":      "olcObjectClasses",
	"objectidentifier": "olcObjectIdentifier",
}

var rootDirectiveSpecs = map[string]directiveSpec{
	"allows":                     joined("olcAllows", 1, -1),
	"authz-policy":               single("olcAuthzPolicy"),
	"authz-regexp":               ordered("olcAuthzRegexp", 2, 2),
	"conn_max_pending":           single("olcConnMaxPending"),
	"conn_max_pending_auth":      single("olcConnMaxPendingAuth"),
	"disallows":                  joined("olcDisallows", 1, -1),
	"gentlehup":                  boolean("olcGentleHUP", false),
	"idletimeout":                single("olcIdleTimeout"),
	"localssf":                   single("olcLocalSSF"),
	"logfile":                    single("olcLogFile"),
	"logfile-format":             single("olcLogFileFormat"),
	"logfile-only":               boolean("olcLogFileOnly", false),
	"logfile-rotate":             joined("olcLogFileRotate", 3, 3),
	"loglevel":                   multi("olcLogLevel", 1, -1),
	"maxfilterdepth":             single("olcMaxFilterDepth"),
	"password-crypt-salt-format": single("olcPasswordCryptSaltFormat"),
	"referral":                   multi("olcReferral", 1, 1),
	"reverse-lookup":             boolean("olcReverseLookup", false),
	"rootdse":                    single("olcRootDSE"),
	"sasl-host":                  single("olcSaslHost"),
	"sasl-realm":                 single("olcSaslRealm"),
	"sasl-secprops":              joined("olcSaslSecProps", 1, -1),
	"serverid":                   multi("olcServerID", 1, 2),
	"sockbuf_max_incoming":       single("olcSockbufMaxIncoming"),
	"sockbuf_max_incoming_auth":  single("olcSockbufMaxIncomingAuth"),
	"tlscacertificatefile":       single("olcTLSCACertificateFile"),
	"tlscacertificatepath":       single("olcTLSCACertificatePath"),
	"tlscertificatefile":         single("olcTLSCertificateFile"),
	"tlscertificatekeyfile":      single("olcTLSCertificateKeyFile"),
	"tlsciphersuite":             joined("olcTLSCipherSuite", 1, -1),
	"tlscrlcheck":                single("olcTLSCRLCheck"),
	"tlscrlfile":                 single("olcTLSCRLFile"),
	"tlsdhparamfile":             single("olcTLSDHParamFile"),
	"tlsecname":                  single("olcTLSECName"),
	"tlsprotocolmin":             single("olcTLSProtocolMin"),
	"tlsrandfile":                single("olcTLSRandFile"),
	"tlsverifyclient":            single("olcTLSVerifyClient"),
	"writetimeout":               single("olcWriteTimeout"),
}

var frontendOrDatabaseDirectiveSpecs = map[string]directiveSpec{
	"access":             ordered("olcAccess", 1, -1),
	"add_content_acl":    boolean("olcAddContentAcl", false),
	"defaultsearchbase":  single("olcDefaultSearchBase"),
	"disabled":           boolean("olcDisabled", false),
	"hidden":             boolean("olcHidden", false),
	"lastbind":           boolean("olcLastBind", true),
	"lastbind-precision": single("olcLastBindPrecision"),
	"lastmod":            boolean("olcLastMod", false),
	"limits":             ordered("olcLimits", 2, -1),
	"maxderefdepth":      single("olcMaxDerefDepth"),
	"mirrormode":         boolean("olcMirrorMode", false),
	"multiprovider":      boolean("olcMultiProvider", false),
	"password-hash":      multi("olcPasswordHash", 1, -1),
	"readonly":           boolean("olcReadOnly", false),
	"require":            joined("olcRequires", 1, -1),
	"restrict":           joined("olcRestrict", 1, -1),
	"schemadn":           single("olcSchemaDN"),
	"security":           joined("olcSecurity", 1, -1),
	"sizelimit":          joined("olcSizeLimit", 1, -1),
	"subordinate":        joined("olcSubordinate", 0, 1),
	"sync_use_subentry":  boolean("olcSyncUseSubentry", false),
	"timelimit":          joined("olcTimeLimit", 1, -1),
	"updatedn":           single("olcUpdateDN"),
	"updateref":          multi("olcUpdateRef", 1, 1),
}

var databaseDirectiveSpecs = map[string]directiveSpec{
	"rootdn":   single("olcRootDN"),
	"rootpw":   single("olcRootPW"),
	"suffix":   multi("olcSuffix", 1, 1),
	"syncrepl": ordered("olcSyncrepl", 1, -1),
}

var mdbDirectiveSpecs = map[string]directiveSpec{
	"maxentrysize": single("olcDbMaxEntrySize"),
	"directory":    single("olcDbDirectory"),
	"index":        multi("olcDbIndex", 1, 2),
	"maxsize":      single("olcDbMaxSize"),
}

var overlayObjectClasses = map[string]string{
	"accesslog": "olcAccessLogConfig", "allop": "", "auditlog": "olcAuditlogConfig",
	"autoca": "olcAutoCAConfig", "chain": "", "collect": "olcCollectConfig",
	"constraint": "olcConstraintConfig", "dds": "olcDDSConfig", "deref": "",
	"dyngroup": "olcDynGroupConfig", "dynlist": "olcDynListConfig", "glue": "", "homedir": "olcHomedirConfig",
	"lastbind": "olcLastBindConfig", "memberof": "olcMemberOfConfig", "nestgroup": "olcNestGroupConfig",
	"noopsrch": "", "nops": "", "otp": "", "pbind": "olcPBindConfig",
	"pcache": "olcPcacheConfig", "ppolicy": "olcPPolicyConfig", "refint": "olcRefintConfig",
	"remoteauth": "olcRemoteAuthCfg", "retcode": "olcRetcodeConfig", "rwm": "olcRwmConfig",
	"seqmod": "", "sock": "olcOvSocketConfig", "sssvlv": "olcSssVlvConfig",
	"syncprov": "olcSyncProvConfig", "totp": "", "translucent": "olcTranslucentConfig",
	"unique": "olcUniqueConfig", "valsort": "olcValSortConfig",
}

var overlayDirectiveSpecs = map[string]map[string]directiveSpec{
	"accesslog": {
		"logbase": multi("olcAccessLogBase", 2, 2), "logdb": single("olcAccessLogDB"),
		"logold": single("olcAccessLogOld"), "logoldattr": multi("olcAccessLogOldAttr", 1, -1),
		"logops": multi("olcAccessLogOps", 1, -1), "logpurge": joined("olcAccessLogPurge", 2, 2),
		"logsuccess": boolean("olcAccessLogSuccess", false),
	},
	"auditlog": {"auditlog": single("olcAuditlogFile")},
	"autoca": {
		"cadays": single("olcAutoCADays"), "cakeybits": single("olcAutoCAKeybits"),
		"localdn": single("olcAutoCAlocalDN"), "serverclass": single("olcAutoCAserverClass"),
		"serverdays": single("olcAutoCAserverDays"), "serverkeybits": single("olcAutoCAserverKeybits"),
		"userclass": single("olcAutoCAuserClass"), "userdays": single("olcAutoCAuserDays"),
		"userkeybits": single("olcAutoCAuserKeybits"),
	},
	"chain": {
		"chain-cache-uri":    boolean("olcChainCacheURI", false),
		"chain-chaining":     joined("olcChainingBehavior", 1, -1),
		"chain-max-depth":    single("olcChainMaxReferralDepth"),
		"chain-return-error": boolean("olcChainReturnError", false),
	},
	"collect":    {"collectinfo": multi("olcCollectInfo", 2, 2)},
	"constraint": {"constraint_attribute": multi("olcConstraintAttribute", 3, -1)},
	"dds": {
		"dds-default-ttl": single("olcDDSdefaultTtl"), "dds-interval": single("olcDDSinterval"),
		"dds-max-dynamicobjects": single("olcDDSmaxDynamicObjects"),
		"dds-max-ttl":            single("olcDDSmaxTtl"), "dds-min-ttl": single("olcDDSminTtl"),
		"dds-state": boolean("olcDDSstate", false), "dds-tolerance": single("olcDDStolerance"),
	},
	"dyngroup": {"attrpair": multi("olcDynGroupAttrPair", 2, 2)},
	"dynlist": {
		"attrpair":         multi("olcDynGroupAttrPair", 2, 2),
		"dynlist-attrpair": multi("olcDynListAttrSet", 2, 2),
		"dynlist-attrset":  ordered("olcDynListAttrSet", 2, -1),
		"dynlist-simple":   boolean("olcDynListSimple", true),
	},
	"homedir": {
		"homedir-archive-path":  single("olcHomedirArchivePath"),
		"homedir-delete-style":  single("olcHomedirDeleteStyle"),
		"homedir-min-uidnumber": single("olcMinimumUidNumber"),
		"homedir-regexp":        ordered("olcHomedirRegexp", 2, 2),
		"homedir-skeleton-path": single("olcSkeletonPath"),
	},
	"lastbind": {"lastbind-forward-updates": boolean("olcLastBindForwardUpdates", true)},
	"memberof": {
		"memberof-addcheck":       boolean("olcMemberOfAddCheck", false),
		"memberof-dangling":       single("olcMemberOfDangling"),
		"memberof-dangling-error": single("olcMemberOfDanglingError"),
		"memberof-dn":             single("olcMemberOfDN"), "memberof-group-oc": single("olcMemberOfGroupOC"),
		"memberof-member-ad":   single("olcMemberOfMemberAD"),
		"memberof-memberof-ad": single("olcMemberOfMemberOfAD"),
		"memberof-refint":      boolean("olcMemberOfRefInt", false),
		"memberof-reverse":     boolean("olcMemberOfReverse", false),
	},
	"nestgroup": {
		"nestgroup-base":     multi("olcNestGroupBase", 1, 1),
		"nestgroup-flags":    multi("olcNestGroupFlags", 1, -1),
		"nestgroup-member":   single("olcNestGroupMember"),
		"nestgroup-memberof": single("olcNestGroupMemberOf"),
	},
	"pbind": {
		"network-timeout": single("olcDbNetworkTimeout"), "quarantine": joined("olcDbQuarantine", 1, -1),
		"tls": joined("olcDbStartTLS", 1, -1), "uri": joined("olcDbURI", 1, -1),
	},
	"pcache": {
		"pcache": joined("olcPcache", 5, 5), "pcacheattrset": multi("olcPcacheAttrset", 2, -1),
		"pcachebind": multi("olcPcacheBind", 5, 5), "pcachemaxqueries": single("olcPcacheMaxQueries"),
		"pcacheoffline": boolean("olcPcacheOffline", false),
		"pcachepersist": boolean("olcPcachePersist", false), "pcacheposition": single("olcPcachePosition"),
		"pcachetemplate": multi("olcPcacheTemplate", 3, 6), "pcachevalidate": boolean("olcPcacheValidate", false),
		"proxyattrset": multi("olcProxyAttrset", 2, -1), "proxycache": joined("olcProxyCache", 5, 5),
		"proxycachequeries":      single("olcProxyCacheQueries"),
		"proxycheckcacheability": boolean("olcProxyCheckCacheability", false),
		"proxysavequeries":       boolean("olcProxySaveQueries", false),
		"proxytemplate":          multi("olcProxyCacheTemplate", 3, 4),
		"response-callback":      single("olcPcachePosition"),
	},
	"ppolicy": {
		"ppolicy_check_module":           single("olcPPolicyCheckModule"),
		"ppolicy_default":                single("olcPPolicyDefault"),
		"ppolicy_disable_write":          boolean("olcPPolicyDisableWrite", true),
		"ppolicy_forward_updates":        boolean("olcPPolicyForwardUpdates", true),
		"ppolicy_hash_cleartext":         boolean("olcPPolicyHashCleartext", true),
		"ppolicy_send_netscape_controls": boolean("olcPPolicySendNetscapeControls", true),
		"ppolicy_use_lockout":            boolean("olcPPolicyUseLockout", true),
	},
	"refint": {
		"refint_attributes":    multi("olcRefintAttribute", 1, -1),
		"refint_modifiersname": single("olcRefintModifiersName"),
		"refint_nothing":       single("olcRefintNothing"),
	},
	"remoteauth": {
		"remoteauth_default_domain":   single("olcRemoteAuthDefaultDomain"),
		"remoteauth_default_realm":    single("olcRemoteAuthDefaultRealm"),
		"remoteauth_dn_attribute":     single("olcRemoteAuthDNAttribute"),
		"remoteauth_domain_attribute": single("olcRemoteAuthDomainAttribute"),
		"remoteauth_mapping":          multi("olcRemoteAuthMapping", 1, 2),
		"remoteauth_retry_count":      single("olcRemoteAuthRetryCount"),
		"remoteauth_store":            boolean("olcRemoteAuthStore", true),
		"remoteauth_tls":              joined("olcRemoteAuthTLS", 1, -1),
		"remoteauth_tls_peerkey_hash": multi("olcRemoteAuthTLSPeerkeyHash", 2, 2),
	},
	"retcode": {
		"retcode-indir": boolean("olcRetcodeInDir", false), "retcode-item": multi("olcRetcodeItem", 2, -1),
		"retcode-parent": single("olcRetcodeParent"), "retcode-sleep": single("olcRetcodeSleep"),
	},
	"rwm": {
		"rwm-rewriteengine":    {attribute: "olcRwmRewrite", minimumArgs: 1, maximumArgs: 1, multiple: true, ordered: true, prefix: "rwm-rewriteEngine"},
		"rwm-rewritecontext":   {attribute: "olcRwmRewrite", minimumArgs: 1, maximumArgs: 3, multiple: true, ordered: true, prefix: "rwm-rewriteContext"},
		"rwm-rewriterule":      {attribute: "olcRwmRewrite", minimumArgs: 2, maximumArgs: 3, multiple: true, ordered: true, prefix: "rwm-rewriteRule"},
		"rwm-rewritemap":       {attribute: "olcRwmRewrite", minimumArgs: 2, maximumArgs: -1, multiple: true, ordered: true, prefix: "rwm-rewriteMap"},
		"rwm-rewriteparam":     {attribute: "olcRwmRewrite", minimumArgs: 2, maximumArgs: 2, multiple: true, ordered: true, prefix: "rwm-rewriteParam"},
		"rwm-rewritemaxpasses": {attribute: "olcRwmRewrite", minimumArgs: 1, maximumArgs: 2, multiple: true, ordered: true, prefix: "rwm-rewriteMaxPasses"},
		"rwm-map":              ordered("olcRwmMap", 2, 3),
		"rwm-rewrite":          {attribute: "olcRwmRewrite", minimumArgs: 1, maximumArgs: -1, multiple: true, ordered: true, prefix: "rwm-rewrite"},
		"rwm-suffixmassage":    {attribute: "olcRwmRewrite", minimumArgs: 1, maximumArgs: 2, multiple: true, ordered: true, prefix: "rwm-suffixmassage"},
	},
	"sock": {
		"sockdnpat": single("olcOvSocketDNpat"), "sockops": joined("olcOvSocketOps", 1, -1),
		"sockresps": joined("olcOvSocketResps", 1, -1),
	},
	"sssvlv": {
		"sssvlv-max": single("olcSssVlvMax"), "sssvlv-maxkeys": single("olcSssVlvMaxKeys"),
		"sssvlv-maxperconn": single("olcSssVlvMaxPerConn"),
	},
	"syncprov": {
		"syncprov-checkpoint": joined("olcSpCheckpoint", 2, 2),
		"syncprov-nopresent":  boolean("olcSpNoPresent", false),
		"syncprov-reloadhint": boolean("olcSpReloadHint", false),
		"syncprov-sessionlog": single("olcSpSessionlog"),
	},
	"translucent": {
		"translucent_bind_local":  boolean("olcTranslucentBindLocal", true),
		"translucent_local":       joined("olcTranslucentLocal", 1, -1),
		"translucent_no_glue":     boolean("olcTranslucentNoGlue", true),
		"translucent_pwmod_local": boolean("olcTranslucentPwModLocal", true),
		"translucent_remote":      joined("olcTranslucentRemote", 1, -1),
		"translucent_strict":      boolean("olcTranslucentStrict", true),
	},
	"unique": {
		"unique_attributes": multi("olcUniqueAttribute", 1, -1),
		"unique_base":       single("olcUniqueBase"), "unique_ignore": multi("olcUniqueIgnore", 1, -1),
		"unique_strict": boolean("olcUniqueStrict", true), "unique_uri": multi("olcUniqueURI", 1, 2),
	},
	"valsort": {"valsort-attr": multi("olcValSortAttr", 3, 4)},
}

var unsupportedDirectives = map[string]string{
	"argsfile":            "process argument files are managed by the service manager",
	"checkpoint":          "LMDB checkpoint scheduling does not apply to bbolt",
	"concurrency":         "the historical thread concurrency hint is obsolete",
	"dbnosync":            "ldap-go does not permit weakening bbolt durability through cn=config",
	"envflags":            "LMDB environment flags do not apply to bbolt",
	"idlexp":              "LMDB IDL sizing does not apply to bbolt",
	"listener-threads":    "listener concurrency is configured by process options",
	"maxreaders":          "LMDB reader slots do not apply to bbolt",
	"mode":                "database file permissions are controlled by the bbolt file",
	"multival":            "LMDB multivalue split thresholds do not apply to bbolt",
	"pidfile":             "the ldap-go serve command owns PID file configuration",
	"plugin":              "SLAPI plugins require the OpenLDAP native ABI",
	"replica":             "slurpd replication is obsolete; use syncrepl",
	"replica-argsfile":    "slurpd replication is not implemented",
	"replica-pidfile":     "slurpd replication is not implemented",
	"replicationinterval": "slurpd replication is not implemented",
	"replogfile":          "slurpd replication is not implemented",
	"rtxnsize":            "LMDB read transaction sizing does not apply to bbolt",
	"sasl-cbinding":       "server SASL channel-binding policy is not implemented",
	"searchstack":         "OpenLDAP's search stack limit is not implemented",
	"threads":             "worker concurrency is configured by process options",
	"threadqueues":        "worker queues are configured by process options",
	"tool-threads":        "offline tool concurrency is not configured through cn=config",
}
