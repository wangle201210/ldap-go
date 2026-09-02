package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type repeatedOfflineOption []string

type offlineLDAPSelector struct {
	baseDN string
	scope  directory.Scope
	filter string
}

func parseOfflineLDAPURL(raw string) (offlineLDAPSelector, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return offlineLDAPSelector{}, fmt.Errorf("parse LDAP URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "ldap") {
		return offlineLDAPSelector{}, errors.New("offline selector must use ldap://")
	}
	if parsed.Host != "" || parsed.User != nil {
		return offlineLDAPSelector{}, errors.New("offline LDAP URL cannot contain a host or userinfo")
	}
	components := []string(nil)
	if parsed.RawQuery != "" || parsed.ForceQuery {
		components = strings.Split(parsed.RawQuery, "?")
	}
	if len(components) > 0 && components[0] != "" {
		return offlineLDAPSelector{}, errors.New("offline LDAP URL cannot select attributes")
	}
	if len(components) > 3 {
		return offlineLDAPSelector{}, errors.New("offline LDAP URL cannot contain extensions")
	}
	direct, err := parseLDAPSearchDirectURL(raw)
	if err != nil {
		return offlineLDAPSelector{}, err
	}
	if !direct.direct || strings.TrimSpace(direct.baseDN) == "" {
		return offlineLDAPSelector{}, errors.New("offline LDAP URL requires a non-empty base DN")
	}
	if len(direct.attributes) != 0 {
		return offlineLDAPSelector{}, errors.New("offline LDAP URL cannot select attributes")
	}
	return offlineLDAPSelector{
		baseDN: direct.baseDN,
		scope:  directory.Scope(direct.scope),
		filter: direct.filter,
	}, nil
}

func (values *repeatedOfflineOption) String() string {
	return strings.Join(*values, ",")
}

func (values *repeatedOfflineOption) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func registerOfflineConfigFlags(
	flags *flag.FlagSet,
) (configFile, configDirectory, debugLevel *string, options *repeatedOfflineOption) {
	configFile = flags.String("f", "", "OpenLDAP slapd.conf path")
	configDirectory = flags.String("F", "", "OpenLDAP config directory")
	debugLevel = flags.String("d", "", "OpenLDAP debug level")
	var values repeatedOfflineOption
	flags.Var(&values, "o", "OpenLDAP generic tool option")
	return configFile, configDirectory, debugLevel, &values
}

func rejectOfflineConfigFlags(command string, flags *flag.FlagSet) error {
	return rejectUnsupportedFlags(command, flags, []unsupportedFlag{
		{name: "f", reason: "ldap-go loads cn=config from -db and cannot consume slapd.conf"},
		{name: "F", reason: "ldap-go loads cn=config from -db and cannot consume an OpenLDAP config directory"},
		{name: "d", reason: "the embedded offline runtime has no OpenLDAP debug subsystem"},
		{name: "o", reason: "OpenLDAP process and syslog tool options do not apply to ldap-go"},
	})
}

func runSlapACL(args []string, stdout, stderr io.Writer) (runErr error) {
	flags := flag.NewFlagSet("slapacl", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "database path")
	targetDN := flags.String("b", "", "target entry DN")
	authenticationDN := flags.String("D", "", "authentication DN")
	authenticationID := flags.String("U", "", "authentication ID")
	authorizationID := flags.String("X", "", "authorization ID")
	dryRun := flags.Bool("u", false, "use an empty synthetic target entry")
	verbose := flags.Bool("v", false, "print normalized identities")
	flags.String("f", "", "unsupported OpenLDAP slapd.conf path")
	flags.String("F", "", "unsupported OpenLDAP config directory")
	flags.String("d", "", "unsupported OpenLDAP debug level")
	var rawOptions repeatedOfflineOption
	flags.Var(&rawOptions, "o", "ACL session option name=value")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := rejectUnsupportedFlags("slapacl", flags, []unsupportedFlag{
		{name: "f", reason: "ldap-go loads cn=config from -db and cannot consume slapd.conf"},
		{name: "F", reason: "ldap-go loads cn=config from -db and cannot consume an OpenLDAP config directory"},
		{name: "d", reason: "the embedded offline runtime has no OpenLDAP debug subsystem"},
	}); err != nil {
		return err
	}
	if strings.TrimSpace(*targetDN) == "" {
		return errors.New("slapacl option -b requires a non-empty target DN")
	}
	if *authenticationDN != "" && *authenticationID != "" {
		return errors.New("slapacl options -D and -U are mutually exclusive")
	}
	if flagWasSet(flags, "D") && *authenticationDN == "" {
		return errors.New("slapacl option -D requires a non-empty authentication DN")
	}
	if flagWasSet(flags, "U") && *authenticationID == "" {
		return errors.New("slapacl option -U requires a non-empty authentication ID")
	}
	if flagWasSet(flags, "X") && *authorizationID == "" {
		return errors.New("slapacl option -X requires a non-empty authorization ID")
	}
	if flagWasSet(flags, "u") && !*dryRun {
		return errors.New("slapacl option -u=false is not supported")
	}
	if flagWasSet(flags, "v") && !*verbose {
		return errors.New("slapacl option -v=false is not supported")
	}

	request := server.OfflineACLRequest{
		TargetDN: *targetDN, AuthenticationDN: *authenticationDN,
		AuthenticationID: *authenticationID, AuthorizationID: *authorizationID,
		DryRun: *dryRun,
	}
	for _, raw := range rawOptions {
		if err := applySlapACLOption(&request, raw); err != nil {
			return err
		}
	}
	if request.AuthorizationDN != "" && request.AuthorizationID != "" {
		return errors.New("slapacl options -X and -o authzDN are mutually exclusive")
	}
	for _, raw := range flags.Args() {
		check, err := parseSlapACLCheck(raw)
		if err != nil {
			return err
		}
		request.Checks = append(request.Checks, check)
	}

	store, err := storage.OpenBoltReadOnly(*databasePath)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, store.Close()) }()
	report, err := server.CheckOfflineACL(context.Background(), store, request)
	if err != nil {
		return err
	}
	if report.AuthenticationDN != "" &&
		(*verbose || *authenticationDN != "" || *authenticationID != "") {
		if _, err := fmt.Fprintf(stderr, "authcDN: \"%s\"\n", report.AuthenticationDN); err != nil {
			return err
		}
	}
	if report.AuthorizationDN != "" {
		if _, err := fmt.Fprintf(stderr, "authzDN: \"%s\"\n", report.AuthorizationDN); err != nil {
			return err
		}
	}
	for _, result := range report.Checks {
		value := string(result.Value)
		if result.HasValue && result.Access == "" &&
			strings.EqualFold(strings.Split(result.Attribute, ";")[0], "userPassword") {
			value = "****"
		}
		nameValue := result.Attribute
		if result.HasValue {
			nameValue += "=" + value
		}
		if result.Access != "" {
			status := "DENIED"
			if result.Allowed {
				status = "ALLOWED"
			}
			if _, err := fmt.Fprintf(
				stderr, "%s access to %s: %s\n", result.Access, nameValue, status,
			); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(stderr, "%s: %s\n", nameValue, result.Mask); err != nil {
			return err
		}
	}
	_ = stdout
	return nil
}

func applySlapACLOption(request *server.OfflineACLRequest, raw string) error {
	name, value, found := strings.Cut(raw, "=")
	name = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
	if !found || name == "" {
		return fmt.Errorf("invalid slapacl option %q; expected name=value", raw)
	}
	switch name {
	case "authzdn":
		if strings.TrimSpace(value) == "" {
			return errors.New("slapacl authzDN option requires a non-empty DN")
		}
		request.AuthorizationDN = value
	case "domain":
		request.Domain = value
	case "peername":
		request.PeerName = value
	case "sockname":
		request.SockName = value
	case "sockurl":
		request.SockURL = value
	case "ssf", "transport_ssf", "tls_ssf", "sasl_ssf":
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			return fmt.Errorf("slapacl option %s requires a non-negative integer", name)
		}
		switch name {
		case "ssf":
			request.SSF = parsed
		case "transport_ssf":
			request.TransportSSF = parsed
		case "tls_ssf":
			request.TLSSSF = parsed
		case "sasl_ssf":
			request.SASLSSF = parsed
		}
	default:
		return fmt.Errorf("unsupported slapacl option %q", name)
	}
	return nil
}

func parseSlapACLCheck(raw string) (server.OfflineACLCheckRequest, error) {
	check := server.OfflineACLCheckRequest{}
	attributeAccess, value, hasValue := strings.Cut(raw, ":")
	attribute, access, hasAccess := strings.Cut(attributeAccess, "/")
	check.Attribute = strings.TrimSpace(attribute)
	if check.Attribute == "" {
		return check, fmt.Errorf("invalid slapacl attribute request %q", raw)
	}
	if hasAccess {
		check.Access = strings.TrimSpace(access)
		if check.Access == "" {
			return check, fmt.Errorf("invalid slapacl access in %q", raw)
		}
	}
	if hasValue {
		check.Value = []byte(value)
		check.HasValue = true
	}
	return check, nil
}

func runSlapAuth(args []string, stdout, stderr io.Writer) (runErr error) {
	flags := flag.NewFlagSet("slapauth", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "database path")
	mechanism := flags.String("M", "", "SASL mechanism")
	realm := flags.String("R", "", "SASL realm")
	authenticationID := flags.String("U", "", "fixed authentication ID")
	authorizationID := flags.String("X", "", "fixed authorization ID")
	flags.Bool("v", false, "verbose output")
	registerOfflineConfigFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := rejectOfflineConfigFlags("slapauth", flags); err != nil {
		return err
	}
	if flagWasSet(flags, "U") && *authenticationID == "" {
		return errors.New("slapauth option -U requires a non-empty authentication ID")
	}
	if flagWasSet(flags, "X") && *authorizationID == "" {
		return errors.New("slapauth option -X requires a non-empty authorization ID")
	}
	if *authenticationID != "" && *authorizationID != "" && flags.NArg() != 0 {
		return errors.New("slapauth does not accept ID arguments when both -U and -X are set")
	}
	if *authenticationID == "" && flags.NArg() == 0 {
		return errors.New("slapauth requires -U or at least one ID")
	}

	store, err := storage.OpenBoltReadOnly(*databasePath)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, store.Close()) }()

	type check struct {
		authentication string
		authorization  string
		display        string
	}
	var checks []check
	switch {
	case *authenticationID != "" && (*authorizationID != "" || flags.NArg() == 0):
		checks = append(checks, check{
			authentication: *authenticationID,
			authorization:  *authorizationID,
			display:        *authenticationID,
		})
	case *authenticationID != "":
		for _, identity := range flags.Args() {
			checks = append(checks, check{
				authentication: *authenticationID,
				authorization:  identity,
				display:        *authenticationID,
			})
		}
	default:
		for _, identity := range flags.Args() {
			checks = append(checks, check{
				authentication: identity,
				authorization:  *authorizationID,
				display:        identity,
			})
		}
	}
	for _, candidate := range checks {
		result, err := server.CheckOfflineAuthorization(
			context.Background(), store, *mechanism, *realm,
			candidate.authentication, candidate.authorization,
		)
		if err != nil {
			fmt.Fprintf(stderr, "ID: <%s> check failed: %v\n", candidate.display, err)
			return err
		}
		if candidate.authorization == "" {
			if _, err := fmt.Fprintf(
				stderr,
				"ID: <%s> check succeeded\nauthcID:     <%s>\n",
				candidate.display,
				result.AuthenticationDN,
			); err != nil {
				return err
			}
			continue
		}
		status := "failed"
		if result.Authorized {
			status = "OK"
		}
		if _, err := fmt.Fprintf(
			stderr,
			"ID:      <%s>\nauthcDN: <%s>\nauthzDN: <%s>\nauthorization %s\n",
			candidate.display,
			result.AuthenticationDN,
			result.AuthorizationDN,
			status,
		); err != nil {
			return err
		}
	}
	_ = stdout
	return nil
}

func runSlapSchema(args []string, stdout, stderr io.Writer) (runErr error) {
	flags := flag.NewFlagSet("slapschema", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "database path")
	database := flags.String("database", "", "OpenLDAP database selector")
	suffix := flags.String("b", "", "select database by suffix")
	databaseNumber := flags.Int("n", -1, "select database by number")
	continueOnError := flags.Bool("c", false, "continue after schema violations")
	disableSubordinateGlue := flags.Bool("g", false, "disable subordinate gluing")
	filter := flags.String("a", "", "check entries matching this LDAP filter")
	subtree := flags.String("s", "", "check entries in this subtree")
	errorPath := flags.String("l", "", "write schema errors to this file")
	selectorURL := flags.String("H", "", "LDAP URL base, scope, and filter selector")
	verbose := flags.Bool("v", false, "print stable entry IDs")
	registerOfflineConfigFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := rejectOfflineConfigFlags("slapschema", flags); err != nil {
		return err
	}
	if flagWasSet(flags, "c") && !*continueOnError {
		return errors.New("slapschema option -c=false is not supported")
	}
	if flagWasSet(flags, "g") && !*disableSubordinateGlue {
		return errors.New("slapschema option -g=false is not supported")
	}
	if flagWasSet(flags, "s") && strings.TrimSpace(*subtree) == "" {
		return errors.New("slapschema option -s requires a non-empty subtree DN")
	}
	scope := directory.ScopeWholeSubtree
	scopeSet := false
	if *selectorURL != "" {
		if flagWasSet(flags, "a") || flagWasSet(flags, "s") {
			return errors.New("slapschema option -H cannot be combined with -a or -s")
		}
		selector, err := parseOfflineLDAPURL(*selectorURL)
		if err != nil {
			return fmt.Errorf("slapschema -H: %w", err)
		}
		*subtree = selector.baseDN
		*filter = selector.filter
		scope = selector.scope
		scopeSet = true
	}
	selected, err := resolveOfflineDatabaseSelection(
		"slapschema", flags, *databasePath, *database, *suffix,
		*databaseNumber, *subtree,
	)
	if err != nil {
		return err
	}

	store, err := storage.OpenBoltReadOnly(*databasePath)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, store.Close()) }()
	report, err := server.CheckOfflineSchema(
		context.Background(), store, server.OfflineSchemaOptions{
			Database: selected, IncludeSubordinates: !*disableSubordinateGlue,
			Continue: *continueOnError, Subtree: *subtree, Filter: *filter,
			Scope: scope, ScopeSet: scopeSet,
		},
	)
	if err != nil {
		return err
	}
	output := stdout
	var file *os.File
	if flagWasSet(flags, "l") {
		if *errorPath == "" || *errorPath == "-" {
			if *errorPath == "" {
				return errors.New("slapschema option -l requires a file path")
			}
		} else {
			file, err = os.OpenFile(*errorPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("open slapschema error file: %w", err)
			}
			defer func() { runErr = errors.Join(runErr, file.Close()) }()
			output = file
		}
	}
	if *verbose {
		for _, record := range report.Records {
			if _, err := fmt.Fprintf(stdout, "# id=%08x\n", record.EntryID); err != nil {
				return err
			}
		}
	}
	for _, issue := range report.Issues {
		if _, err := fmt.Fprintf(
			output,
			"# (%d) %s: %v\ndn: %s\n\n",
			issue.Code,
			openLDAPResultName(issue.Code),
			issue.Err,
			issue.DN,
		); err != nil {
			return err
		}
	}
	if len(report.Issues) != 0 {
		return &ldapClientExitError{code: int(report.Issues[len(report.Issues)-1].Code)}
	}
	return nil
}

func runSlapModify(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) (runErr error) {
	flags := flag.NewFlagSet("slapmodify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "database path")
	database := flags.String("database", "", "OpenLDAP database selector")
	suffix := flags.String("b", "", "select database by suffix")
	databaseNumber := flags.Int("n", -1, "select database by number")
	continueOnError := flags.Bool("c", false, "continue after failed records")
	disableSubordinateGlue := flags.Bool("g", false, "disable subordinate gluing")
	inputPath := flags.String("l", "-", "LDIF change file, or - for stdin")
	dryRun := flags.Bool("u", false, "validate and roll back all changes")
	quick := flags.Bool("q", false, "skip value syntax checks")
	skipSchema := false
	flags.BoolFunc("s", "disable schema checking", func(value string) error {
		if value != "true" {
			return errors.New("slapmodify option -s=false is not supported")
		}
		skipSchema = true
		return nil
	})
	serverID := flags.Int("S", 0, "server ID for generated entryCSN values")
	resumeLine := flags.Int("j", 0, "skip records beginning before this physical line")
	updateContextCSN := flags.Bool("w", false, "update contextCSN from committed entryCSN values")
	flags.Bool("v", false, "write a completion summary")
	flags.String("f", "", "OpenLDAP slapd.conf path")
	flags.String("F", "", "OpenLDAP config directory")
	flags.String("d", "", "OpenLDAP debug level")
	var skipValueValidation bool
	var valueCheckExplicit, valueCheckEnabled bool
	flags.Func("o", "set slapmodify tool option", func(raw string) error {
		name, value, found := strings.Cut(raw, "=")
		if !found || strings.TrimSpace(name) == "" {
			return fmt.Errorf(
				"invalid slapmodify option %q; expected name=yes|no",
				raw,
			)
		}
		enabled := false
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "yes":
			enabled = true
		case "no":
		default:
			return fmt.Errorf(
				"invalid slapmodify option %q; value must be yes or no",
				raw,
			)
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "schema-check":
			skipSchema = !enabled
		case "value-check":
			valueCheckExplicit = true
			valueCheckEnabled = enabled
			skipValueValidation = !enabled
		default:
			return fmt.Errorf("unsupported slapmodify option %q", name)
		}
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := rejectUnsupportedFlags("slapmodify", flags, []unsupportedFlag{
		{name: "f", reason: "ldap-go loads cn=config from -db and cannot consume slapd.conf"},
		{name: "F", reason: "ldap-go loads cn=config from -db and cannot consume an OpenLDAP config directory"},
		{name: "d", reason: "the embedded offline runtime has no OpenLDAP debug subsystem"},
	}); err != nil {
		return err
	}
	for _, option := range []struct {
		name    string
		enabled bool
	}{
		{name: "c", enabled: *continueOnError},
		{name: "g", enabled: *disableSubordinateGlue},
		{name: "u", enabled: *dryRun},
		{name: "q", enabled: *quick},
		{name: "w", enabled: *updateContextCSN},
	} {
		if flagWasSet(flags, option.name) && !option.enabled {
			return fmt.Errorf("slapmodify option -%s=false is not supported", option.name)
		}
	}
	if *serverID < 0 || *serverID > 0x0fff {
		return fmt.Errorf("slapmodify server ID must be between 0 and %d", 0x0fff)
	}
	if *resumeLine < 0 {
		return errors.New("slapmodify option -j requires a non-negative line number")
	}
	if *quick {
		if valueCheckExplicit && valueCheckEnabled {
			if _, err := fmt.Fprintln(
				stderr,
				"slapmodify: value-check incompatible with quick mode; disabled.",
			); err != nil {
				return err
			}
		}
		skipValueValidation = true
	}
	selected, err := resolveOfflineDatabaseSelection(
		"slapmodify", flags, *databasePath, *database, *suffix,
		*databaseNumber, "",
	)
	if err != nil {
		return err
	}
	reader := stdin
	var input *os.File
	if *inputPath != "-" {
		input, err = os.Open(*inputPath)
		if err != nil {
			return fmt.Errorf("open slapmodify LDIF: %w", err)
		}
		defer func() { runErr = errors.Join(runErr, input.Close()) }()
		reader = input
	}
	store, err := storage.OpenBolt(*databasePath)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, store.Close()) }()
	report, err := server.ApplyOfflineChanges(
		context.Background(), store, reader, server.OfflineModifyOptions{
			Database: selected, IncludeSubordinates: !*disableSubordinateGlue,
			Continue: *continueOnError, DryRun: *dryRun,
			SkipSchema: skipSchema, SkipValueValidation: skipValueValidation,
			ServerID: uint16(*serverID), ResumeLine: *resumeLine,
			UpdateContextCSN: *updateContextCSN,
		},
	)
	for _, failure := range report.Failures {
		fmt.Fprintf(
			stderr,
			"slapmodify: line %d: dn=%q: %v\n",
			failure.Line,
			failure.DN,
			failure.Err,
		)
	}
	if err != nil {
		return err
	}
	if flagWasSet(flags, "v") {
		action := "applied"
		if *dryRun {
			action = "validated"
		}
		_, err = fmt.Fprintf(stdout, "slapmodify: %s %d change record(s)\n", action, report.Applied)
	}
	return err
}
