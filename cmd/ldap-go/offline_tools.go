package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type repeatedOfflineOption []string

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
	flags.String("H", "", "unsupported LDAP URL selector")
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
	if err := rejectUnsupportedFlags("slapschema", flags, []unsupportedFlag{
		{name: "H", reason: "use -b, -s, and -a with the embedded cn=config database"},
	}); err != nil {
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
	skipSchema := flags.Bool("s", false, "disable schema checking")
	serverID := flags.Int("S", 0, "server ID for generated entryCSN values")
	resumeLine := flags.Int("j", 0, "skip records beginning before this physical line")
	updateContextCSN := flags.Bool("w", false, "update contextCSN from committed entryCSN values")
	flags.Bool("v", false, "write a completion summary")
	registerOfflineConfigFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := rejectOfflineConfigFlags("slapmodify", flags); err != nil {
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
		{name: "s", enabled: *skipSchema},
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
			SkipSchema: *skipSchema, SkipValueValidation: *quick,
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
