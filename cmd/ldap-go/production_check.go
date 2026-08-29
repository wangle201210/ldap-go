package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	productionCheckExitNotReady     = 3
	productionCheckExitInconclusive = 4
	productionMinimumPBKDF2Rounds   = 100_000
)

var (
	productionSecretAssignmentPattern = regexp.MustCompile(
		`(?i)(credential|credentials|password|passwd|rootpw|bindpw|olcrootpw|secret|token|private[_-]?key)([=:][^\s,;"'}\]]+|\s*=\s*"[^"]*")`,
	)
	productionURLUserInfoPattern   = regexp.MustCompile(`://[^/@\s]+@`)
	productionPasswordValuePattern = regexp.MustCompile(
		`\{[A-Za-z0-9_-]+\}[^\s,;"'}\]]+`,
	)
	productionArgon2Pattern = regexp.MustCompile(
		`^\$argon2(?:id|i|d)\$v=(?:16|19)\$m=([0-9]+),t=([0-9]+),p=([0-9]+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$`,
	)
)

type productionCheckStatus string

const (
	productionCheckPass    productionCheckStatus = "pass"
	productionCheckWarn    productionCheckStatus = "warn"
	productionCheckFail    productionCheckStatus = "fail"
	productionCheckUnknown productionCheckStatus = "unknown"
)

type productionCheckFinding struct {
	ID          string                `json:"id"`
	Category    string                `json:"category"`
	Status      productionCheckStatus `json:"status"`
	Summary     string                `json:"summary"`
	Evidence    []string              `json:"evidence,omitempty"`
	Remediation string                `json:"remediation,omitempty"`
}

type productionCheckSummary struct {
	Pass    int `json:"pass"`
	Warn    int `json:"warn"`
	Fail    int `json:"fail"`
	Unknown int `json:"unknown"`
}

type productionCheckReport struct {
	SchemaVersion int                      `json:"schemaVersion"`
	Ready         bool                     `json:"ready"`
	ExitCode      int                      `json:"exitCode"`
	Strict        bool                     `json:"strict"`
	Summary       productionCheckSummary   `json:"summary"`
	Checks        []productionCheckFinding `json:"checks"`
}

type productionCheckOptions struct {
	databasePath string
	format       string
	strict       bool

	tlsCertificate  string
	tlsPrivateKey   string
	ldaps           bool
	ldapsListen     string
	tlcpSignCert    string
	tlcpSignKey     string
	tlcpEncryptCert string
	tlcpEncryptKey  string
	implicitTLCP    bool
	tlcpListen      string
	tlsTerminated   bool
	requireStartTLS bool

	onlineBackupDirectory string
	externalBackup        bool
	auditLog              string
	auditKeyFile          string
	auditKeyEnvironment   bool

	maxMessageSize               int64
	searchLimit                  int
	transactionOperations        int
	transactionQueuedBytes       int64
	maxConnections               int
	maxOperations                int
	maxOperationsPerConnection   int
	maxPendingBytesPerConnection int64
	maxPendingOperationBytes     int64
	maxHandshakes                int
	maxSearchCandidates          int
	maxSearchCandidateBytes      int64
	maxSearchResponseBytes       int64
	maxSearchMemoryBytes         int64
	maxResponsePDUBytes          int64
	maxInFlightResponseBytes     int64
	handshakeTimeout             time.Duration
	shutdownTimeout              time.Duration
}

type productionConfigSnapshot struct {
	global                directory.Entry
	effectiveHashSchemes  []string
	passwordCryptFormat   string
	anonymousUpdates      bool
	anonymousWriteCount   int
	weakPasswords         int
	strongPasswords       int
	disabledPasswords     int
	unknownPasswords      int
	tlsConfigured         bool
	idleTimeout           time.Duration
	writeTimeout          time.Duration
	incomingAnonymous     uint64
	incomingAuthenticated uint64
}

// runProductionCheck validates persisted cn=config and the deployment options
// that live outside the database. It never opens the database for writing.
func runProductionCheck(args []string, stdout, stderr io.Writer) (runErr error) {
	options, err := parseProductionCheckOptions(args, stderr)
	if err != nil {
		return err
	}
	store, err := storage.OpenBoltReadOnly(options.databasePath)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, store.Close()) }()

	configuration, validationErr := server.ValidateConfiguration(
		context.Background(),
		server.Config{Store: store},
	)
	if validationErr != nil {
		report := productionCheckReport{
			SchemaVersion: 1,
			ExitCode:      productionCheckExitNotReady,
			Strict:        options.strict,
			Summary:       productionCheckSummary{Fail: 1},
			Checks: []productionCheckFinding{{
				ID: "configuration.valid", Category: "configuration",
				Status:      productionCheckFail,
				Summary:     "cn=config failed runtime validation",
				Evidence:    []string{redactProductionDiagnostic(validationErr.Error())},
				Remediation: "repair cn=config before starting the service",
			}},
		}
		if err := writeProductionCheckReport(stdout, report, options.format); err != nil {
			return err
		}
		return &ldapClientExitError{code: report.ExitCode}
	}
	snapshot, err := inspectProductionConfiguration(context.Background(), store)
	if err != nil {
		return err
	}

	report, err := buildProductionCheckReport(options, configuration, snapshot)
	if err != nil {
		return err
	}
	if err := writeProductionCheckReport(stdout, report, options.format); err != nil {
		return err
	}
	if report.ExitCode != 0 {
		return &ldapClientExitError{code: report.ExitCode}
	}
	return nil
}

func parseProductionCheckOptions(
	args []string,
	stderr io.Writer,
) (productionCheckOptions, error) {
	options := productionCheckOptions{}
	flags := flag.NewFlagSet("production-check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.databasePath, "db", "data/ldap-go.db", "database path")
	flags.StringVar(&options.format, "format", "json", "report format: json or text")
	flags.BoolVar(&options.strict, "strict", false, "return exit 4 when warnings are present")

	flags.StringVar(&options.tlsCertificate, "tls-cert", "", "PEM server certificate used by serve")
	flags.StringVar(&options.tlsPrivateKey, "tls-key", "", "PEM server private key used by serve")
	flags.BoolVar(&options.ldaps, "ldaps", false, "serve uses implicit TLS")
	flags.StringVar(&options.ldapsListen, "ldaps-listen", "", "additional implicit TLS listener used by serve")
	flags.StringVar(&options.tlcpSignCert, "tlcp-sign-cert", "", "PEM TLCP signing certificate used by serve")
	flags.StringVar(&options.tlcpSignKey, "tlcp-sign-key", "", "PEM TLCP signing key used by serve")
	flags.StringVar(&options.tlcpEncryptCert, "tlcp-enc-cert", "", "PEM TLCP encryption certificate used by serve")
	flags.StringVar(&options.tlcpEncryptKey, "tlcp-enc-key", "", "PEM TLCP encryption key used by serve")
	flags.BoolVar(&options.implicitTLCP, "tlcp-implicit", false, "serve uses implicit TLCP")
	flags.StringVar(&options.tlcpListen, "tlcp-listen", "", "additional implicit TLCP listener used by serve")
	flags.BoolVar(&options.tlsTerminated, "tls-terminated-upstream", false, "attest that a trusted upstream enforces TLS")
	flags.BoolVar(&options.requireStartTLS, "require-starttls", false, "attest that cleartext LDAP operations are rejected")

	flags.StringVar(&options.onlineBackupDirectory, "online-backup-dir", "", "online backup directory used by serve")
	flags.BoolVar(&options.externalBackup, "external-backup", false, "attest that tested external backups protect the database")
	flags.StringVar(&options.auditLog, "audit-log", "", "append-only audit log path used by serve")
	flags.StringVar(&options.auditKeyFile, "audit-key-file", "", "audit HMAC key file used by serve")
	flags.BoolVar(&options.auditKeyEnvironment, "audit-key-env", false, "attest that LDAP_GO_AUDIT_KEY is injected securely")

	flags.Int64Var(&options.maxMessageSize, "max-message-size", 0, "serve maximum BER frame size")
	flags.IntVar(&options.searchLimit, "search-limit", 1000, "serve search result limit")
	flags.IntVar(&options.transactionOperations, "transaction-max-operations", 1000, "serve transaction operation limit")
	flags.Int64Var(&options.transactionQueuedBytes, "transaction-max-queued-bytes", 16<<20, "serve transaction byte limit")
	flags.IntVar(&options.maxConnections, "max-connections", 4096, "serve connection limit")
	flags.IntVar(&options.maxOperations, "max-concurrent-operations", 256, "serve concurrent operation limit")
	flags.IntVar(&options.maxOperationsPerConnection, "max-operations-per-connection", 8, "serve per-connection operation limit")
	flags.Int64Var(&options.maxPendingBytesPerConnection, "max-pending-bytes-per-connection", 64<<20, "serve per-connection decoded operation byte limit")
	flags.Int64Var(&options.maxPendingOperationBytes, "max-pending-operation-bytes", 256<<20, "serve process decoded operation byte limit")
	flags.IntVar(&options.maxHandshakes, "max-concurrent-handshakes", 64, "serve concurrent handshake limit")
	flags.IntVar(&options.maxSearchCandidates, "search-candidate-limit", 100000, "serve sorted-search candidate limit")
	flags.Int64Var(&options.maxSearchCandidateBytes, "search-candidate-bytes", 64<<20, "serve sorted-search retained byte limit")
	flags.Int64Var(&options.maxSearchResponseBytes, "search-response-bytes", 128<<20, "serve finite-search encoded response limit")
	flags.Int64Var(&options.maxSearchMemoryBytes, "search-memory-bytes", 512<<20, "serve process retained search memory limit")
	flags.Int64Var(&options.maxResponsePDUBytes, "response-pdu-bytes", 16<<20, "serve maximum encoded Search response PDU")
	flags.Int64Var(&options.maxInFlightResponseBytes, "in-flight-response-bytes", 256<<20, "serve process in-flight Search response limit")
	flags.DurationVar(&options.handshakeTimeout, "secure-handshake-timeout", 10*time.Second, "serve secure handshake timeout")
	flags.DurationVar(&options.shutdownTimeout, "shutdown-timeout", 30*time.Second, "serve graceful shutdown timeout")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return productionCheckOptions{}, &ldapClientExitError{code: 0}
		}
		return productionCheckOptions{}, &ldapClientExitError{code: 2, cause: err}
	}
	if flags.NArg() != 0 {
		return productionCheckOptions{}, &ldapClientExitError{
			code:  2,
			cause: fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " ")),
		}
	}
	options.format = strings.ToLower(strings.TrimSpace(options.format))
	if options.format != "json" && options.format != "text" {
		return productionCheckOptions{}, &ldapClientExitError{
			code:  2,
			cause: errors.New("-format must be json or text"),
		}
	}
	if options.auditKeyFile != "" && options.auditKeyEnvironment {
		return productionCheckOptions{}, &ldapClientExitError{
			code:  2,
			cause: errors.New("-audit-key-file and -audit-key-env are mutually exclusive"),
		}
	}
	return options, nil
}

func inspectProductionConfiguration(
	ctx context.Context,
	store storage.Store,
) (productionConfigSnapshot, error) {
	snapshot := productionConfigSnapshot{
		incomingAnonymous:     (1 << 18) - 1,
		incomingAuthenticated: (1 << 24) - 1,
	}
	err := store.View(ctx, func(reader storage.Reader) error {
		configReader := storage.ReaderInPartition(reader, storage.OpenLDAPConfigPartition)
		globalDN, err := directory.ParseDN("cn=config")
		if err != nil {
			return err
		}
		global, err := configReader.Get(globalDN)
		if err != nil && !errors.Is(err, storage.ErrEntryNotFound) {
			return fmt.Errorf("read cn=config: %w", err)
		}
		if err == nil {
			snapshot.global = global
		}

		var frontendHashSchemes []string
		if err := configReader.ForEach(func(entry directory.Entry) error {
			if productionEntryIsFrontend(entry) {
				frontendHashSchemes = productionStringValues(entry.Values("olcPasswordHash"))
			}
			return nil
		}); err != nil {
			return fmt.Errorf("read cn=config entries: %w", err)
		}

		snapshot.effectiveHashSchemes = productionPasswordHashSchemes(
			productionStringValues(global.Values("olcPasswordHash")),
			frontendHashSchemes,
		)
		cryptFormats := productionStringValues(global.Values("olcPasswordCryptSaltFormat"))
		if len(cryptFormats) != 0 {
			snapshot.passwordCryptFormat = cryptFormats[0]
		} else {
			snapshot.passwordCryptFormat = auth.DefaultOpenLDAPCryptSaltFormat
		}
		snapshot.anonymousUpdates = productionFeatureEnabled(global.Values("olcAllows"), "update_anon")
		snapshot.tlsConfigured = productionGlobalTLSConfigured(global)
		snapshot.idleTimeout, err = productionDurationSeconds(global.Values("olcIdleTimeout"))
		if err != nil {
			return fmt.Errorf("olcIdleTimeout: %w", err)
		}
		snapshot.writeTimeout, err = productionDurationSeconds(global.Values("olcWriteTimeout"))
		if err != nil {
			return fmt.Errorf("olcWriteTimeout: %w", err)
		}
		if snapshot.incomingAnonymous, err = productionUnsignedValue(
			global.Values("olcSockbufMaxIncoming"), snapshot.incomingAnonymous,
		); err != nil {
			return fmt.Errorf("olcSockbufMaxIncoming: %w", err)
		}
		if snapshot.incomingAuthenticated, err = productionUnsignedValue(
			global.Values("olcSockbufMaxIncomingAuth"), snapshot.incomingAuthenticated,
		); err != nil {
			return fmt.Errorf("olcSockbufMaxIncomingAuth: %w", err)
		}

		policy, _, err := acl.LoadOpenLDAPConfigReader(reader)
		if err != nil {
			return err
		}
		if err := reader.ForEachPartition(func(_ string, entry directory.Entry) error {
			for _, description := range []string{"userPassword", "olcRootPW"} {
				for _, value := range entry.Values(description) {
					switch productionStoredPasswordStrength(value) {
					case productionPasswordStrong:
						snapshot.strongPasswords++
					case productionPasswordWeak:
						snapshot.weakPasswords++
					case productionPasswordDisabled:
						snapshot.disabledPasswords++
					case productionPasswordUnknown:
						snapshot.unknownPasswords++
					}
				}
			}
			if snapshot.anonymousUpdates && productionAnonymousCanWrite(policy, reader, entry) {
				snapshot.anonymousWriteCount++
			}
			return nil
		}); err != nil {
			return fmt.Errorf("inspect directory entries: %w", err)
		}
		return nil
	})
	return snapshot, err
}

func buildProductionCheckReport(
	options productionCheckOptions,
	configuration server.ConfigurationSummary,
	snapshot productionConfigSnapshot,
) (productionCheckReport, error) {
	report := productionCheckReport{SchemaVersion: 1, Strict: options.strict}
	add := func(finding productionCheckFinding) {
		report.Checks = append(report.Checks, finding)
		switch finding.Status {
		case productionCheckPass:
			report.Summary.Pass++
		case productionCheckWarn:
			report.Summary.Warn++
		case productionCheckFail:
			report.Summary.Fail++
		case productionCheckUnknown:
			report.Summary.Unknown++
		}
	}

	add(productionCheckFinding{
		ID: "configuration.valid", Category: "configuration", Status: productionCheckPass,
		Summary: "cn=config parsed and cross-validated successfully",
		Evidence: []string{fmt.Sprintf(
			"databases=%d overlays=%d syncreplConsumers=%d aclRules=%d",
			configuration.Databases, configuration.Overlays,
			configuration.SyncreplConsumers, configuration.ACLRules,
		)},
	})

	transportFindings := productionTransportFindings(options, snapshot)
	for _, finding := range transportFindings {
		add(finding)
	}

	if snapshot.anonymousUpdates {
		evidence := []string{"cn=config enables olcAllows=update_anon"}
		if snapshot.anonymousWriteCount != 0 {
			evidence = append(evidence, fmt.Sprintf(
				"anonymous ACL write access matched %d stored entries",
				snapshot.anonymousWriteCount,
			))
		}
		add(productionCheckFinding{
			ID: "access.anonymous_updates", Category: "access", Status: productionCheckFail,
			Summary: "anonymous update processing is enabled", Evidence: evidence,
			Remediation: "remove update_anon from olcAllows and require authenticated writers",
		})
	} else {
		add(productionCheckFinding{
			ID: "access.anonymous_updates", Category: "access", Status: productionCheckPass,
			Summary: "anonymous update processing is disabled",
		})
	}

	weakSchemes, uncertainSchemes := productionClassifyConfiguredSchemes(
		snapshot.effectiveHashSchemes,
		snapshot.passwordCryptFormat,
	)
	switch {
	case len(weakSchemes) != 0:
		add(productionCheckFinding{
			ID: "password.default_hash", Category: "password", Status: productionCheckFail,
			Summary:     "new passwords may use weak or fast password hashing",
			Evidence:    []string{"effective schemes: " + strings.Join(weakSchemes, ", ")},
			Remediation: "configure {ARGON2} or {PBKDF2-SM3}; imported PBKDF2-SHA2 values need at least 100000 rounds",
		})
	case len(uncertainSchemes) != 0:
		add(productionCheckFinding{
			ID: "password.default_hash", Category: "password", Status: productionCheckWarn,
			Summary:     "password hash strength depends on an external or variable-cost scheme",
			Evidence:    []string{"effective schemes: " + strings.Join(uncertainSchemes, ", ")},
			Remediation: "verify the external verifier and cost parameters operationally",
		})
	default:
		add(productionCheckFinding{
			ID: "password.default_hash", Category: "password", Status: productionCheckPass,
			Summary:  "new passwords use adaptive password hashing",
			Evidence: []string{"effective schemes: " + strings.Join(snapshot.effectiveHashSchemes, ", ")},
		})
	}

	switch {
	case snapshot.weakPasswords != 0:
		add(productionCheckFinding{
			ID: "password.stored_values", Category: "password", Status: productionCheckFail,
			Summary: "stored password values include weak, fast, or cleartext forms",
			Evidence: []string{fmt.Sprintf(
				"weak=%d strong=%d disabled=%d unclassified=%d",
				snapshot.weakPasswords, snapshot.strongPasswords,
				snapshot.disabledPasswords, snapshot.unknownPasswords,
			)},
			Remediation: "rehash credentials on successful bind or force a password reset",
		})
	case snapshot.unknownPasswords != 0:
		add(productionCheckFinding{
			ID: "password.stored_values", Category: "password", Status: productionCheckUnknown,
			Summary: "some stored password values have externally defined or unclassified strength",
			Evidence: []string{fmt.Sprintf(
				"strong=%d disabled=%d unclassified=%d",
				snapshot.strongPasswords, snapshot.disabledPasswords, snapshot.unknownPasswords,
			)},
			Remediation: "verify external password providers and variable-cost hash parameters",
		})
	default:
		add(productionCheckFinding{
			ID: "password.stored_values", Category: "password", Status: productionCheckPass,
			Summary: "stored password values contain no recognized weak hashes",
			Evidence: []string{fmt.Sprintf(
				"adaptive hashes=%d disabled credentials=%d",
				snapshot.strongPasswords, snapshot.disabledPasswords,
			)},
		})
	}

	add(productionTimeoutFinding(snapshot))
	add(productionLifecycleTimeoutFinding(options))
	add(productionResourceFinding(options, snapshot))
	add(productionBackupFinding(options))
	add(productionAuditFinding(options))
	add(productionDatabasePermissionFinding(options.databasePath))

	sort.SliceStable(report.Checks, func(i, j int) bool {
		return report.Checks[i].ID < report.Checks[j].ID
	})
	report.ExitCode = productionCheckReportExitCode(report)
	report.Ready = report.ExitCode == 0
	return report, nil
}

func productionTransportFindings(
	options productionCheckOptions,
	snapshot productionConfigSnapshot,
) []productionCheckFinding {
	standardTLS, err := loadServerTLSConfig(options.tlsCertificate, options.tlsPrivateKey)
	if err != nil {
		return []productionCheckFinding{{
			ID: "transport.encryption", Category: "transport", Status: productionCheckFail,
			Summary: "serve TLS options are invalid", Evidence: []string{err.Error()},
			Remediation: "provide a readable, matching TLS certificate and private key",
		}}
	}
	if standardTLS != nil {
		if issue := productionTLSCertificateIssue(standardTLS.Certificates[0].Certificate); issue != "" {
			return []productionCheckFinding{{
				ID: "transport.encryption", Category: "transport", Status: productionCheckFail,
				Summary:     "serve TLS certificate is not currently usable for a server",
				Evidence:    []string{issue},
				Remediation: "install a currently valid certificate permitting TLS server authentication",
			}}
		}
	}
	tlcp, err := loadServerTLCP(
		options.tlcpSignCert, options.tlcpSignKey,
		options.tlcpEncryptCert, options.tlcpEncryptKey,
	)
	if err != nil {
		return []productionCheckFinding{{
			ID: "transport.encryption", Category: "transport", Status: productionCheckFail,
			Summary: "serve TLCP options are invalid", Evidence: []string{err.Error()},
			Remediation: "provide valid TLCP signing and encryption certificate/key pairs",
		}}
	}
	if tlcp != nil {
		for _, certificate := range []struct {
			path    string
			signing bool
			name    string
		}{
			{path: options.tlcpSignCert, signing: true, name: "signing"},
			{path: options.tlcpEncryptCert, name: "encryption"},
		} {
			if issue := productionTLCPCertificateIssue(certificate.path, certificate.signing); issue != "" {
				return []productionCheckFinding{{
					ID: "transport.encryption", Category: "transport", Status: productionCheckFail,
					Summary:     "serve TLCP " + certificate.name + " certificate is not currently usable",
					Evidence:    []string{issue},
					Remediation: "install currently valid TLCP certificates with appropriate key and server usages",
				}}
			}
		}
	}
	if standardTLS != nil && tlcp != nil {
		return []productionCheckFinding{{
			ID: "transport.encryption", Category: "transport", Status: productionCheckFail,
			Summary:     "standard TLS and TLCP material are configured together",
			Remediation: "run separate processes when both TLS families are required",
		}}
	}
	if (options.ldaps || options.ldapsListen != "") &&
		(options.implicitTLCP || options.tlcpListen != "") {
		return []productionCheckFinding{{
			ID: "transport.encryption", Category: "transport", Status: productionCheckFail,
			Summary:     "standard TLS and TLCP listeners share one server process",
			Remediation: "run separate processes when both TLS families are required",
		}}
	}
	if (options.ldaps || options.ldapsListen != "") && standardTLS == nil {
		return []productionCheckFinding{{
			ID: "transport.encryption", Category: "transport", Status: productionCheckFail,
			Summary:     "implicit TLS lacks a certificate and private key",
			Remediation: "provide -tls-cert and -tls-key with -ldaps",
		}}
	}
	if (options.implicitTLCP || options.tlcpListen != "") && tlcp == nil {
		return []productionCheckFinding{{
			ID: "transport.encryption", Category: "transport", Status: productionCheckFail,
			Summary:     "implicit TLCP lacks signing or encryption material",
			Remediation: "provide all four TLCP certificate/key options",
		}}
	}
	configured := snapshot.tlsConfigured || standardTLS != nil || tlcp != nil || options.tlsTerminated
	if !configured {
		return []productionCheckFinding{{
			ID: "transport.encryption", Category: "transport", Status: productionCheckFail,
			Summary:     "no TLS or TLCP server transport is configured",
			Remediation: "configure TLS/TLCP material or attest trusted upstream TLS termination",
		}}
	}

	evidence := make([]string, 0, 3)
	if snapshot.tlsConfigured {
		evidence = append(evidence, "cn=config TLS certificate and key")
	}
	if standardTLS != nil {
		evidence = append(evidence, "serve TLS certificate and key")
	}
	if tlcp != nil {
		evidence = append(evidence, "serve TLCP signing and encryption material")
	}
	if options.tlsTerminated {
		evidence = append(evidence, "operator-attested trusted upstream TLS termination")
	}
	findings := []productionCheckFinding{{
		ID: "transport.encryption", Category: "transport", Status: productionCheckPass,
		Summary: "encrypted LDAP transport is available", Evidence: evidence,
	}}
	if options.ldaps || options.ldapsListen != "" || options.implicitTLCP ||
		options.tlcpListen != "" || options.requireStartTLS || options.tlsTerminated {
		findings = append(findings, productionCheckFinding{
			ID: "transport.enforcement", Category: "transport", Status: productionCheckPass,
			Summary: "deployment declares encryption enforcement",
		})
	} else {
		findings = append(findings, productionCheckFinding{
			ID: "transport.enforcement", Category: "transport", Status: productionCheckWarn,
			Summary:     "StartTLS is available but encryption enforcement was not established",
			Remediation: "use implicit TLS/TLCP or pass -require-starttls after enforcing it in access policy",
		})
	}
	return findings
}

func productionTimeoutFinding(snapshot productionConfigSnapshot) productionCheckFinding {
	if snapshot.idleTimeout <= 0 || snapshot.writeTimeout <= 0 {
		missing := make([]string, 0, 2)
		if snapshot.idleTimeout <= 0 {
			missing = append(missing, "olcIdleTimeout")
		}
		if snapshot.writeTimeout <= 0 {
			missing = append(missing, "olcWriteTimeout")
		}
		return productionCheckFinding{
			ID: "timeout.connections", Category: "timeout", Status: productionCheckFail,
			Summary:     "one or more connection timeouts are unlimited",
			Evidence:    []string{"disabled: " + strings.Join(missing, ", ")},
			Remediation: "set positive olcIdleTimeout and olcWriteTimeout values on cn=config",
		}
	}
	return productionCheckFinding{
		ID: "timeout.connections", Category: "timeout", Status: productionCheckPass,
		Summary: "idle and blocked-write connections are bounded",
		Evidence: []string{fmt.Sprintf(
			"idle=%s write=%s", snapshot.idleTimeout, snapshot.writeTimeout,
		)},
	}
}

func productionLifecycleTimeoutFinding(options productionCheckOptions) productionCheckFinding {
	if options.handshakeTimeout <= 0 || options.shutdownTimeout <= 0 {
		return productionCheckFinding{
			ID: "timeout.lifecycle", Category: "timeout", Status: productionCheckFail,
			Summary:     "secure handshake or graceful shutdown timeout is not positive",
			Remediation: "configure positive secure-handshake-timeout and shutdown-timeout values",
		}
	}
	return productionCheckFinding{
		ID: "timeout.lifecycle", Category: "timeout", Status: productionCheckPass,
		Summary: "secure handshakes and graceful shutdown are bounded",
		Evidence: []string{fmt.Sprintf(
			"handshake=%s shutdown=%s", options.handshakeTimeout, options.shutdownTimeout,
		)},
	}
}

func productionResourceFinding(
	options productionCheckOptions,
	snapshot productionConfigSnapshot,
) productionCheckFinding {
	bounded := options.maxMessageSize >= 0 && options.searchLimit > 0 &&
		options.transactionOperations > 0 && options.transactionQueuedBytes > 0 &&
		options.maxConnections > 0 && options.maxOperations > 0 &&
		options.maxOperationsPerConnection > 0 &&
		options.maxPendingBytesPerConnection > 0 && options.maxPendingOperationBytes > 0 &&
		options.maxHandshakes > 0 && snapshot.incomingAnonymous > 0 &&
		snapshot.incomingAuthenticated > 0 && options.maxSearchCandidates > 0 &&
		options.maxSearchCandidateBytes > 0 && options.maxSearchResponseBytes > 0 &&
		options.maxSearchMemoryBytes > 0
	bounded = bounded && options.maxResponsePDUBytes > 0
	bounded = bounded && options.maxInFlightResponseBytes > 0
	if !bounded {
		return productionCheckFinding{
			ID: "resource.global_limits", Category: "resource", Status: productionCheckFail,
			Summary:     "one or more global resource limits are disabled or invalid",
			Remediation: "set positive connection, operation, handshake, search, transaction, and incoming PDU limits",
		}
	}
	return productionCheckFinding{
		ID: "resource.global_limits", Category: "resource", Status: productionCheckPass,
		Summary: "global connection, operation, transaction, search, and PDU resources are bounded",
		Evidence: []string{fmt.Sprintf(
			"connections=%d operations=%d perConnection=%d pendingPerConnectionBytes=%d pendingProcessBytes=%d handshakes=%d search=%d candidates=%d candidateBytes=%d responseBytes=%d processSearchMemoryBytes=%d responsePDUBytes=%d inFlightResponseBytes=%d transactionOps=%d transactionBytes=%d incomingAnon=%d incomingAuth=%d",
			options.maxConnections, options.maxOperations, options.maxOperationsPerConnection,
			options.maxPendingBytesPerConnection, options.maxPendingOperationBytes,
			options.maxHandshakes, options.searchLimit, options.maxSearchCandidates,
			options.maxSearchCandidateBytes, options.maxSearchResponseBytes,
			options.maxSearchMemoryBytes,
			options.maxResponsePDUBytes,
			options.maxInFlightResponseBytes,
			options.transactionOperations,
			options.transactionQueuedBytes, snapshot.incomingAnonymous,
			snapshot.incomingAuthenticated,
		)},
	}
}

func productionBackupFinding(options productionCheckOptions) productionCheckFinding {
	if options.externalBackup {
		return productionCheckFinding{
			ID: "backup.recovery", Category: "backup", Status: productionCheckPass,
			Summary: "tested external backup coverage was operator-attested",
		}
	}
	if options.onlineBackupDirectory == "" {
		return productionCheckFinding{
			ID: "backup.recovery", Category: "backup", Status: productionCheckFail,
			Summary:     "no online or external backup coverage was declared",
			Remediation: "configure -online-backup-dir or attest tested external backups",
		}
	}
	return productionBackupDirectoryPermissionFinding(options.onlineBackupDirectory)
}

func productionAuditFinding(options productionCheckOptions) productionCheckFinding {
	if options.auditLog == "" {
		return productionCheckFinding{
			ID: "audit.integrity", Category: "audit", Status: productionCheckFail,
			Summary:     "the append-only HMAC-chained audit log is disabled",
			Remediation: "configure -audit-log and a private audit HMAC key source",
		}
	}
	if samePath(options.auditLog, options.databasePath) ||
		(options.auditKeyFile != "" && samePath(options.auditLog, options.auditKeyFile)) {
		return productionCheckFinding{
			ID: "audit.integrity", Category: "audit", Status: productionCheckFail,
			Summary:     "audit log path conflicts with the database or audit key path",
			Remediation: "use separate files for directory data, audit records, and the audit key",
		}
	}
	if options.auditKeyFile == "" && !options.auditKeyEnvironment {
		return productionCheckFinding{
			ID: "audit.integrity", Category: "audit", Status: productionCheckFail,
			Summary:     "audit logging has no declared HMAC key source",
			Remediation: "configure -audit-key-file or attest secure LDAP_GO_AUDIT_KEY injection",
		}
	}
	if options.auditKeyFile != "" {
		key, err := loadAuditKey(options.auditKeyFile, func(string) string { return "" })
		if err != nil {
			return productionCheckFinding{
				ID: "audit.integrity", Category: "audit", Status: productionCheckFail,
				Summary:     "audit HMAC key file is not production-safe",
				Evidence:    []string{err.Error()},
				Remediation: "provide a non-empty regular key file with owner-only permissions",
			}
		}
		if len(key) < 32 {
			clear(key)
			return productionCheckFinding{
				ID: "audit.integrity", Category: "audit", Status: productionCheckFail,
				Summary:     "audit HMAC key is shorter than 32 bytes",
				Remediation: "provide at least 32 random bytes in the private audit key file",
			}
		}
		clear(key)
	}
	return productionCheckFinding{
		ID: "audit.integrity", Category: "audit", Status: productionCheckPass,
		Summary: "append-only HMAC-chained audit logging is configured",
	}
}

func productionTLSCertificateIssue(chain [][]byte) string {
	if len(chain) == 0 {
		return "certificate chain is empty"
	}
	certificate, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return "leaf certificate cannot be parsed"
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) {
		return "leaf certificate is not valid yet"
	}
	if now.After(certificate.NotAfter) {
		return "leaf certificate is expired"
	}
	if len(certificate.ExtKeyUsage) == 0 {
		return ""
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageServerAuth {
			return ""
		}
	}
	return "leaf certificate does not permit TLS server authentication"
}

func productionTLCPCertificateIssue(path string, signing bool) string {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return "certificate file cannot be read"
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" {
		return "certificate file contains no PEM certificate"
	}
	certificate, err := smx509.ParseCertificate(block.Bytes)
	if err != nil {
		return "certificate cannot be parsed"
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) {
		return "certificate is not valid yet"
	}
	if now.After(certificate.NotAfter) {
		return "certificate is expired"
	}
	if len(certificate.ExtKeyUsage) != 0 {
		serverUsage := false
		for _, usage := range certificate.ExtKeyUsage {
			if usage == smx509.ExtKeyUsageAny || usage == smx509.ExtKeyUsageServerAuth {
				serverUsage = true
				break
			}
		}
		if !serverUsage {
			return "certificate does not permit server authentication"
		}
	}
	if certificate.KeyUsage != 0 {
		if signing && certificate.KeyUsage&smx509.KeyUsageDigitalSignature == 0 {
			return "signing certificate does not permit digital signatures"
		}
		encryptionUsage := smx509.KeyUsageKeyEncipherment |
			smx509.KeyUsageDataEncipherment |
			smx509.KeyUsageKeyAgreement
		if !signing && certificate.KeyUsage&encryptionUsage == 0 {
			return "encryption certificate does not permit encryption or key agreement"
		}
	}
	return ""
}

func redactProductionDiagnostic(value string) string {
	value = productionURLUserInfoPattern.ReplaceAllString(value, "://<redacted>@")
	value = productionPasswordValuePattern.ReplaceAllString(value, "<password-value-redacted>")
	return productionSecretAssignmentPattern.ReplaceAllStringFunc(
		value,
		func(match string) string {
			separator := strings.IndexAny(match, "=:")
			if separator < 0 {
				return "<redacted>"
			}
			return strings.TrimSpace(match[:separator]) + "=<redacted>"
		},
	)
}

func productionCheckReportExitCode(report productionCheckReport) int {
	if report.Summary.Fail != 0 {
		return productionCheckExitNotReady
	}
	if report.Summary.Unknown != 0 || (report.Strict && report.Summary.Warn != 0) {
		return productionCheckExitInconclusive
	}
	return 0
}

func writeProductionCheckReport(
	writer io.Writer,
	report productionCheckReport,
	format string,
) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	for _, finding := range report.Checks {
		if _, err := fmt.Fprintf(
			writer, "%-7s %-28s %s\n",
			strings.ToUpper(string(finding.Status)), finding.ID, finding.Summary,
		); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(
		writer,
		"ready=%t exit=%d pass=%d warn=%d fail=%d unknown=%d\n",
		report.Ready, report.ExitCode, report.Summary.Pass, report.Summary.Warn,
		report.Summary.Fail, report.Summary.Unknown,
	)
	return err
}

func productionEntryIsFrontend(entry directory.Entry) bool {
	values := entry.Values("olcDatabase")
	if len(values) != 1 {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(string(values[0])))
	if close := strings.IndexByte(value, '}'); strings.HasPrefix(value, "{") && close >= 0 {
		value = value[close+1:]
	}
	return value == "frontend"
}

func productionPasswordHashSchemes(global, frontend []string) []string {
	values := global
	if len(frontend) != 0 {
		values = frontend
	}
	if len(values) == 0 {
		return []string{auth.OpenLDAPDefaultHashScheme}
	}
	var schemes []string
	for _, value := range values {
		for _, field := range strings.Fields(value) {
			normalized, err := auth.NormalizePasswordHashScheme(field)
			if err == nil {
				schemes = append(schemes, normalized)
			}
		}
	}
	return schemes
}

func productionClassifyConfiguredSchemes(
	schemes []string,
	cryptFormat string,
) (weak, uncertain []string) {
	for _, scheme := range schemes {
		payload := []byte(nil)
		if strings.EqualFold(scheme, auth.OpenLDAPCryptHashScheme) {
			payload = []byte(cryptFormat)
		}
		switch productionPasswordSchemeStrength(scheme, payload) {
		case productionPasswordWeak:
			weak = append(weak, scheme)
		case productionPasswordUnknown:
			uncertain = append(uncertain, scheme)
		}
	}
	sort.Strings(weak)
	sort.Strings(uncertain)
	return weak, uncertain
}

type productionPasswordStrength uint8

const (
	productionPasswordUnknown productionPasswordStrength = iota
	productionPasswordWeak
	productionPasswordStrong
	productionPasswordDisabled
)

func productionStoredPasswordStrength(value []byte) productionPasswordStrength {
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" || strings.HasPrefix(trimmed, "!") || trimmed == "*" {
		return productionPasswordDisabled
	}
	if !strings.HasPrefix(trimmed, "{") {
		return productionPasswordWeak
	}
	close := strings.IndexByte(trimmed, '}')
	if close <= 1 {
		return productionPasswordWeak
	}
	return productionPasswordSchemeStrength(strings.ToUpper(trimmed[:close+1]), []byte(trimmed[close+1:]))
}

func productionPasswordSchemeStrength(
	scheme string,
	payload []byte,
) productionPasswordStrength {
	switch strings.ToUpper(strings.TrimSpace(scheme)) {
	case auth.SMPBKDF2HashScheme:
		return productionPBKDF2Strength(payload, 32, true, productionMinimumPBKDF2Rounds)
	case auth.OpenLDAPPBKDF2SHA256HashScheme:
		return productionPBKDF2Strength(payload, 32, false, productionMinimumPBKDF2Rounds)
	case auth.OpenLDAPPBKDF2SHA512HashScheme:
		return productionPBKDF2Strength(payload, 64, false, productionMinimumPBKDF2Rounds)
	case auth.OpenLDAPArgon2HashScheme:
		return productionArgon2Strength(payload)
	case "{CLEARTEXT}", "{SHA}", "{SSHA}", "{SHA256}", "{SSHA256}",
		"{SHA384}", "{SSHA384}", "{SHA512}", "{SSHA512}", "{MD5}",
		"{SMD5}", "{SM3}", "{SSM3}", auth.OpenLDAPPBKDF2HashScheme,
		auth.OpenLDAPPBKDF2SHA1HashScheme, auth.OpenLDAPAPR1HashScheme,
		auth.OpenLDAPBSDMD5HashScheme, auth.OpenLDAPNetscapeMTAHashScheme:
		return productionPasswordWeak
	case auth.OpenLDAPCryptHashScheme:
		return productionCryptPasswordStrength(string(payload))
	default:
		return productionPasswordUnknown
	}
}

func productionPBKDF2Strength(
	payload []byte,
	derivedLength int,
	adapted bool,
	minimumRounds int,
) productionPasswordStrength {
	if payload == nil {
		if adapted {
			return productionPasswordStrong
		}
		return productionPasswordWeak
	}
	fields := strings.Split(string(payload), "$")
	if len(fields) != 3 {
		return productionPasswordUnknown
	}
	rounds, err := strconv.Atoi(fields[0])
	if err != nil || rounds < 1 {
		return productionPasswordUnknown
	}
	maximumRounds := auth.MaxOpenLDAPPBKDF2Iterations
	if adapted {
		maximumRounds = auth.MaxSMPBKDF2Iterations
	}
	if rounds > maximumRounds {
		return productionPasswordUnknown
	}
	salt, err := decodeProductionPasswordBase64(fields[1], adapted)
	if err != nil || len(salt) != 16 {
		return productionPasswordUnknown
	}
	derived, err := decodeProductionPasswordBase64(fields[2], adapted)
	if err != nil || len(derived) != derivedLength {
		return productionPasswordUnknown
	}
	if rounds < minimumRounds {
		return productionPasswordWeak
	}
	return productionPasswordStrong
}

func decodeProductionPasswordBase64(value string, adapted bool) ([]byte, error) {
	if adapted {
		value = strings.ReplaceAll(value, ".", "+")
	}
	switch len(value) % 4 {
	case 0:
	case 2:
		value += "=="
	case 3:
		value += "="
	default:
		return nil, errors.New("invalid base64 length")
	}
	return base64.StdEncoding.DecodeString(value)
}

func productionArgon2Strength(payload []byte) productionPasswordStrength {
	if payload == nil {
		return productionPasswordStrong
	}
	matches := productionArgon2Pattern.FindStringSubmatch(string(payload))
	if len(matches) != 6 {
		return productionPasswordUnknown
	}
	memory, memoryErr := strconv.ParseUint(matches[1], 10, 32)
	timeCost, timeErr := strconv.ParseUint(matches[2], 10, 32)
	threads, threadsErr := strconv.ParseUint(matches[3], 10, 8)
	salt, saltErr := base64.RawStdEncoding.DecodeString(matches[4])
	hash, hashErr := base64.RawStdEncoding.DecodeString(matches[5])
	if memoryErr != nil || timeErr != nil || threadsErr != nil ||
		saltErr != nil || hashErr != nil || len(salt) < 8 || len(salt) > 64 ||
		len(hash) < 16 || threads == 0 || memory > uint64(auth.OpenLDAPArgon2MaxMemory) ||
		timeCost > uint64(auth.OpenLDAPArgon2MaxTime) ||
		threads > uint64(auth.OpenLDAPArgon2MaxThreads) {
		return productionPasswordUnknown
	}
	if memory < uint64(auth.OpenLDAPArgon2DefaultMemory) || timeCost < 3 {
		return productionPasswordWeak
	}
	return productionPasswordStrong
}

func productionCryptPasswordStrength(payload string) productionPasswordStrength {
	switch {
	case strings.HasPrefix(payload, "$y$"):
		return productionPasswordUnknown
	case strings.HasPrefix(payload, "$2a$") || strings.HasPrefix(payload, "$2b$") ||
		strings.HasPrefix(payload, "$2y$"):
		parts := strings.Split(payload, "$")
		if len(parts) >= 3 {
			cost, err := strconv.Atoi(parts[2])
			if err == nil && cost >= 12 {
				return productionPasswordStrong
			}
		}
		return productionPasswordWeak
	case strings.HasPrefix(payload, "$6$rounds="):
		rest := strings.TrimPrefix(payload, "$6$rounds=")
		rawRounds, _, found := strings.Cut(rest, "$")
		if found {
			rounds, err := strconv.Atoi(rawRounds)
			if err == nil && rounds >= 100_000 {
				return productionPasswordStrong
			}
		}
		return productionPasswordWeak
	case strings.HasPrefix(payload, "$1$") || strings.HasPrefix(payload, "$5$") ||
		strings.HasPrefix(payload, "$6$") || !strings.HasPrefix(payload, "$"):
		return productionPasswordWeak
	default:
		return productionPasswordUnknown
	}
}

func productionAnonymousCanWrite(
	policy *acl.Policy,
	reader storage.Reader,
	entry directory.Entry,
) bool {
	if policy == nil {
		return false
	}
	target := acl.Target{Entry: entry}
	return policy.Allowed(acl.Subject{}, target, acl.WriteAdd, reader) ||
		policy.Allowed(acl.Subject{}, target, acl.WriteDelete, reader) ||
		policy.Allowed(acl.Subject{}, target, acl.Manage, reader)
}

func productionFeatureEnabled(values [][]byte, feature string) bool {
	for _, value := range values {
		for _, field := range strings.Fields(string(value)) {
			if strings.EqualFold(field, feature) {
				return true
			}
		}
	}
	return false
}

func productionGlobalTLSConfigured(entry directory.Entry) bool {
	certificate := entry.HasAttribute("olcTLSCertificate") || entry.HasAttribute("olcTLSCertificateFile")
	key := entry.HasAttribute("olcTLSCertificateKey") || entry.HasAttribute("olcTLSCertificateKeyFile")
	return certificate && key
}

func productionDurationSeconds(values [][]byte) (time.Duration, error) {
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, errors.New("must contain exactly one value")
	}
	raw := strings.TrimLeft(string(values[0]), " \t\n\v\f\r")
	seconds, err := strconv.ParseInt(raw, 0, 32)
	if err != nil {
		return 0, errors.New("must be a 32-bit integer")
	}
	return time.Duration(seconds) * time.Second, nil
}

func productionUnsignedValue(values [][]byte, fallback uint64) (uint64, error) {
	if len(values) == 0 {
		return fallback, nil
	}
	if len(values) != 1 {
		return 0, errors.New("must contain exactly one value")
	}
	value, err := strconv.ParseUint(string(values[0]), 0, 64)
	if err != nil {
		return 0, errors.New("must be an unsigned 64-bit integer")
	}
	return value, nil
}

func productionStringValues(values [][]byte) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}
