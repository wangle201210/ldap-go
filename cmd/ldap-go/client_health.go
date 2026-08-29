package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

const defaultReplicationHealthGrace = 2 * time.Minute

type healthReport struct {
	Healthy   bool                        `json:"healthy"`
	CheckedAt time.Time                   `json:"checked_at"`
	Endpoint  string                      `json:"endpoint"`
	Consumers []replicationConsumerHealth `json:"consumers"`
}

type replicationConsumerHealth struct {
	Name            string     `json:"name"`
	State           string     `json:"state"`
	RID             string     `json:"rid,omitempty"`
	Partition       string     `json:"partition,omitempty"`
	Provider        string     `json:"provider,omitempty"`
	Attempts        uint64     `json:"attempts"`
	Retries         uint64     `json:"retries"`
	LastAttempt     *time.Time `json:"last_attempt,omitempty"`
	LastSuccess     *time.Time `json:"last_success,omitempty"`
	DegradedSince   *time.Time `json:"degraded_since,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	Healthy         bool       `json:"healthy"`
	UnhealthyReason string     `json:"unhealthy_reason,omitempty"`
}

func runHealth(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	flags := flag.NewFlagSet("health", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var client ldapClientOptions
	client.register(flags)
	degradedGrace := flags.Duration(
		"degraded-grace",
		defaultReplicationHealthGrace,
		"maximum tolerated syncrepl degraded duration",
	)
	jsonOutput := flags.Bool("json", false, "emit a machine-readable JSON report")
	defer client.clear()
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := client.validate(flags); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *degradedGrace < 0 {
		return errors.New("degraded grace cannot be negative")
	}

	connection, err := client.connectAndBind(flags, stdin, stderr)
	if err != nil {
		return err
	}
	defer connection.Close()
	if _, err := connection.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedLDAPVersion"},
		client.generalControls,
	)); err != nil {
		return fmt.Errorf("root DSE health search: %w", err)
	}
	monitorResult, err := connection.Search(ldap.NewSearchRequest(
		"cn=Monitor",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"monitoredInfo"},
		client.generalControls,
	))
	if err != nil {
		return fmt.Errorf("monitor health search: %w", err)
	}
	if len(monitorResult.Entries) != 1 {
		return fmt.Errorf("monitor health search returned %d entries", len(monitorResult.Entries))
	}
	configuredConsumers, err := monitorReplicationConsumerCount(
		monitorResult.Entries[0].GetAttributeValues("monitoredInfo"),
	)
	if err != nil {
		return fmt.Errorf("monitor replication inventory: %w", err)
	}

	var result *ldap.SearchResult
	if configuredConsumers != 0 {
		if _, err := connection.Search(ldap.NewSearchRequest(
			"cn=Replication,cn=Monitor",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1,
			0,
			false,
			"(objectClass=monitorContainer)",
			[]string{"1.1"},
			client.generalControls,
		)); err != nil {
			return fmt.Errorf("replication monitor container search: %w", err)
		}
		result, err = connection.Search(ldap.NewSearchRequest(
			"cn=Replication,cn=Monitor",
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=monitoredObject)",
			[]string{"cn", "monitoredInfo"},
			client.generalControls,
		))
		if err != nil {
			return fmt.Errorf("replication health search: %w", err)
		}
		if len(result.Entries) != configuredConsumers {
			return fmt.Errorf(
				"replication health inventory returned %d of %d configured consumers",
				len(result.Entries),
				configuredConsumers,
			)
		}
	}

	now := time.Now().UTC()
	report := healthReport{Healthy: true, CheckedAt: now, Endpoint: client.uri}
	if result != nil {
		for _, entry := range result.Entries {
			consumer, parseErr := parseReplicationConsumerHealth(
				entry.GetAttributeValue("cn"),
				entry.GetAttributeValues("monitoredInfo"),
				now,
				*degradedGrace,
			)
			if parseErr != nil {
				return fmt.Errorf("parse replication health entry %q: %w", entry.DN, parseErr)
			}
			if !consumer.Healthy {
				report.Healthy = false
			}
			report.Consumers = append(report.Consumers, consumer)
		}
	}
	if err := writeHealthReport(stdout, report, *jsonOutput); err != nil {
		return err
	}
	if !report.Healthy {
		return &ldapClientExitError{code: 2}
	}
	return nil
}

func monitorReplicationConsumerCount(values []string) (int, error) {
	for _, value := range values {
		raw, found := strings.CutPrefix(value, "replicationConsumers=")
		if !found {
			continue
		}
		count, err := strconv.Atoi(raw)
		if err != nil || count < 0 {
			return 0, fmt.Errorf("invalid replication consumer count %q", raw)
		}
		return count, nil
	}
	return 0, errors.New("replication consumer count is not visible")
}

func parseReplicationConsumerHealth(
	name string,
	values []string,
	now time.Time,
	grace time.Duration,
) (replicationConsumerHealth, error) {
	consumer := replicationConsumerHealth{Name: name}
	for _, raw := range values {
		key, value, found := strings.Cut(raw, "=")
		if !found {
			continue
		}
		switch key {
		case "state":
			consumer.State = value
		case "rid":
			consumer.RID = value
		case "partition":
			consumer.Partition = value
		case "provider":
			consumer.Provider = value
		case "attempts":
			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return consumer, fmt.Errorf("invalid attempts %q", value)
			}
			consumer.Attempts = parsed
		case "retries":
			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return consumer, fmt.Errorf("invalid retries %q", value)
			}
			consumer.Retries = parsed
		case "lastAttempt":
			parsed, err := parseMonitorHealthTime(value)
			if err != nil {
				return consumer, fmt.Errorf("invalid lastAttempt %q: %w", value, err)
			}
			consumer.LastAttempt = &parsed
		case "lastSuccess":
			parsed, err := parseMonitorHealthTime(value)
			if err != nil {
				return consumer, fmt.Errorf("invalid lastSuccess %q: %w", value, err)
			}
			consumer.LastSuccess = &parsed
		case "degradedSince":
			parsed, err := parseMonitorHealthTime(value)
			if err != nil {
				return consumer, fmt.Errorf("invalid degradedSince %q: %w", value, err)
			}
			consumer.DegradedSince = &parsed
		case "lastError":
			consumer.LastError = value
		}
	}
	if consumer.State == "" {
		return consumer, errors.New("state is missing")
	}
	consumer.Healthy, consumer.UnhealthyReason = evaluateReplicationConsumerHealth(
		consumer,
		now,
		grace,
	)
	return consumer, nil
}

func evaluateReplicationConsumerHealth(
	consumer replicationConsumerHealth,
	now time.Time,
	grace time.Duration,
) (bool, string) {
	switch strings.ToLower(consumer.State) {
	case "healthy":
		return true, ""
	case "connecting", "synchronizing", "retrying":
		if consumer.DegradedSince != nil &&
			now.Sub(*consumer.DegradedSince) <= grace {
			return true, ""
		}
		return false, "replication has exceeded the degraded grace period"
	case "configured":
		return false, "replication worker has not started"
	case "stopped":
		return false, "replication worker stopped"
	default:
		return false, "unknown replication state"
	}
}

func parseMonitorHealthTime(value string) (time.Time, error) {
	for _, layout := range []string{"20060102150405Z", "20060102150405.000000Z"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, errors.New("invalid generalized time")
}

func writeHealthReport(writer io.Writer, report healthReport, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(report)
	}
	status := "healthy"
	if !report.Healthy {
		status = "unhealthy"
	}
	if _, err := fmt.Fprintf(writer, "%s: %d replication consumer(s)\n", status, len(report.Consumers)); err != nil {
		return err
	}
	for _, consumer := range report.Consumers {
		if _, err := fmt.Fprintf(
			writer,
			"%s rid=%s partition=%s state=%s provider=%s retries=%d",
			consumer.Name,
			consumer.RID,
			consumer.Partition,
			consumer.State,
			consumer.Provider,
			consumer.Retries,
		); err != nil {
			return err
		}
		if consumer.UnhealthyReason != "" {
			if _, err := fmt.Fprintf(writer, " reason=%q", consumer.UnhealthyReason); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
	}
	return nil
}
