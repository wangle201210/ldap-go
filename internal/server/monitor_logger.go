package server

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
)

type monitorLogCategory uint32

const monitorLogRouteActive uint64 = 1 << 32

const (
	monitorLogTrace   monitorLogCategory = 0x0001
	monitorLogPackets monitorLogCategory = 0x0002
	monitorLogArgs    monitorLogCategory = 0x0004
	monitorLogConns   monitorLogCategory = 0x0008
	monitorLogBER     monitorLogCategory = 0x0010
	monitorLogFilter  monitorLogCategory = 0x0020
	monitorLogConfig  monitorLogCategory = 0x0040
	monitorLogACL     monitorLogCategory = 0x0080
	monitorLogStats   monitorLogCategory = 0x0100
	monitorLogStats2  monitorLogCategory = 0x0200
	monitorLogShell   monitorLogCategory = 0x0400
	monitorLogParse   monitorLogCategory = 0x0800
	monitorLogSync    monitorLogCategory = 0x4000
	monitorLogNone    monitorLogCategory = 0x8000
	monitorLogAny     monitorLogCategory = ^monitorLogCategory(0)
)

var monitorLogCategories = map[string]monitorLogCategory{
	"trace":   monitorLogTrace,
	"packets": monitorLogPackets,
	"args":    monitorLogArgs,
	"conns":   monitorLogConns,
	"ber":     monitorLogBER,
	"filter":  monitorLogFilter,
	"config":  monitorLogConfig,
	"acl":     monitorLogACL,
	"stats":   monitorLogStats,
	"stats2":  monitorLogStats2,
	"shell":   monitorLogShell,
	"parse":   monitorLogParse,
	"sync":    monitorLogSync,
	"none":    monitorLogNone,
	"any":     monitorLogAny,
}

func compileMonitorLogMask(values []string) monitorLogCategory {
	var mask monitorLogCategory
	for _, value := range values {
		value = strings.TrimSpace(value)
		if category, ok := monitorLogCategories[strings.ToLower(value)]; ok {
			mask |= category
			continue
		}
		if number, ok := parseMonitorLogMaskNumber(value); ok {
			mask |= monitorLogCategory(number)
		}
	}
	return mask
}

func parseMonitorLogMaskNumber(value string) (uint32, bool) {
	if number, err := strconv.ParseInt(value, 0, 32); err == nil {
		return uint32(int32(number)), true
	}
	if number, err := strconv.ParseUint(value, 0, 32); err == nil {
		return uint32(number), true
	}
	if number, err := strconv.ParseInt(value, 10, 32); err == nil {
		return uint32(int32(number)), true
	}
	if number, err := strconv.ParseUint(value, 10, 32); err == nil {
		return uint32(number), true
	}
	return 0, false
}

type monitorLogHandler struct {
	next    slog.Handler
	monitor *monitorState
}

func (handler *monitorLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	mask, active := handler.monitor.logRoute()
	if !active {
		return handler.next.Enabled(ctx, level)
	}
	return mask != 0
}

func (handler *monitorLogHandler) Handle(ctx context.Context, record slog.Record) error {
	mask, active := handler.monitor.logRoute()
	if !active {
		return handler.next.Handle(ctx, record)
	}
	categories, label := monitorLogEventCategory(record.Message)
	if mask&categories == 0 {
		return nil
	}
	record.AddAttrs(slog.String("openldap_category", label))
	return handler.next.Handle(ctx, record)
}

func (handler *monitorLogHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	return &monitorLogHandler{
		next:    handler.next.WithAttrs(attributes),
		monitor: handler.monitor,
	}
}

func (handler *monitorLogHandler) WithGroup(name string) slog.Handler {
	return &monitorLogHandler{
		next:    handler.next.WithGroup(name),
		monitor: handler.monitor,
	}
}

func monitorLogEventCategory(message string) (monitorLogCategory, string) {
	switch message {
	case "TLS handshake failed",
		"secure transport returned a nil connection",
		"LDAP Cancel request failed",
		"LDAP request failed":
		return monitorLogConns, "CONNS"
	case "closing malformed LDAP connection":
		return monitorLogBER, "BER"
	case "AutoCA entry issuance skipped",
		"AutoCA Search preparation failed",
		"close SQL backend":
		return monitorLogConfig, "CONFIG"
	case "SASL auxiliary credential lookup failed",
		"SASL GSSAPI AP-REQ rejected",
		"SASL GSSAPI security selection rejected",
		"external password verification failed",
		"load remoteauth entry",
		"resolve remoteauth realm",
		"remoteauth provider failed",
		"remoteauth password hashing failed; storing cleartext for OpenLDAP compatibility",
		"store remoteauth password",
		"pbind provider failed",
		"OTP state transaction failed",
		"TOTP authentication state update failed",
		"TOTP root authentication state update failed",
		"forward password policy state update failed":
		return monitorLogACL, "ACL"
	case "write LDAP audit event",
		"write OpenLDAP auditlog record",
		"write accesslog operation",
		"accesslog purge failed",
		"LDAP dynamic refresh failed",
		"DDS expiration failed",
		"LDAP operation failed",
		"LDAP transaction operation preparation failed",
		"LDAP transaction operation accounting failed",
		"LDAP transaction seqmod acquisition failed",
		"LDAP transaction external password verification failed",
		"LDAP transaction failed",
		"rejecting delegated search with unverifiable candidate limit":
		return monitorLogStats, "STATS"
	case "back-sock request encoding failed",
		"back-sock request write failed",
		"back-sock response parsing failed",
		"socket overlay response callback failed closed",
		"homedir overlay filesystem operation failed":
		return monitorLogShell, "SHELL"
	case "syncrepl consumer stopped after retry policy was exhausted",
		"syncrepl consumer will retry",
		"syncrepl StartTLS was rejected; continuing without TLS":
		return monitorLogSync, "SYNC"
	default:
		// OpenLDAP uses LDAP_DEBUG_ANY for errors without a narrower subsystem.
		return monitorLogAny, "ANY"
	}
}
