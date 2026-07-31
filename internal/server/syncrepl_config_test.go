package server

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseSyncConsumerConfigOpenLDAPValue(t *testing.T) {
	t.Parallel()

	suffix := mustSyncConsumerDN(t, "dc=example,dc=com")
	config, err := parseSyncConsumerConfig(
		`{2}rid=007 provider="ldap://provider-a:1389 ldap://provider-b" `+
			`bindmethod=simple binddn="cn=replicator,dc=example,dc=com" `+
			`credentials="space secret" searchbase="dc=example,dc=com" `+
			`filter="(&(objectClass=inetOrgPerson)(cn=literal\2a))" `+
			`scope=sub attrs="cn,sn,*,+" exattrs="jpegPhoto userPassword" `+
			`attrsonly=off schemachecking=on type=refreshOnly `+
			`interval=01:02:03:04 retry="5 3 60 +" `+
			`sizelimit=unlimited timelimit=30 manageDSAit=1 `+
			`starttls=critical tls_reqcert=demand network-timeout=4 `+
			`timeout=5 tcp-user-timeout=6000 keepalive=10:3:2 version=3`,
		"database/example",
		[]directory.DN{suffix},
	)
	if err != nil {
		t.Fatalf("parseSyncConsumerConfig(): %v", err)
	}

	if config.order != 2 || config.rid != 7 {
		t.Fatalf("order/rid = %d/%d, want 2/7", config.order, config.rid)
	}
	if !slices.Equal(config.providerURLs, []string{
		"ldap://provider-a:1389",
		"ldap://provider-b",
	}) {
		t.Fatalf("provider URLs = %q", config.providerURLs)
	}
	if config.partition != "database/example" {
		t.Fatalf("partition = %q", config.partition)
	}
	if config.bindDN != "cn=replicator,dc=example,dc=com" ||
		string(config.credentials) != "space secret" {
		t.Fatalf(
			"bind identity = %q/%q",
			config.bindDN,
			config.credentials,
		)
	}
	if config.filterText != `(&(objectClass=inetOrgPerson)(cn=literal\2a))` {
		t.Fatalf("filter = %q", config.filterText)
	}
	if config.scope != directory.ScopeWholeSubtree {
		t.Fatalf("scope = %d", config.scope)
	}
	if !slices.Equal(config.attributes, []string{"cn", "sn", "*", "+"}) ||
		!slices.Equal(config.exAttributes, []string{"jpegPhoto", "userPassword"}) {
		t.Fatalf(
			"attributes/exattrs = %q/%q",
			config.attributes,
			config.exAttributes,
		)
	}
	if config.attributesOnly || !config.schemaChecking {
		t.Fatalf(
			"attrsonly/schemachecking = %t/%t",
			config.attributesOnly,
			config.schemaChecking,
		)
	}
	if config.mode != syncConsumerRefreshOnly ||
		config.interval != 26*time.Hour+3*time.Minute+4*time.Second {
		t.Fatalf("mode/interval = %d/%s", config.mode, config.interval)
	}
	if len(config.retry) != 2 ||
		config.retry[0].interval != 5*time.Second ||
		config.retry[0].attempts != 3 ||
		config.retry[1].interval != time.Minute ||
		config.retry[1].attempts != -1 {
		t.Fatalf("retry = %#v", config.retry)
	}
	if config.sizeLimit != 0 || config.timeLimit != 30 ||
		!config.manageDSAit {
		t.Fatalf(
			"limits/manageDSAit = %d/%d/%t",
			config.sizeLimit,
			config.timeLimit,
			config.manageDSAit,
		)
	}
	if config.startTLS != syncConsumerStartTLSCritical ||
		config.tls.requireCert != "demand" ||
		config.networkTimeout != 4*time.Second ||
		config.operationTimeout != 5*time.Second ||
		config.tcpUserTimeout != 6*time.Second {
		t.Fatalf(
			"transport settings = %d/%q/%s/%s/%s",
			config.startTLS,
			config.tls.requireCert,
			config.networkTimeout,
			config.operationTimeout,
			config.tcpUserTimeout,
		)
	}
	if !config.keepalive.set ||
		config.keepalive.idle != 10 ||
		config.keepalive.probes != 3 ||
		config.keepalive.interval != 2 {
		t.Fatalf("keepalive = %#v", config.keepalive)
	}
	if !config.localBase.Equal(suffix) {
		t.Fatalf("local base = %q", config.localBase.String())
	}
}

func TestParseSyncConsumerConfigDefaults(t *testing.T) {
	t.Parallel()

	suffix := mustSyncConsumerDN(t, "dc=example,dc=com")
	config, err := parseSyncConsumerConfig(
		`rid=0 provider=ldap://127.0.0.1 searchbase="dc=example,dc=com"`,
		"database/example",
		[]directory.DN{suffix},
	)
	if err != nil {
		t.Fatalf("parseSyncConsumerConfig(): %v", err)
	}
	if config.filterText != "(objectclass=*)" ||
		config.scope != directory.ScopeWholeSubtree ||
		!slices.Equal(config.attributes, []string{"*", "+"}) {
		t.Fatalf(
			"default search = %q/%d/%q",
			config.filterText,
			config.scope,
			config.attributes,
		)
	}
	if config.mode != syncConsumerRefreshOnly ||
		config.interval != 24*time.Hour ||
		len(config.retry) != 1 ||
		config.retry[0].interval != time.Hour ||
		config.retry[0].attempts != -1 {
		t.Fatalf(
			"default scheduling = %d/%s/%#v",
			config.mode,
			config.interval,
			config.retry,
		)
	}
}

func TestParseSyncConsumerConfigSuffixMassage(t *testing.T) {
	t.Parallel()

	local := mustSyncConsumerDN(t, "dc=local,dc=com")
	_, err := parseSyncConsumerConfig(
		`rid=1 provider=ldap://provider `+
			`searchbase="dc=remote,dc=com" suffixmassage="dc=local,dc=com"`,
		"database/local",
		[]directory.DN{local},
	)
	if err != nil {
		t.Fatalf("suffixmassage configuration: %v", err)
	}
	_, err = parseSyncConsumerConfig(
		`rid=1 provider=ldap://provider searchbase="dc=remote,dc=com"`,
		"database/local",
		[]directory.DN{local},
	)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside searchbase error = %v", err)
	}
}

func TestParseSyncConsumerConfigRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	suffix := mustSyncConsumerDN(t, "dc=example,dc=com")
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "missing required",
			value: `rid=1 provider=ldap://provider`,
			want:  "searchbase",
		},
		{
			name: "rid range",
			value: `rid=1000 provider=ldap://provider ` +
				`searchbase="dc=example,dc=com"`,
			want: "outside",
		},
		{
			name: "provider scheme",
			value: `rid=1 provider=http://provider ` +
				`searchbase="dc=example,dc=com"`,
			want: "unsupported scheme",
		},
		{
			name: "filter",
			value: `rid=1 provider=ldap://provider ` +
				`searchbase="dc=example,dc=com" filter="(cn="`,
			want: "filter",
		},
		{
			name: "retry pair",
			value: `rid=1 provider=ldap://provider ` +
				`searchbase="dc=example,dc=com" retry="5 3 60"`,
			want: "incomplete",
		},
		{
			name: "permanent retry position",
			value: `rid=1 provider=ldap://provider ` +
				`searchbase="dc=example,dc=com" retry="5 + 60 2"`,
			want: "final",
		},
		{
			name: "interval",
			value: `rid=1 provider=ldap://provider ` +
				`searchbase="dc=example,dc=com" interval=1h2d`,
			want: "interval",
		},
		{
			name: "unknown argument",
			value: `rid=1 provider=ldap://provider ` +
				`searchbase="dc=example,dc=com" mystery=yes`,
			want: "unknown",
		},
		{
			name: "SASL fields on simple bind",
			value: `rid=1 provider=ldap://provider ` +
				`searchbase="dc=example,dc=com" saslmech=EXTERNAL`,
			want: "bindmethod=sasl",
		},
		{
			name: "delta log settings",
			value: `rid=1 provider=ldap://provider ` +
				`searchbase="dc=example,dc=com" syncdata=accesslog`,
			want: "requires logbase and logfilter",
		},
		{
			name: "attribute include",
			value: `rid=1 provider=ldap://provider ` +
				`searchbase="dc=example,dc=com" attrs=:include:/tmp/attrs`,
			want: "include files",
		},
		{
			name: "unterminated quote",
			value: `rid=1 provider="ldap://provider ` +
				`searchbase="dc=example,dc=com"`,
			want: "unterminated",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseSyncConsumerConfig(
				test.value,
				"database/example",
				[]directory.DN{suffix},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf(
					"parseSyncConsumerConfig() error = %v, want %q",
					err,
					test.want,
				)
			}
		})
	}
}

func TestLoadRuntimeDatabasesOrdersSyncConsumers(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{
				Description: "olcSyncrepl",
				Values: stringValues(
					`{1}rid=2 provider=ldap://two searchbase="dc=example,dc=com"`,
					`{0}rid=1 provider=ldap://one searchbase="dc=example,dc=com"`,
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	if len(databases) != 1 || len(databases[0].syncConsumers) != 2 {
		t.Fatalf("sync consumers = %#v", databases)
	}
	if databases[0].syncConsumers[0].rid != 1 ||
		databases[0].syncConsumers[1].rid != 2 {
		t.Fatalf("consumer order = %#v", databases[0].syncConsumers)
	}
}

func TestLoadRuntimeDatabasesRejectsDuplicateSyncConsumerRID(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=one,dc=com")},
				{
					Description: "olcSyncrepl",
					Values: stringValues(
						`rid=7 provider=ldap://one searchbase="dc=one,dc=com"`,
					),
				},
			},
		},
		{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=two,dc=com")},
				{
					Description: "olcSyncrepl",
					Values: stringValues(
						`rid=7 provider=ldap://two searchbase="dc=two,dc=com"`,
					),
				},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	_, err := loadRuntimeDatabases(context.Background(), store)
	if err == nil || !strings.Contains(err.Error(), "rid 007") {
		t.Fatalf("duplicate rid error = %v", err)
	}
}

func mustSyncConsumerDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
