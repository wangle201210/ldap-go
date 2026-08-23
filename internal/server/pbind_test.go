package server

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadPBindRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "olcOverlay={0}pbind,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcDbURI",
				Values: stringValues(
					"ldap://127.0.0.1:1389 ldaps://ldap.example.test",
				),
			},
			{
				Description: "olcDbStartTLS",
				Values: stringValues(
					"try-start tls_reqcert=demand tls_reqsan=try tls_crlcheck=peer",
				),
			},
			{Description: "olcDbNetworkTimeout", Values: stringValues("2s")},
			{Description: "olcDbQuarantine", Values: stringValues("1s,2 5s,+")},
		},
	}
	configuration, err := loadPBindRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadPBindRuntimeConfiguration(): %v", err)
	}
	if len(configuration.providers) != 2 ||
		configuration.connection.startTLS != syncConsumerStartTLSYes ||
		configuration.connection.tls.requireCert != "demand" ||
		configuration.connection.tls.requireSAN != "try" ||
		configuration.connection.tls.crlCheck != "peer" ||
		configuration.connection.networkTimeout.Seconds() != 2 ||
		configuration.connection.operationTimeout.Seconds() != 2 ||
		len(configuration.quarantine) != 2 || configuration.health == nil {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestPBindQuarantineSchedule(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	configuration := pbindRuntimeConfiguration{
		quarantine: []syncConsumerRetry{
			{interval: time.Second, attempts: 2},
			{interval: 5 * time.Second, attempts: -1},
		},
		health: &pbindQuarantineState{now: func() time.Time { return now }},
	}
	if !configuration.beginPBindAttempt() {
		t.Fatal("initial pbind attempt was quarantined")
	}
	configuration.finishPBindAttempt(ldapwire.ResultUnavailable)
	if configuration.beginPBindAttempt() {
		t.Fatal("pbind retry was allowed before the first interval")
	}

	now = now.Add(time.Second)
	if !configuration.beginPBindAttempt() {
		t.Fatal("first scheduled retry was not allowed")
	}
	configuration.finishPBindAttempt(ldapwire.ResultUnavailable)
	now = now.Add(time.Second)
	if !configuration.beginPBindAttempt() {
		t.Fatal("second scheduled retry was not allowed")
	}
	configuration.finishPBindAttempt(ldapwire.ResultUnavailable)
	if configuration.health.index != 1 {
		t.Fatalf("quarantine index = %d, want 1", configuration.health.index)
	}

	now = now.Add(time.Second)
	if configuration.beginPBindAttempt() {
		t.Fatal("pbind retry ignored the second interval")
	}
	now = now.Add(4 * time.Second)
	if !configuration.beginPBindAttempt() {
		t.Fatal("permanent scheduled retry was not allowed")
	}
	configuration.finishPBindAttempt(ldapwire.ResultInvalidCredentials)
	if configuration.health.quarantined || configuration.health.index != 0 {
		t.Fatalf("successful target contact did not clear quarantine: %#v", configuration.health)
	}
}

func TestPBindQuarantineAllowsOneConcurrentProbe(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	configuration := pbindRuntimeConfiguration{
		quarantine: []syncConsumerRetry{{interval: time.Second, attempts: -1}},
		health:     &pbindQuarantineState{now: func() time.Time { return now }},
	}
	configuration.finishPBindAttempt(ldapwire.ResultUnavailable)
	now = now.Add(time.Second)

	const callers = 32
	var wait sync.WaitGroup
	results := make(chan bool, callers)
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- configuration.beginPBindAttempt()
		}()
	}
	wait.Wait()
	close(results)
	allowed := 0
	for result := range results {
		if result {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("concurrent quarantine probes allowed = %d, want 1", allowed)
	}
}

func TestPBindCancellationDoesNotRecordProviderFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	configuration := pbindRuntimeConfiguration{
		quarantine: []syncConsumerRetry{{interval: time.Second, attempts: -1}},
		health:     &pbindQuarantineState{now: func() time.Time { return now }},
	}
	if !configuration.beginPBindAttempt() {
		t.Fatal("initial pbind attempt was rejected")
	}
	configuration.cancelPBindAttempt()
	if configuration.health.quarantined || configuration.health.retrying ||
		!configuration.health.lastFailure.IsZero() {
		t.Fatalf("canceled initial attempt changed provider health: %#v", configuration.health)
	}

	configuration.health.quarantined = true
	configuration.health.retrying = true
	configuration.health.lastFailure = now
	configuration.cancelPBindAttempt()
	if !configuration.health.quarantined || configuration.health.retrying ||
		!configuration.health.lastFailure.Equal(now) {
		t.Fatalf("canceled quarantine probe changed provider health: %#v", configuration.health)
	}
}

func TestLoadPBindRuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		attributes []directory.Attribute
	}{
		{name: "missing URI"},
		{
			name: "URI with search base",
			attributes: []directory.Attribute{{
				Description: "olcDbURI",
				Values:      stringValues("ldap://127.0.0.1/dc=example,dc=com"),
			}},
		},
		{
			name: "unsupported URI",
			attributes: []directory.Attribute{{
				Description: "olcDbURI",
				Values:      stringValues("https://ldap.example.test"),
			}},
		},
		{
			name: "invalid TLS mode",
			attributes: []directory.Attribute{
				{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
				{Description: "olcDbStartTLS", Values: stringValues("required")},
			},
		},
		{
			name: "unknown TLS option",
			attributes: []directory.Attribute{
				{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
				{Description: "olcDbStartTLS", Values: stringValues("start tls_magic=yes")},
			},
		},
		{
			name: "invalid quarantine",
			attributes: []directory.Attribute{
				{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
				{Description: "olcDbQuarantine", Values: stringValues("invalid")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadPBindRuntimeConfiguration(directory.Entry{
				DN:         "olcOverlay=pbind,olcDatabase=mdb,cn=config",
				Attributes: test.attributes,
			})
			if err == nil {
				t.Fatal("invalid pbind configuration was accepted")
			}
		})
	}
}

func TestLDAPClientPBindUsesRemoteCredentialsAndFailover(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	providerRunning := true
	t.Cleanup(func() {
		if providerRunning {
			stopProvider()
		}
	})

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedDirectory(t, consumerStore)
	seedPBindConfiguration(
		t,
		consumerStore,
		"ldap://127.0.0.1:1 ldap://"+providerAddress,
		"local-only",
	)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	userDN := "uid=alice,ou=people,dc=example,dc=com"
	if err := client.Bind(userDN, "secret"); err != nil {
		t.Fatalf("remote credential Bind(): %v", err)
	}
	identity, err := client.WhoAmI(nil)
	if err != nil || identity.AuthzID != "dn:"+userDN {
		t.Fatalf("WhoAmI() = %#v, %v", identity, err)
	}

	if err := client.Bind(userDN, "local-only"); err == nil {
		t.Fatal("pbind accepted the local-only password")
	} else {
		assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	}

	stopProvider()
	providerRunning = false
	if err := client.Bind(userDN, "secret"); err == nil {
		t.Fatal("pbind succeeded after every provider stopped")
	} else {
		assertLDAPResultCode(t, err, ldap.LDAPResultUnavailable)
	}
}

func TestLDAPClientPBindRetriesUnavailableProvider(t *testing.T) {
	tests := []struct {
		name  string
		first func(net.Conn) error
	}{
		{
			name: "remote unavailable",
			first: func(connection net.Conn) error {
				return writePBindTestResult(connection, ldapwire.ResultUnavailable)
			},
		},
		{
			name: "connection lost",
			first: func(connection net.Conn) error {
				_, err := readSyncConsumerPacket(connection)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providerAddress, provider := startPBindTestProvider(
				t,
				func(attempt int, connection net.Conn) error {
					if attempt == 1 {
						return test.first(connection)
					}
					return writePBindTestResult(
						connection,
						ldapwire.ResultSuccess,
					)
				},
			)

			consumerAddress, stopConsumer := startPBindTestConsumer(
				t,
				"ldap://"+providerAddress,
				"1s",
			)
			defer stopConsumer()

			client, err := ldap.DialURL("ldap://" + consumerAddress)
			if err != nil {
				t.Fatalf("DialURL(): %v", err)
			}
			defer client.Close()
			if err := client.Bind(
				"uid=alice,ou=people,dc=example,dc=com",
				"secret",
			); err != nil {
				t.Fatalf("Bind after one retry: %v", err)
			}
			provider.waitForAttempts(t, 2)
			time.Sleep(25 * time.Millisecond)
			if got := provider.accepted.Load(); got != 2 {
				t.Fatalf("provider connection attempts = %d, want 2", got)
			}
		})
	}
}

func TestLDAPClientPBindUnavailableFailsOverAfterOneRetry(t *testing.T) {
	firstAddress, first := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			return writePBindTestResult(connection, ldapwire.ResultUnavailable)
		},
	)
	secondAddress, second := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			return writePBindTestResult(connection, ldapwire.ResultSuccess)
		},
	)
	consumerAddress, stopConsumer := startPBindTestConsumer(
		t,
		"ldap://"+firstAddress+" ldap://"+secondAddress,
		"1s",
	)
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"uid=alice,ou=people,dc=example,dc=com",
		"secret",
	); err != nil {
		t.Fatalf("Bind after unavailable provider failover: %v", err)
	}
	first.waitForAttempts(t, 2)
	second.waitForAttempts(t, 1)
	if got := first.accepted.Load(); got != 2 {
		t.Fatalf("unavailable provider attempts = %d, want exactly 2", got)
	}
}

func TestLDAPClientPBindDoesNotRetryDefinitiveResult(t *testing.T) {
	providerAddress, provider := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			return writePBindTestResult(
				connection,
				ldapwire.ResultInvalidCredentials,
			)
		},
	)
	consumerAddress, stopConsumer := startPBindTestConsumer(
		t,
		"ldap://"+providerAddress,
		"1s",
	)
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	err = client.Bind("uid=alice,ou=people,dc=example,dc=com", "wrong")
	if err == nil {
		t.Fatal("pbind accepted invalid credentials")
	}
	assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	provider.waitForAttempts(t, 1)
	time.Sleep(25 * time.Millisecond)
	if got := provider.accepted.Load(); got != 1 {
		t.Fatalf("definitive result provider attempts = %d, want 1", got)
	}
}

func TestLDAPClientPBindDoesNotRetryProtocolFailure(t *testing.T) {
	providerAddress, provider := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			messageID, err := readPBindTestRequest(connection)
			if err != nil {
				return err
			}
			response := ber.NewSequence("LDAPMessage")
			response.AppendChild(ber.NewInteger(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagInteger,
				messageID,
				"messageID",
			))
			response.AppendChild(ber.Encode(
				ber.ClassApplication,
				ber.TypeConstructed,
				ldapwire.ApplicationBindResponse,
				nil,
				"malformed BindResponse",
			))
			return writeAll(connection, response.Bytes())
		},
	)
	consumerAddress, stopConsumer := startPBindTestConsumer(
		t,
		"ldap://"+providerAddress,
		"1s",
	)
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret")
	assertLDAPResultCode(t, err, ldap.LDAPResultUnavailable)
	provider.waitForAttempts(t, 1)
	time.Sleep(50 * time.Millisecond)
	if got := provider.accepted.Load(); got != 1 {
		t.Fatalf("protocol failure attempts = %d, want 1", got)
	}
}

func TestPBindRetryableErrorClassification(t *testing.T) {
	if !pbindRetryableError(io.EOF) {
		t.Fatal("connection loss was not retryable")
	}
	if pbindRetryableError(errors.New("malformed LDAP response")) {
		t.Fatal("deterministic protocol error was retryable")
	}
	if pbindRetryableError(context.DeadlineExceeded) {
		t.Fatal("attempt timeout was retryable")
	}
}

func TestPBindRejectsSuccessFromRetiredRuntime(t *testing.T) {
	requestReceived := make(chan struct{})
	releaseProvider := make(chan struct{})
	defer close(releaseProvider)
	providerAddress, _ := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			messageID, err := readPBindTestRequest(connection)
			if err != nil {
				return err
			}
			close(requestReceived)
			<-releaseProvider
			return writePBindTestResponse(connection, messageID, ldapwire.ResultSuccess)
		},
	)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedPBindConfiguration(t, store, "ldap://"+providerAddress, "local-only")
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	requestDN, err := parseRuntimeConnectionDN(
		instance.runtime.Load(),
		"uid=alice,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForDN(instance.runtime.Load(), requestDN)
	if database == nil || database.pbind == nil {
		t.Fatal("pbind runtime configuration is missing")
	}
	configuration := *database.pbind
	done := make(chan ldapwire.Result, 1)
	go func() {
		result, _ := instance.proxySimpleBind(
			t.Context(),
			configuration,
			ldapwire.Message{ID: 1},
			ldapwire.BindRequest{
				Version: 3,
				Name:    requestDN.String(),
				Authentication: ldapwire.Authentication{
					Simple: []byte("secret"),
				},
			},
		)
		done <- result
	}()
	<-requestReceived
	retired := *instance.runtime.Load()
	retired.databases = append([]runtimeDatabase(nil), retired.databases...)
	for index := range retired.databases {
		retired.databases[index].pbind = nil
	}
	instance.runtime.Store(&retired)
	select {
	case result := <-done:
		if result.Code != ldapwire.ResultUnavailable {
			t.Fatalf("retired pbind result = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("retired pbind did not cancel its active provider connection")
	}
}

func TestPBindRuntimeRetirementCancelsAdmissionWaiter(t *testing.T) {
	if len(pbindGlobalAttempts) != 0 {
		t.Fatalf("global pbind attempts are unexpectedly occupied: %d", len(pbindGlobalAttempts))
	}
	holder := pbindRuntimeConfiguration{identity: newPBindRuntimeIdentity()}
	releases := make([]func(), 0, cap(pbindGlobalAttempts))
	for range cap(pbindGlobalAttempts) {
		release, err := holder.acquirePBindAttempt(t.Context())
		if err != nil {
			t.Fatalf("fill global pbind admission: %v", err)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	configuration := pbindRuntimeConfiguration{identity: newPBindRuntimeIdentity()}
	current := atomic.Bool{}
	current.Store(true)
	stop := watchPBindRuntime(t.Context(), configuration.identity, current.Load)
	defer stop()
	attemptContext, cancelAttempt := configuration.runtimeAttemptContext(t.Context())
	defer cancelAttempt()
	waiter := make(chan error, 1)
	go func() {
		_, err := configuration.acquirePBindAttempt(attemptContext)
		waiter <- err
	}()

	current.Store(false)
	select {
	case err := <-waiter:
		if err == nil || !configuration.retired() {
			t.Fatalf("retired admission waiter = %v, retired=%t", err, configuration.retired())
		}
	case <-time.After(time.Second):
		t.Fatal("runtime retirement did not cancel a pbind admission waiter")
	}
	select {
	case <-attemptContext.Done():
	case <-time.After(time.Second):
		t.Fatal("runtime retirement did not cancel the pbind attempt context")
	}
}

func TestPBindGlobalAdmissionAcrossRuntimeGenerations(t *testing.T) {
	if len(pbindGlobalAttempts) != 0 {
		t.Fatalf("global pbind attempts are unexpectedly occupied: %d", len(pbindGlobalAttempts))
	}
	const callers = defaultPBindConcurrentAttempts + 8
	configurations := []pbindRuntimeConfiguration{
		{identity: newPBindRuntimeIdentity()},
		{identity: newPBindRuntimeIdentity()},
	}
	releaseAttempts := make(chan struct{})
	results := make(chan error, callers)
	started := make(chan struct{}, callers)
	var active, maximum atomic.Int32
	for index := range callers {
		configuration := configurations[index%len(configurations)]
		go func() {
			release, err := configuration.acquirePBindAttempt(t.Context())
			if err != nil {
				results <- err
				return
			}
			current := active.Add(1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			started <- struct{}{}
			<-releaseAttempts
			active.Add(-1)
			release()
			results <- nil
		}()
	}
	for range defaultPBindConcurrentAttempts {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("cross-generation callers did not fill the global pbind limit")
		}
	}
	time.Sleep(30 * time.Millisecond)
	if got := maximum.Load(); got != defaultPBindConcurrentAttempts {
		t.Fatalf("cross-generation maximum = %d, want %d", got, defaultPBindConcurrentAttempts)
	}
	close(releaseAttempts)
	for range callers {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("cross-generation pbind admission: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out draining cross-generation pbind admission")
		}
	}
	if len(pbindGlobalAttempts) != 0 {
		t.Fatalf("global pbind slots leaked after cross-generation test: %d", len(pbindGlobalAttempts))
	}
}

func TestLDAPClientPBindAttemptTimeoutFailsOver(t *testing.T) {
	firstAddress, first := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			if _, err := readSyncConsumerPacket(connection); err != nil {
				return err
			}
			time.Sleep(1500 * time.Millisecond)
			return nil
		},
	)
	secondAddress, second := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			return writePBindTestResult(connection, ldapwire.ResultSuccess)
		},
	)
	consumerAddress, stopConsumer := startPBindTestConsumer(
		t,
		"ldap://"+firstAddress+" ldap://"+secondAddress,
		"1s",
	)
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	started := time.Now()
	if err := client.Bind(
		"uid=alice,ou=people,dc=example,dc=com",
		"secret",
	); err != nil {
		t.Fatalf("Bind after timed-out provider: %v", err)
	}
	elapsed := time.Since(started)
	if elapsed < 800*time.Millisecond || elapsed >= 1800*time.Millisecond {
		t.Fatalf("failover elapsed = %v, want one independent attempt budget", elapsed)
	}
	first.waitForAttempts(t, 1)
	second.waitForAttempts(t, 1)
	if got := first.accepted.Load(); got != 1 {
		t.Fatalf("timed-out provider attempts = %d, want no timeout retry", got)
	}
}

func TestExecutePBindCancellationClosesActiveConnection(t *testing.T) {
	requestReceived := make(chan struct{})
	providerAddress, _ := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			if _, err := readPBindTestRequest(connection); err != nil {
				return err
			}
			close(requestReceived)
			buffer := make([]byte, 1)
			_, _ = connection.Read(buffer)
			return nil
		},
	)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, _, err := executePBind(
			ctx,
			syncConsumerConfig{},
			"ldap://"+providerAddress,
			nil,
			ldapwire.BindRequest{
				Version: 3,
				Name:    "uid=alice,ou=people,dc=example,dc=com",
				Authentication: ldapwire.Authentication{
					Simple: []byte("secret"),
				},
			},
		)
		result <- err
	}()
	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("pbind provider did not receive the request")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled pbind returned without an error")
		}
	case <-time.After(time.Second):
		t.Fatal("active pbind connection ignored context cancellation")
	}
}

func TestLDAPClientPBindBoundsConcurrentAttempts(t *testing.T) {
	const callers = defaultPBindConcurrentAttempts + 8
	release := make(chan struct{})
	started := make(chan struct{}, callers)
	var active, maximum atomic.Int32
	providerAddress, provider := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			messageID, err := readPBindTestRequest(connection)
			if err != nil {
				return err
			}
			current := active.Add(1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			return writePBindTestResponse(
				connection,
				messageID,
				ldapwire.ResultSuccess,
			)
		},
	)
	consumerAddress, stopConsumer := startPBindTestConsumer(
		t,
		"ldap://"+providerAddress,
		"5s",
	)
	defer stopConsumer()

	results := make(chan error, callers)
	for range callers {
		go func() {
			client, err := ldap.DialURL("ldap://" + consumerAddress)
			if err == nil {
				err = client.Bind(
					"uid=alice,ou=people,dc=example,dc=com",
					"secret",
				)
				client.Close()
			}
			results <- err
		}()
	}
	for range defaultPBindConcurrentAttempts {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out filling the pbind attempt limit")
		}
	}
	time.Sleep(150 * time.Millisecond)
	if got := provider.accepted.Load(); got != defaultPBindConcurrentAttempts {
		t.Fatalf(
			"concurrent provider connections = %d, want %d before release",
			got,
			defaultPBindConcurrentAttempts,
		)
	}
	close(release)
	for range callers {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent pbind: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out draining concurrent pbind attempts")
		}
	}
	provider.waitForAttempts(t, callers)
	if got := maximum.Load(); got > defaultPBindConcurrentAttempts {
		t.Fatalf("maximum active provider attempts = %d", got)
	}
}

func TestOpenLDAPPBindConnectionLifecycleSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	bindSource, err := os.ReadFile(filepath.Join(
		sourceRoot,
		"servers",
		"slapd",
		"back-ldap",
		"bind.c",
	))
	if err != nil {
		t.Fatalf("read pinned OpenLDAP bind.c: %v", err)
	}
	for _, contract := range []string{
		"Explicit Bind requests always get their own conn",
		"if ( rc == LDAP_UNAVAILABLE && retrying )",
		"retrying &= ~LDAP_BACK_RETRYING",
	} {
		if !strings.Contains(string(bindSource), contract) {
			t.Fatalf("pinned OpenLDAP bind.c lacks %q", contract)
		}
	}
	slapHeader, err := os.ReadFile(filepath.Join(
		sourceRoot,
		"servers",
		"slapd",
		"slap.h",
	))
	if err != nil {
		t.Fatalf("read pinned OpenLDAP slap.h: %v", err)
	}
	if !strings.Contains(
		string(slapHeader),
		"#define SLAP_MAX_WORKER_THREADS\t\t(16)",
	) {
		t.Fatal("pinned OpenLDAP worker concurrency default changed")
	}
}

func TestLDAPClientPBindStartTLSModes(t *testing.T) {
	t.Run("critical with trusted peer", func(t *testing.T) {
		providerTLS := testServerTLSConfig(t)
		providerStore := storage.NewMemory()
		t.Cleanup(func() { _ = providerStore.Close() })
		seedDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(
			t,
			providerStore,
			Config{TLSConfig: providerTLS},
		)
		defer stopProvider()

		certificatePath := writePBindTestCertificate(
			t,
			providerTLS.Certificates[0].Certificate[0],
		)
		_, port, err := net.SplitHostPort(providerAddress)
		if err != nil {
			t.Fatalf("SplitHostPort(): %v", err)
		}
		consumerStore := storage.NewMemory()
		t.Cleanup(func() { _ = consumerStore.Close() })
		seedDirectory(t, consumerStore)
		seedPBindConfiguration(
			t,
			consumerStore,
			"ldap://localhost:"+port,
			"local-only",
		)
		setPBindStartTLS(
			t,
			consumerStore,
			"start tls_cacert="+certificatePath+
				" tls_reqcert=demand tls_reqsan=demand",
		)
		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
		defer stopConsumer()

		client, err := ldap.DialURL("ldap://" + consumerAddress)
		if err != nil {
			t.Fatalf("DialURL(): %v", err)
		}
		defer client.Close()
		if err := client.Bind(
			"uid=alice,ou=people,dc=example,dc=com",
			"secret",
		); err != nil {
			t.Fatalf("StartTLS pbind: %v", err)
		}
	})

	t.Run("critical rejects untrusted peer", func(t *testing.T) {
		providerTLS := testServerTLSConfig(t)
		providerStore := storage.NewMemory()
		t.Cleanup(func() { _ = providerStore.Close() })
		seedDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(
			t,
			providerStore,
			Config{TLSConfig: providerTLS},
		)
		defer stopProvider()

		untrustedTLS := testServerTLSConfig(t)
		certificatePath := writePBindTestCertificate(
			t,
			untrustedTLS.Certificates[0].Certificate[0],
		)
		_, port, err := net.SplitHostPort(providerAddress)
		if err != nil {
			t.Fatalf("SplitHostPort(): %v", err)
		}
		consumerStore := storage.NewMemory()
		t.Cleanup(func() { _ = consumerStore.Close() })
		seedDirectory(t, consumerStore)
		seedPBindConfiguration(
			t,
			consumerStore,
			"ldap://localhost:"+port,
			"local-only",
		)
		setPBindStartTLS(
			t,
			consumerStore,
			"start tls_cacert="+certificatePath+" tls_reqcert=demand",
		)
		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
		defer stopConsumer()

		client, err := ldap.DialURL("ldap://" + consumerAddress)
		if err != nil {
			t.Fatalf("DialURL(): %v", err)
		}
		defer client.Close()
		err = client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret")
		if err == nil {
			t.Fatal("pbind accepted an untrusted StartTLS provider")
		}
		assertLDAPResultCode(t, err, ldap.LDAPResultUnavailable)
	})

	t.Run("try-start falls back to cleartext", func(t *testing.T) {
		providerStore := storage.NewMemory()
		t.Cleanup(func() { _ = providerStore.Close() })
		seedDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(t, providerStore, Config{})
		defer stopProvider()

		consumerStore := storage.NewMemory()
		t.Cleanup(func() { _ = consumerStore.Close() })
		seedDirectory(t, consumerStore)
		seedPBindConfiguration(
			t,
			consumerStore,
			"ldap://"+providerAddress,
			"local-only",
		)
		setPBindStartTLS(t, consumerStore, "try-start")
		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
		defer stopConsumer()

		client, err := ldap.DialURL("ldap://" + consumerAddress)
		if err != nil {
			t.Fatalf("DialURL(): %v", err)
		}
		defer client.Close()
		if err := client.Bind(
			"uid=alice,ou=people,dc=example,dc=com",
			"secret",
		); err != nil {
			t.Fatalf("noncritical StartTLS pbind fallback: %v", err)
		}
	})
}

func TestPBindOverlayConfigurationValidation(t *testing.T) {
	t.Parallel()

	t.Run("duplicate", func(t *testing.T) {
		store := storage.NewMemory()
		defer store.Close()
		seedDirectory(t, store)
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			for _, index := range []string{"{0}", "{1}"} {
				if err := writer.Put(directory.Entry{
					DN: "olcOverlay=" + index + "pbind,olcDatabase={1}mdb,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcOverlay", Values: stringValues(index + "pbind")},
						{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
					},
				}, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed duplicate overlays: %v", err)
		}
		if _, err := New(Config{Store: store}); err == nil {
			t.Fatal("New() accepted duplicate pbind overlays")
		}
	})

	t.Run("global", func(t *testing.T) {
		store := storage.NewMemory()
		defer store.Close()
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			entries := []directory.Entry{
				{
					DN: "olcDatabase={-1}frontend,cn=config",
					Attributes: []directory.Attribute{{
						Description: "olcDatabase",
						Values:      stringValues("{-1}frontend"),
					}},
				},
				{
					DN: "olcOverlay={0}pbind,olcDatabase={-1}frontend,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcOverlay", Values: stringValues("{0}pbind")},
						{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
					},
				},
			}
			for _, entry := range entries {
				if err := writer.Put(entry, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed global overlay: %v", err)
		}
		if _, err := New(Config{Store: store}); err == nil {
			t.Fatal("New() accepted a global pbind overlay")
		}
	})
}

func TestDecodePBindResponseControls(t *testing.T) {
	t.Parallel()

	response := ber.NewSequence("LDAPMessage")
	response.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(1),
		"messageID",
	))
	response.AppendChild(ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindResponse,
		nil,
		"BindResponse",
	))
	wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	control := ber.NewSequence("Control")
	control.AppendChild(syncConsumerOctetString([]byte("1.2.3"), "OID"))
	control.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		true,
		"critical",
	))
	control.AppendChild(syncConsumerOctetString(nil, "value"))
	wrapper.AppendChild(control)
	response.AppendChild(wrapper)

	controls, err := decodePBindResponseControls(response)
	if err != nil || len(controls) != 1 || controls[0].OID != "1.2.3" ||
		!controls[0].Critical || !controls[0].HasValue || len(controls[0].Value) != 0 {
		t.Fatalf("decodePBindResponseControls() = %#v, %v", controls, err)
	}
}

func seedPBindConfiguration(
	t *testing.T,
	store storage.Store,
	providers,
	localPassword string,
) {
	t.Helper()
	userDN, err := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		user, err := writer.Get(userDN)
		if err != nil {
			return err
		}
		user.ReplaceValues("userPassword", stringValues(localPassword))
		if err := writer.Put(user, true); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}pbind,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}pbind")},
				{Description: "olcDbURI", Values: stringValues(providers)},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed pbind configuration: %v", err)
	}
}

func setPBindStartTLS(t *testing.T, store storage.Store, value string) {
	t.Helper()
	dn, err := directory.ParseDN(
		"olcOverlay={0}pbind,olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbStartTLS", stringValues(value))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure pbind StartTLS: %v", err)
	}
}

func writePBindTestCertificate(t *testing.T, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	return path
}

type pbindTestProvider struct {
	listener net.Listener
	accepted atomic.Int32
	errors   chan error
	wait     sync.WaitGroup
}

func startPBindTestProvider(
	t *testing.T,
	handler func(int, net.Conn) error,
) (string, *pbindTestProvider) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for pbind provider: %v", err)
	}
	provider := &pbindTestProvider{
		listener: listener,
		errors:   make(chan error, 256),
	}
	provider.wait.Add(1)
	go func() {
		defer provider.wait.Done()
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			attempt := int(provider.accepted.Add(1))
			provider.wait.Add(1)
			go func() {
				defer provider.wait.Done()
				defer connection.Close()
				if handlerErr := handler(attempt, connection); handlerErr != nil {
					provider.errors <- handlerErr
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		provider.wait.Wait()
		close(provider.errors)
		for providerErr := range provider.errors {
			t.Errorf("pbind provider: %v", providerErr)
		}
	})
	return listener.Addr().String(), provider
}

func (provider *pbindTestProvider) waitForAttempts(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for int(provider.accepted.Load()) < want {
		if time.Now().After(deadline) {
			t.Fatalf(
				"pbind provider attempts = %d, want at least %d",
				provider.accepted.Load(),
				want,
			)
		}
		time.Sleep(time.Millisecond)
	}
}

func startPBindTestConsumer(
	t *testing.T,
	providers string,
	networkTimeout string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedPBindConfiguration(t, store, providers, "local-only")
	setPBindNetworkTimeout(t, store, networkTimeout)
	return startServer(t, store, Config{})
}

func setPBindNetworkTimeout(t *testing.T, store storage.Store, value string) {
	t.Helper()
	dn, err := directory.ParseDN(
		"olcOverlay={0}pbind,olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbNetworkTimeout", stringValues(value))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure pbind network timeout: %v", err)
	}
}

func readPBindTestRequest(connection net.Conn) (int64, error) {
	request, err := readSyncConsumerPacket(connection)
	if err != nil {
		return 0, err
	}
	if len(request.Children) < 2 ||
		request.Children[1].ClassType != ber.ClassApplication ||
		request.Children[1].Tag != ldapwire.ApplicationBindRequest {
		return 0, fmt.Errorf("unexpected pbind request %#v", request)
	}
	messageID, err := syncConsumerPacketInteger(request.Children[0])
	if err != nil {
		return 0, fmt.Errorf("pbind message ID: %w", err)
	}
	return messageID, nil
}

func writePBindTestResult(
	connection net.Conn,
	code ldapwire.ResultCode,
) error {
	messageID, err := readPBindTestRequest(connection)
	if err != nil {
		return err
	}
	return writePBindTestResponse(connection, messageID, code)
}

func writePBindTestResponse(
	connection net.Conn,
	messageID int64,
	code ldapwire.ResultCode,
) error {
	return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		messageID,
		ldapwire.Result{Code: code},
		nil,
	))
}
