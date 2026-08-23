package lloadd

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestOpenLDAPReferenceLloaddResultDifferential(t *testing.T) {
	requirePinnedOpenLDAPLloaddSource(t)
	configText := `
sockbuf_max_incoming_client 4194303
sockbuf_max_incoming_upstream 4194303
restrict_control 1.2.3.4 reject
`
	referenceAddress := startOpenLDAPReferenceLloadd(t, configText)
	config, err := ParseReader("lloadd-result.conf", strings.NewReader(configText))
	if err != nil {
		t.Fatalf("ParseReader(): %v", err)
	}
	runtime, err := config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(): %v", err)
	}
	_, goAddress := startRuntimeProxy(t, runtime)

	for _, test := range []struct {
		name     string
		controls []ldap.Control
		want     uint16
	}{
		{name: "unavailable", want: ldap.LDAPResultUnavailable},
		{
			name: "rejected control",
			controls: []ldap.Control{
				ldap.NewControlString("1.2.3.4", true, ""),
			},
			want: ldap.LDAPResultUnwillingToPerform,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			referenceCode := searchLDAPResultCode(t, referenceAddress, test.controls)
			goCode := searchLDAPResultCode(t, goAddress, test.controls)
			if referenceCode != test.want || goCode != test.want {
				t.Fatalf(
					"result codes: OpenLDAP=%d ldap-go=%d, want %d",
					referenceCode,
					goCode,
					test.want,
				)
			}
		})
	}
}

func TestOpenLDAPReferenceLloaddMonitorDataListenerDifference(t *testing.T) {
	requirePinnedOpenLDAPLloaddSource(t)
	configText := `
sockbuf_max_incoming_client 4194303
sockbuf_max_incoming_upstream 4194303
`
	referenceAddress := startOpenLDAPReferenceLloadd(t, configText)
	_, goAddress := startRuntimeProxy(t, RuntimeConfig{})

	referenceEntries, referenceCode := searchLloaddMonitorBase(t, referenceAddress)
	if referenceCode != ldap.LDAPResultUnavailable || len(referenceEntries) != 0 {
		t.Fatalf(
			"OpenLDAP standalone lloadd monitor data listener = entries %d code %d, want 0/%d",
			len(referenceEntries),
			referenceCode,
			ldap.LDAPResultUnavailable,
		)
	}
	goEntries, goCode := searchLloaddMonitorBase(t, goAddress)
	if goCode != ldap.LDAPResultSuccess || len(goEntries) != 1 ||
		goEntries[0].DN != MonitorLoadBalancerDN {
		t.Fatalf(
			"ldap-go lloadd monitor data listener = %#v code %d",
			goEntries,
			goCode,
		)
	}
}

func TestOpenLDAPReferenceLloaddBindProxyAuthzDifferential(t *testing.T) {
	requirePinnedOpenLDAPLloaddSource(t)
	authz := make(chan string, 4)
	provider := startProxyTestUpstream(t, "oracle", func(_ net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagSearchRequest {
			return false
		}
		value := "missing"
		if len(frame.Controls) > 0 && frame.Controls[0].OID == ProxyAuthzControlOID {
			switch {
			case bytes.Contains(frame.Controls[0].Raw, []byte("dn:uid=alice,dc=example,dc=com")):
				value = "alice"
			default:
				value = "wrong"
			}
		}
		authz <- value
		return false
	})
	configText := fmt.Sprintf(`
sockbuf_max_incoming_client 4194303
sockbuf_max_incoming_upstream 4194303
feature proxyauthz
bindconf bindmethod=simple binddn="cn=Manager,dc=example,dc=com" credentials=secret
tier roundrobin
backend-server uri=ldap://%s numconns=1 bindconns=1 retry=50 max-pending-ops=20 conn-max-pending=3
`, provider.listener.Addr())
	referenceAddress := startOpenLDAPReferenceLloadd(t, configText)
	config, err := ParseReader("lloadd-bind.conf", strings.NewReader(configText))
	if err != nil {
		t.Fatalf("ParseReader(): %v", err)
	}
	runtime, err := config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(): %v", err)
	}
	proxy, goAddress := startRuntimeProxy(t, runtime)
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	waitForReadyConnections(t, proxy, PoolBind, 1)

	for name, address := range map[string]string{
		"OpenLDAP": referenceAddress,
		"ldap-go":  goAddress,
	} {
		t.Run(name, func(t *testing.T) {
			marker, err := retryBindSearch(address, 5*time.Second)
			if err != nil {
				t.Fatalf(
					"Bind/Search through %s: %v (provider read: %v)",
					name,
					err,
					provider.readError(),
				)
			}
			if marker != "oracle" {
				t.Fatalf("Search marker through %s = %q", name, marker)
			}
		})
	}
	for index := 0; index < 2; index++ {
		select {
		case got := <-authz:
			if got != "alice" {
				t.Fatalf("forwarded ProxyAuthz identity %d = %q", index, got)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("missing forwarded Search %d", index)
		}
	}
}

type openLDAPLloaddProcess struct {
	command *exec.Cmd
	logs    bytes.Buffer
	done    chan struct{}
	waitErr error
}

func (process *openLDAPLloaddProcess) start() error {
	if err := process.command.Start(); err != nil {
		return err
	}
	go func() {
		process.waitErr = process.command.Wait()
		close(process.done)
	}()
	return nil
}

func (process *openLDAPLloaddProcess) wait(timeout time.Duration) (error, bool) {
	if timeout <= 0 {
		select {
		case <-process.done:
			return process.waitErr, true
		default:
			return nil, false
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-process.done:
		return process.waitErr, true
	case <-timer.C:
		return nil, false
	}
}

func (process *openLDAPLloaddProcess) stop(gracePeriod, killTimeout time.Duration) (error, bool, bool) {
	if err, exited := process.wait(0); exited {
		return err, false, true
	}
	if process.command.Process != nil {
		_ = process.command.Process.Signal(syscall.SIGTERM)
	}
	if err, exited := process.wait(gracePeriod); exited {
		return err, false, true
	}
	if process.command.Process != nil {
		_ = process.command.Process.Kill()
	}
	err, exited := process.wait(killTimeout)
	return err, true, exited
}

func startOpenLDAPReferenceLloadd(t *testing.T, configText string) string {
	t.Helper()
	binary := os.Getenv("OPENLDAP_LLOADD")
	if binary == "" {
		t.Fatal("OPENLDAP_LLOADD is required for lloadd runtime differentials")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve OpenLDAP lloadd address: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	configPath := filepath.Join(t.TempDir(), "lloadd.conf")
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatalf("write OpenLDAP lloadd config: %v", err)
	}
	process := &openLDAPLloaddProcess{done: make(chan struct{})}
	debugLevel := os.Getenv("LDAP_GO_OPENLDAP_LLOADD_DEBUG")
	if debugLevel == "" {
		debugLevel = "0"
	}
	process.command = exec.Command(
		binary,
		"-f", configPath,
		"-h", "ldap://"+address+"/",
		"-d", debugLevel,
	)
	process.command.Stdout = &process.logs
	process.command.Stderr = &process.logs
	if err := process.start(); err != nil {
		t.Fatalf("start OpenLDAP lloadd: %v", err)
	}
	t.Cleanup(func() {
		err, forceKilled, exited := process.stop(5*time.Second, 5*time.Second)
		if !exited {
			t.Error("OpenLDAP lloadd did not exit after SIGKILL")
			return
		}
		if forceKilled {
			t.Error("OpenLDAP lloadd did not stop after SIGTERM")
		}
		if t.Failed() && process.logs.Len() != 0 {
			t.Logf("OpenLDAP lloadd logs:\n%s", process.logs.String())
		} else if err != nil && !strings.Contains(err.Error(), "signal") {
			t.Logf("OpenLDAP lloadd exit: %v\n%s", err, process.logs.String())
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return address
		}
		select {
		case <-process.done:
			t.Fatalf("OpenLDAP lloadd exited before listening: %v\n%s", process.waitErr, process.logs.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("OpenLDAP lloadd did not listen on %s", address)
	return ""
}

func TestOpenLDAPLloaddProcessExitCanBeObservedRepeatedly(t *testing.T) {
	process, _ := startOpenLDAPLloaddProcessHelper(t, "exit")
	for observation := 0; observation < 3; observation++ {
		err, exited := process.wait(2 * time.Second)
		if !exited {
			t.Fatalf("observation %d timed out", observation)
		}
		if err != nil {
			t.Fatalf("observation %d exit error: %v", observation, err)
		}
	}
	if err, forceKilled, exited := process.stop(time.Second, time.Second); err != nil || forceKilled || !exited {
		t.Fatalf("stop after observed exit = (%v, %t, %t), want (nil, false, true)", err, forceKilled, exited)
	}
}

func TestOpenLDAPLloaddProcessStop(t *testing.T) {
	for _, test := range []struct {
		name            string
		mode            string
		gracePeriod     time.Duration
		wantForceKilled bool
	}{
		{name: "graceful", mode: "graceful", gracePeriod: 2 * time.Second},
		{name: "forced", mode: "ignore-term", gracePeriod: 50 * time.Millisecond, wantForceKilled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			process, readyPath := startOpenLDAPLloaddProcessHelper(t, test.mode)
			waitForOpenLDAPLloaddProcessHelper(t, process, readyPath)
			waitErr, forceKilled, exited := process.stop(test.gracePeriod, 2*time.Second)
			if !exited {
				t.Fatal("helper process was not reaped")
			}
			if forceKilled != test.wantForceKilled {
				t.Fatalf("forceKilled = %t, want %t (wait error: %v)", forceKilled, test.wantForceKilled, waitErr)
			}
			if !forceKilled && waitErr != nil {
				t.Fatalf("graceful stop error: %v", waitErr)
			}
			for observation := 0; observation < 2; observation++ {
				gotErr, gotExited := process.wait(0)
				if !gotExited || fmt.Sprint(gotErr) != fmt.Sprint(waitErr) {
					t.Fatalf(
						"observation %d = (%v, %t), want (%v, true)",
						observation,
						gotErr,
						gotExited,
						waitErr,
					)
				}
			}
		})
	}
}

func TestOpenLDAPLloaddProcessHelper(t *testing.T) {
	mode := os.Getenv("LDAP_GO_LLOADD_PROCESS_HELPER")
	if mode == "" {
		return
	}
	if mode == "exit" {
		return
	}
	readyPath := os.Getenv("LDAP_GO_LLOADD_PROCESS_READY")
	switch mode {
	case "graceful":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		defer signal.Stop(signals)
		if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
			t.Fatalf("write ready marker: %v", err)
		}
		<-signals
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
			t.Fatalf("write ready marker: %v", err)
		}
		for {
			time.Sleep(time.Hour)
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

func startOpenLDAPLloaddProcessHelper(t *testing.T, mode string) (*openLDAPLloaddProcess, string) {
	t.Helper()
	readyPath := filepath.Join(t.TempDir(), "ready")
	process := &openLDAPLloaddProcess{
		command: exec.Command(os.Args[0], "-test.run=^TestOpenLDAPLloaddProcessHelper$"),
		done:    make(chan struct{}),
	}
	process.command.Env = append(
		os.Environ(),
		"LDAP_GO_LLOADD_PROCESS_HELPER="+mode,
		"LDAP_GO_LLOADD_PROCESS_READY="+readyPath,
	)
	process.command.Stdout = &process.logs
	process.command.Stderr = &process.logs
	if err := process.start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}
	t.Cleanup(func() {
		if _, exited := process.wait(0); exited {
			return
		}
		if process.command.Process != nil {
			_ = process.command.Process.Kill()
		}
		if _, exited := process.wait(2 * time.Second); !exited {
			t.Error("helper process was not reaped during cleanup")
		}
	})
	return process, readyPath
}

func waitForOpenLDAPLloaddProcessHelper(
	t *testing.T,
	process *openLDAPLloaddProcess,
	readyPath string,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(readyPath); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat helper ready marker: %v", err)
		}
		if waitErr, exited := process.wait(0); exited {
			t.Fatalf("helper exited before ready: %v\n%s", waitErr, process.logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("helper process did not become ready")
}

func searchLDAPResultCode(t *testing.T, address string, controls []ldap.Control) uint16 {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	defer client.Close()
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		controls,
	))
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("Search(%s) = %v, want LDAP error", address, err)
	}
	return ldapErr.ResultCode
}

func searchLloaddMonitorBase(t *testing.T, address string) ([]*ldap.Entry, uint16) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		MonitorLoadBalancerDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	))
	if err == nil {
		return result.Entries, ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("Search(%s) = %v, want LDAP result", address, err)
	}
	return nil, ldapErr.ResultCode
}

func retryBindSearch(address string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := ldap.DialURL("ldap://" + address)
		if err == nil {
			err = client.Bind("uid=alice,dc=example,dc=com", "password")
			if err == nil {
				var marker string
				marker, err = proxySearchMarkerResult(client)
				client.Close()
				if err == nil {
					return marker, nil
				}
			} else {
				client.Close()
			}
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	return "", lastErr
}
