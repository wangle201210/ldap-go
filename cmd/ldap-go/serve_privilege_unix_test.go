//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	servePrivilegeChildEnvironment  = "LDAP_GO_TEST_PRIVILEGE_CHILD"
	servePrivilegeUserEnvironment   = "LDAP_GO_TEST_PRIVILEGE_USER"
	servePrivilegeGroupEnvironment  = "LDAP_GO_TEST_PRIVILEGE_GROUP"
	servePrivilegeChrootEnvironment = "LDAP_GO_TEST_PRIVILEGE_CHROOT"
)

func TestResolveServePrivileges(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	primary, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	jail := t.TempDir()
	for _, test := range []struct {
		name  string
		user  string
		group string
	}{
		{name: "names", user: current.Username, group: primary.Name},
		{name: "numeric", user: current.Uid, group: current.Gid},
		{name: "user primary group", user: current.Username},
		{name: "group only", group: primary.Name},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration, err := resolveServePrivileges(test.user, test.group, jail)
			if err != nil {
				t.Fatal(err)
			}
			defer configuration.Close()
			identity, err := resolveServeIdentity(test.user, test.group)
			if err != nil {
				t.Fatal(err)
			}
			wantUID, _ := strconv.Atoi(current.Uid)
			wantGID, _ := strconv.Atoi(current.Gid)
			if test.user != "" && (!identity.setUID || identity.uid != wantUID) {
				t.Fatalf("resolved uid = %d, set=%t", identity.uid, identity.setUID)
			}
			if !identity.setGID || identity.gid != wantGID ||
				configuration.chroot == "" {
				t.Fatalf("resolved privileges = %#v, %#v", configuration, identity)
			}
		})
	}
	for _, test := range []struct {
		user, group, chroot string
	}{
		{user: "ldap-go-user-that-does-not-exist"},
		{group: "ldap-go-group-that-does-not-exist"},
		{chroot: "relative"},
		{chroot: filepath.Join(t.TempDir(), "missing")},
	} {
		configuration, err := resolveServePrivileges(test.user, test.group, test.chroot)
		if err == nil {
			_ = configuration.Close()
			if test.user != "" || test.group != "" {
				_, err = resolveServeIdentity(test.user, test.group)
			}
		}
		if err == nil {
			t.Fatalf("invalid privileges were accepted: %#v", test)
		}
	}
}

func TestApplyServePrivilegesSubprocess(t *testing.T) {
	if os.Getenv(servePrivilegeChildEnvironment) == "identity" {
		startedAsRoot := os.Geteuid() == 0
		configuration, err := resolveServePrivileges(
			os.Getenv(servePrivilegeUserEnvironment),
			os.Getenv(servePrivilegeGroupEnvironment),
			"",
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyServePrivileges(configuration); err != nil {
			t.Fatal(err)
		}
		if startedAsRoot && os.Geteuid() != 0 {
			if err := syscall.Setuid(0); err == nil {
				t.Fatal("dropped process recovered uid 0")
			}
		}
		fmt.Printf("identity=%d:%d\n", os.Geteuid(), os.Getegid())
		return
	}

	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	target := current
	if os.Geteuid() == 0 {
		if nobody, lookupErr := user.Lookup("nobody"); lookupErr == nil {
			target = nobody
		}
	}
	command := exec.Command(os.Args[0], "-test.run=^TestApplyServePrivilegesSubprocess$")
	command.Env = append(
		cleanPrivilegeTestEnvironment(os.Environ()),
		servePrivilegeChildEnvironment+"=identity",
		servePrivilegeUserEnvironment+"="+target.Uid,
		servePrivilegeGroupEnvironment+"="+target.Gid,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("privilege child: %v\n%s", err, output)
	}
	want := "identity=" + target.Uid + ":" + target.Gid
	if !bytes.Contains(output, []byte(want)) {
		t.Fatalf("privilege child output = %q, want %q", output, want)
	}
}

func TestApplyServeChrootSubprocess(t *testing.T) {
	if os.Getenv(servePrivilegeChildEnvironment) == "chroot" {
		configuration, err := resolveServePrivileges(
			"",
			"",
			os.Getenv(servePrivilegeChrootEnvironment),
		)
		if err != nil {
			t.Fatal(err)
		}
		err = applyServePrivileges(configuration)
		if os.Geteuid() != 0 {
			if err == nil || !strings.Contains(err.Error(), "requires root") {
				t.Fatalf("non-root chroot error = %v", err)
			}
			fmt.Println("chroot=denied")
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		working, err := os.Getwd()
		if err != nil || working != "/" {
			t.Fatalf("chroot working directory = %q, %v", working, err)
		}
		if contents, err := os.ReadFile("/inside"); err != nil || string(contents) != "inside" {
			t.Fatalf("chroot marker = %q, %v", contents, err)
		}
		fmt.Println("chroot=entered")
		return
	}

	jail := t.TempDir()
	if err := os.WriteFile(filepath.Join(jail, "inside"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestApplyServeChrootSubprocess$")
	command.Env = append(
		cleanPrivilegeTestEnvironment(os.Environ()),
		servePrivilegeChildEnvironment+"=chroot",
		servePrivilegeChrootEnvironment+"="+jail,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("chroot child: %v\n%s", err, output)
	}
	want := "chroot=denied"
	if os.Geteuid() == 0 {
		want = "chroot=entered"
	}
	if !bytes.Contains(output, []byte(want)) {
		t.Fatalf("chroot child output = %q, want %q", output, want)
	}
}

func TestOpenLDAPPrivilegeOrderSourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	mainSource, err := os.ReadFile(filepath.Join(source, "servers", "slapd", "main.c"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(mainSource)
	positions := []int{
		strings.Index(text, "slapd_daemon_init( urls )"),
		strings.Index(text, "chroot( sandbox )"),
		strings.Index(text, "slap_init_user( username, groupname )"),
		strings.Index(text, "read_config( configfile, configdir )"),
	}
	for index, position := range positions {
		if position < 0 || index > 0 && position <= positions[index-1] {
			t.Fatalf("OpenLDAP privilege order anchors = %v", positions)
		}
	}
}

func TestServePrivilegeFlagValidation(t *testing.T) {
	jail := t.TempDir()
	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"-user", "nobody", "-u", "nobody"}, want: "aliases and cannot both be set"},
		{args: []string{"-group", "nobody", "-g", "nobody"}, want: "aliases and cannot both be set"},
		{args: []string{"-chroot", jail, "-r", jail}, want: "aliases and cannot both be set"},
		{args: []string{"-chroot", "relative"}, want: "absolute directory"},
		{args: []string{"-user", "ldap-go-user-that-does-not-exist", "-listen", "127.0.0.1:0"}, want: "resolve serve user"},
		{args: []string{"-chroot", jail, "-ldapi", filepath.Join(jail, "ldapi")}, want: "requires -systemd-activation"},
	} {
		args := append([]string{"serve"}, test.args...)
		var stdout, stderr bytes.Buffer
		exitCode := run(args, strings.NewReader(""), &stdout, &stderr, func(string) string { return "" })
		if exitCode != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.want) {
			t.Fatalf("serve privilege validation %q: exit=%d stdout=%q stderr=%q", test.args, exitCode, stdout.String(), stderr.String())
		}
	}
}

func cleanPrivilegeTestEnvironment(environment []string) []string {
	result := make([]string, 0, len(environment))
	for _, value := range environment {
		if strings.HasPrefix(value, servePrivilegeChildEnvironment+"=") ||
			strings.HasPrefix(value, servePrivilegeUserEnvironment+"=") ||
			strings.HasPrefix(value, servePrivilegeGroupEnvironment+"=") ||
			strings.HasPrefix(value, servePrivilegeChrootEnvironment+"=") {
			continue
		}
		result = append(result, value)
	}
	return result
}
