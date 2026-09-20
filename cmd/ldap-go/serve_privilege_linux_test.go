package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestApplyServePrivilegesAllThreads(t *testing.T) {
	if os.Getenv(servePrivilegeChildEnvironment) == "threads" {
		testServePrivilegesAllThreadsChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to verify permanent privilege dropping")
	}
	target, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	if target.Uid == "0" || target.Gid == "0" {
		t.Fatal("privilege test requires an unprivileged nobody account")
	}
	for _, name := range []string{"user", "group only", "chroot user and group"} {
		t.Run(name, func(t *testing.T) {
			userSpec, groupSpec, jail := target.Uid, "", ""
			if name == "group only" {
				userSpec, groupSpec = "", target.Gid
			}
			if name == "chroot user and group" {
				jail = t.TempDir()
				if err := os.Chmod(jail, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(jail, "etc"), 0o755); err != nil {
					t.Fatal(err)
				}
				for file, contents := range map[string]string{
					"passwd": "jailed:x:" + target.Uid + ":" + target.Gid + ":Test:/:/bin/false\n",
					"group":  "primary:x:" + target.Gid + ":\noverride:x:12345:\nextra:x:12346:jailed\n",
				} {
					if err := os.WriteFile(filepath.Join(jail, "etc", file), []byte(contents), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				userSpec, groupSpec = "jailed", "override"
			}
			command := exec.Command(os.Args[0], "-test.run=^TestApplyServePrivilegesAllThreads$", "-test.v", "-test.timeout=30s")
			command.WaitDelay = 5 * time.Second
			command.Env = append(cleanPrivilegeTestEnvironment(os.Environ()),
				servePrivilegeChildEnvironment+"=threads",
				servePrivilegeUserEnvironment+"="+userSpec,
				servePrivilegeGroupEnvironment+"="+groupSpec,
				servePrivilegeChrootEnvironment+"="+jail,
			)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("privilege child: %v\n%s", err, output)
			}
			t.Logf("%s", output)
		})
	}
}

func testServePrivilegesAllThreadsChild(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("privilege child must start as root")
	}
	threads := pinServePrivilegeThreads(t, 8)
	// Keep access to every task's status across chroot; the jail has no /proc.
	tasks, err := os.OpenRoot("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	defer tasks.Close()
	initialGroups, err := syscall.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv(servePrivilegeChrootEnvironment) == "" {
		if err := serveSetgroups(nil); err != nil {
			t.Fatal(err)
		}
		checkServeThreadCredentials(t, tasks, threads, 0, os.Getgid(), nil)
		initialGroups = []int{0}
		if err := serveSetgroups(initialGroups); err != nil {
			t.Fatal(err)
		}
	}
	configuration, err := resolveServePrivileges(
		os.Getenv(servePrivilegeUserEnvironment),
		os.Getenv(servePrivilegeGroupEnvironment),
		os.Getenv(servePrivilegeChrootEnvironment),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer configuration.Close()
	if err := applyServePrivileges(configuration); err != nil {
		t.Fatal(err)
	}
	identity, err := resolveServeIdentity(configuration.userSpec, configuration.groupSpec)
	if err != nil {
		t.Fatal(err)
	}
	wantUID, wantGroups := 0, initialGroups
	if identity.setUID {
		wantUID, wantGroups = identity.uid, identity.groups
	}
	before := checkServeThreadCredentials(t, tasks, threads, wantUID, identity.gid, wantGroups)
	// More pinned workers than existing tasks force creation of new OS threads.
	newThreads := pinServePrivilegeThreads(t, len(before)+1)
	created := false
	for _, thread := range newThreads {
		if !before[thread] {
			created = true
		}
	}
	if !created {
		t.Fatal("no OS thread was created after dropping privileges")
	}
	threads = append(threads, newThreads...)
	checkServeThreadCredentials(t, tasks, threads, wantUID, identity.gid, wantGroups)
	if identity.setUID {
		for _, operation := range []struct {
			name string
			call func() error
		}{
			{"setuid", func() error { return serveSetuid(0) }},
			{"setgid", func() error { return serveSetgid(0) }},
			{"setgroups", func() error { return serveSetgroups([]int{0}) }},
		} {
			if err := operation.call(); !errors.Is(err, syscall.EPERM) {
				t.Fatalf("restore root via %s: got %v, want EPERM", operation.name, err)
			}
		}
		checkServeThreadCredentials(t, tasks, threads, wantUID, identity.gid, wantGroups)
	}
}

func pinServePrivilegeThreads(t *testing.T, count int) []int {
	t.Helper()
	ready, release := make(chan int, count), make(chan struct{})
	var workers sync.WaitGroup
	for range count {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- syscall.Gettid()
			<-release
		}()
	}
	t.Cleanup(func() {
		close(release)
		workers.Wait()
	})
	threads := make([]int, count)
	for index := range threads {
		threads[index] = <-ready
	}
	return threads
}

func checkServeThreadCredentials(t *testing.T, tasks *os.Root, pinned []int, uid, gid int, groups []int) map[int]bool {
	t.Helper()
	directory, err := tasks.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		t.Fatal(err)
	}
	wantGroups := make([]string, len(groups))
	for index, group := range groups {
		wantGroups[index] = strconv.Itoa(group)
	}
	slices.Sort(wantGroups)
	want := map[string][]string{
		"Uid:":    {strconv.Itoa(uid), strconv.Itoa(uid), strconv.Itoa(uid), strconv.Itoa(uid)},
		"Gid:":    {strconv.Itoa(gid), strconv.Itoa(gid), strconv.Itoa(gid), strconv.Itoa(gid)},
		"Groups:": wantGroups,
	}
	checked := make(map[int]bool)
	for _, entry := range entries {
		thread, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		status, err := tasks.ReadFile(filepath.Join(entry.Name(), "status"))
		if errors.Is(err, os.ErrNotExist) {
			continue // An unpinned runtime thread may have exited.
		}
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for line := range strings.SplitSeq(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			expected, ok := want[fields[0]]
			if !ok {
				continue
			}
			actual := fields[1:]
			if fields[0] == "Groups:" {
				slices.Sort(actual)
			}
			if !slices.Equal(actual, expected) {
				t.Fatalf("thread %d %s = %v, want %v", thread, fields[0], actual, expected)
			}
			found++
		}
		if found != len(want) {
			t.Fatalf("thread %d: incomplete credential status\n%s", thread, status)
		}
		checked[thread] = true
	}
	for _, thread := range append(slices.Clone(pinned), os.Getpid()) {
		if !checked[thread] {
			t.Fatalf("thread %d was not checked", thread)
		}
	}
	fmt.Printf("checked %d OS threads: uid=%d gid=%d groups=%v\n", len(checked), uid, gid, groups)
	return checked
}
