package server

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceHomedirOverlay(t *testing.T) {
	tools := requireOpenLDAPHomedirReferenceTools(t)
	checkOwnership := homedirCanChangeOwnership()
	if !checkOwnership {
		t.Log("ownership transition assertion skipped: changing UID/GID requires root")
	}

	for _, deleteStyle := range []string{"DELETE", "ARCHIVE"} {
		t.Run(strings.ToLower(deleteStyle), func(t *testing.T) {
			openLDAPFixture := newHomedirReferenceFixture(t)
			openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				nil,
				"include "+filepath.Join(tools.schemaDir, "nis.schema"),
				openLDAPHomedirReferenceConfiguration(
					openLDAPFixture,
					deleteStyle,
				),
				"",
			)
			defer stopOpenLDAP()

			ldapGoFixture := newHomedirReferenceFixture(t)
			ldapGoURI, stopLDAPGo := startLDAPGoHomedirReferenceServer(
				t,
				ldapGoFixture,
				deleteStyle,
			)
			defer stopLDAPGo()

			openLDAPOutcome := runHomedirReferenceScenario(
				t,
				openLDAPURI,
				"secret",
				openLDAPFixture,
				deleteStyle,
				checkOwnership,
			)
			assertHomedirReferenceOutcome(
				t,
				"OpenLDAP",
				openLDAPOutcome,
				deleteStyle,
				checkOwnership,
			)

			ldapGoOutcome := runHomedirReferenceScenario(
				t,
				ldapGoURI,
				"admin-secret",
				ldapGoFixture,
				deleteStyle,
				checkOwnership,
			)
			assertHomedirReferenceOutcome(
				t,
				"ldap-go",
				ldapGoOutcome,
				deleteStyle,
				checkOwnership,
			)

			if ldapGoOutcome != openLDAPOutcome {
				t.Fatalf(
					"ldap-go homedir %s outcome = %#v, want OpenLDAP %#v",
					deleteStyle,
					ldapGoOutcome,
					openLDAPOutcome,
				)
			}
		})
	}
}

func requireOpenLDAPHomedirReferenceTools(
	t *testing.T,
) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if len(output) == 0 {
		t.Skipf("inspect OpenLDAP overlays: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "homedir") {
			if _, err := os.Stat(filepath.Join(tools.schemaDir, "nis.schema")); err != nil {
				t.Skipf("OpenLDAP nis.schema required by the homedir fixture was not found: %v", err)
			}
			return tools
		}
	}
	t.Skip(
		"the selected OpenLDAP slapd was not built with the homedir overlay " +
			"(configure OpenLDAP with --enable-homedir=yes)",
	)
	return openLDAPReferenceTools{}
}

type homedirReferenceFixture struct {
	skeleton string
	homes    string
	archive  string
}

func newHomedirReferenceFixture(t *testing.T) homedirReferenceFixture {
	t.Helper()
	root := t.TempDir()
	fixture := homedirReferenceFixture{
		skeleton: filepath.Join(root, "skeleton"),
		homes:    filepath.Join(root, "homes"),
		archive:  filepath.Join(root, "archive"),
	}
	for _, path := range []string{
		fixture.skeleton,
		fixture.homes,
		fixture.archive,
	} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("Mkdir(%q): %v", path, err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(fixture.skeleton, "welcome.txt"),
		[]byte("welcome\n"),
		0o640,
	); err != nil {
		t.Fatalf("write homedir skeleton marker: %v", err)
	}
	if err := os.Mkdir(filepath.Join(fixture.skeleton, "profile"), 0o750); err != nil {
		t.Fatalf("create homedir skeleton directory: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(fixture.skeleton, "profile", "settings"),
		[]byte("enabled"),
		0o600,
	); err != nil {
		t.Fatalf("write nested homedir skeleton marker: %v", err)
	}
	if err := os.Symlink(
		"welcome.txt",
		filepath.Join(fixture.skeleton, "welcome-link"),
	); err != nil {
		t.Fatalf("create homedir skeleton symlink: %v", err)
	}
	return fixture
}

func openLDAPHomedirReferenceConfiguration(
	fixture homedirReferenceFixture,
	deleteStyle string,
) string {
	return fmt.Sprintf(
		"overlay homedir\n"+
			"homedir-skeleton-path %s\n"+
			"homedir-min-uidnumber 0\n"+
			"homedir-regexp %s %s\n"+
			"homedir-delete-style %s\n"+
			"homedir-archive-path %s",
		strconv.Quote(fixture.skeleton),
		strconv.Quote(`^/legacy/([^/]+)$`),
		strconv.Quote(filepath.Join(fixture.homes, "$1")),
		deleteStyle,
		strconv.Quote(fixture.archive),
	)
}

func startLDAPGoHomedirReferenceServer(
	t *testing.T,
	fixture homedirReferenceFixture,
	deleteStyle string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedHomedirOverlay(t, store, homedirOverlayEntry(
		fixture.skeleton,
		fixture.homes,
		fixture.archive,
		deleteStyle,
	))
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	return "ldap://" + address, stop
}

type homedirReferenceOutcome struct {
	addCode          uint16
	modifyCode       uint16
	deleteCode       uint16
	addedTree        homedirReferenceTree
	oldHomeRemoved   bool
	renamedTree      homedirReferenceTree
	ownership        homedirReferenceOwnership
	finalHomeRemoved bool
	archive          homedirReferenceArchive
}

type homedirReferenceTree struct {
	welcome     string
	welcomeMode uint32
	settings    string
	linkTarget  string
}

type homedirReferenceOwnership struct {
	checked   bool
	rootUID   uint32
	rootGID   uint32
	markerUID uint32
	markerGID uint32
}

type homedirReferenceArchive struct {
	count          int
	mode           uint32
	welcomeFound   bool
	welcomeContent string
}

const (
	homedirReferenceChangedUID = uint32(42421)
	homedirReferenceChangedGID = uint32(42422)
)

func runHomedirReferenceScenario(
	t *testing.T,
	uri,
	password string,
	fixture homedirReferenceFixture,
	deleteStyle string,
	checkOwnership bool,
) homedirReferenceOutcome {
	t.Helper()
	client := bindOverlayReferenceClient(t, uri, password)
	defer client.Close()

	name := strings.ToLower(deleteStyle)
	dn := "uid=homedir-" + name + ",ou=people,dc=example,dc=com"
	oldLogicalHome := "/legacy/" + name + "-old"
	newLogicalHome := "/legacy/" + name + "-new"
	oldHome := filepath.Join(fixture.homes, name+"-old")
	newHome := filepath.Join(fixture.homes, name+"-new")

	outcome := homedirReferenceOutcome{}
	outcome.addCode = overlayLDAPResultCode(t, client.Add(
		homedirAccountAddRequest(dn, "homedir-"+name, oldLogicalHome),
	))
	if outcome.addCode != ldap.LDAPResultSuccess {
		return outcome
	}
	outcome.addedTree = readHomedirReferenceTree(t, oldHome)

	modify := ldap.NewModifyRequest(dn, nil)
	modify.Replace("homeDirectory", []string{newLogicalHome})
	if checkOwnership {
		modify.Replace("uidNumber", []string{strconv.FormatUint(
			uint64(homedirReferenceChangedUID),
			10,
		)})
		modify.Replace("gidNumber", []string{strconv.FormatUint(
			uint64(homedirReferenceChangedGID),
			10,
		)})
	}
	outcome.modifyCode = overlayLDAPResultCode(t, client.Modify(modify))
	if outcome.modifyCode != ldap.LDAPResultSuccess {
		return outcome
	}
	outcome.oldHomeRemoved = homedirReferencePathMissing(t, oldHome)
	outcome.renamedTree = readHomedirReferenceTree(t, newHome)
	if checkOwnership {
		outcome.ownership = readHomedirReferenceOwnership(t, newHome)
	}

	outcome.deleteCode = overlayLDAPResultCode(
		t,
		client.Del(ldap.NewDelRequest(dn, nil)),
	)
	if outcome.deleteCode != ldap.LDAPResultSuccess {
		return outcome
	}
	outcome.finalHomeRemoved = homedirReferencePathMissing(t, newHome)
	outcome.archive = readHomedirReferenceArchive(
		t,
		fixture.archive,
		name+"-new-",
	)
	return outcome
}

func readHomedirReferenceTree(t *testing.T, home string) homedirReferenceTree {
	t.Helper()
	welcomePath := filepath.Join(home, "welcome.txt")
	welcome, err := os.ReadFile(welcomePath)
	if err != nil {
		t.Fatalf("read provisioned skeleton marker %q: %v", welcomePath, err)
	}
	welcomeInfo, err := os.Stat(welcomePath)
	if err != nil {
		t.Fatalf("stat provisioned skeleton marker %q: %v", welcomePath, err)
	}
	settingsPath := filepath.Join(home, "profile", "settings")
	settings, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read nested skeleton marker %q: %v", settingsPath, err)
	}
	linkPath := filepath.Join(home, "welcome-link")
	linkTarget, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("read provisioned skeleton symlink %q: %v", linkPath, err)
	}
	return homedirReferenceTree{
		welcome:     string(welcome),
		welcomeMode: uint32(welcomeInfo.Mode().Perm()),
		settings:    string(settings),
		linkTarget:  linkTarget,
	}
}

func homedirReferencePathMissing(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	t.Fatalf("Lstat(%q): %v", path, err)
	return false
}

func readHomedirReferenceOwnership(
	t *testing.T,
	home string,
) homedirReferenceOwnership {
	t.Helper()
	rootUID, rootGID := homedirReferencePathOwnership(t, home)
	markerUID, markerGID := homedirReferencePathOwnership(
		t,
		filepath.Join(home, "welcome.txt"),
	)
	return homedirReferenceOwnership{
		checked:   true,
		rootUID:   rootUID,
		rootGID:   rootGID,
		markerUID: markerUID,
		markerGID: markerGID,
	}
}

func homedirReferencePathOwnership(
	t *testing.T,
	path string,
) (uint32, uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", path, err)
	}
	uid, gid, ok := homedirFileOwnership(info)
	if !ok {
		t.Fatalf("ownership information is unavailable for %q", path)
	}
	return uint32(uid), uint32(gid)
}

func readHomedirReferenceArchive(
	t *testing.T,
	archiveDirectory,
	prefix string,
) homedirReferenceArchive {
	t.Helper()
	entries, err := os.ReadDir(archiveDirectory)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", archiveDirectory, err)
	}
	result := homedirReferenceArchive{}
	var archivePath string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) ||
			!strings.HasSuffix(entry.Name(), ".tar") {
			continue
		}
		result.count++
		archivePath = filepath.Join(archiveDirectory, entry.Name())
	}
	if result.count == 0 {
		return result
	}
	if result.count != 1 {
		t.Fatalf("archive files with prefix %q = %d, want at most one", prefix, result.count)
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatalf("Stat(%q): %v", archivePath, err)
	}
	result.mode = uint32(info.Mode().Perm())

	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("Open(%q): %v", archivePath, err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read archive %q: %v", archivePath, err)
		}
		if !strings.HasSuffix(
			filepath.ToSlash(header.Name),
			prefix[:len(prefix)-1]+"/welcome.txt",
		) {
			continue
		}
		contents, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read welcome.txt from archive %q: %v", archivePath, err)
		}
		result.welcomeFound = true
		result.welcomeContent = string(contents)
		break
	}
	return result
}

func assertHomedirReferenceOutcome(
	t *testing.T,
	serverName string,
	outcome homedirReferenceOutcome,
	deleteStyle string,
	checkOwnership bool,
) {
	t.Helper()
	for operation, code := range map[string]uint16{
		"Add":    outcome.addCode,
		"Modify": outcome.modifyCode,
		"Delete": outcome.deleteCode,
	} {
		if code != ldap.LDAPResultSuccess {
			t.Errorf(
				"%s homedir %s %s result = %d, want success",
				serverName,
				deleteStyle,
				operation,
				code,
			)
		}
	}
	wantTree := homedirReferenceTree{
		welcome:     "welcome\n",
		welcomeMode: 0o640,
		settings:    "enabled",
		linkTarget:  "welcome.txt",
	}
	if outcome.addedTree != wantTree {
		t.Errorf(
			"%s homedir %s tree after Add = %#v, want %#v",
			serverName,
			deleteStyle,
			outcome.addedTree,
			wantTree,
		)
	}
	if !outcome.oldHomeRemoved || outcome.renamedTree != wantTree {
		t.Errorf(
			"%s homedir %s rename result: old removed=%t tree=%#v, want true and %#v",
			serverName,
			deleteStyle,
			outcome.oldHomeRemoved,
			outcome.renamedTree,
			wantTree,
		)
	}
	if checkOwnership {
		wantOwnership := homedirReferenceOwnership{
			checked:   true,
			rootUID:   homedirReferenceChangedUID,
			rootGID:   homedirReferenceChangedGID,
			markerUID: homedirReferenceChangedUID,
			markerGID: homedirReferenceChangedGID,
		}
		if outcome.ownership != wantOwnership {
			t.Errorf(
				"%s homedir %s ownership after Modify = %#v, want %#v",
				serverName,
				deleteStyle,
				outcome.ownership,
				wantOwnership,
			)
		}
	}
	if !outcome.finalHomeRemoved {
		t.Errorf(
			"%s homedir %s source home still exists after Delete",
			serverName,
			deleteStyle,
		)
	}
	wantArchive := homedirReferenceArchive{}
	if deleteStyle == "ARCHIVE" {
		wantArchive = homedirReferenceArchive{
			count:          1,
			mode:           0o600,
			welcomeFound:   true,
			welcomeContent: "welcome\n",
		}
	}
	if outcome.archive != wantArchive {
		t.Errorf(
			"%s homedir %s archive = %#v, want %#v",
			serverName,
			deleteStyle,
			outcome.archive,
			wantArchive,
		)
	}
}
