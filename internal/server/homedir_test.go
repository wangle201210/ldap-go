package server

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const testHomedirOverlayDN = "olcOverlay={0}homedir,olcDatabase={1}mdb,cn=config"

func TestLoadHomedirRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	skeleton := filepath.Join(root, "skel")
	archive := filepath.Join(root, "archive")
	homes := filepath.Join(root, "homes")
	entry := homedirOverlayEntry(
		skeleton,
		homes,
		archive,
		"ARCHIVE",
	)
	entry.ReplaceValues("olcHomedirRegexp", stringValues(
		"{1}^/legacy/special/([^/]+)$ "+homes+"/special-$1",
		"{0}^/legacy/([^/]+)$ "+homes+"/$1",
	))

	configuration, err := loadHomedirRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadHomedirRuntimeConfiguration(): %v", err)
	}
	if configuration.skeletonPath != skeleton ||
		configuration.minimumUID != 0 ||
		configuration.deleteStyle != homedirDeleteArchive ||
		configuration.archivePath != archive ||
		len(configuration.regexps) != 2 {
		t.Fatalf("homedir configuration = %#v", configuration)
	}
	if configuration.regexps[0].match != "^/legacy/([^/]+)$" {
		t.Fatalf("first ordered regexp = %q", configuration.regexps[0].match)
	}
	values := configuration.harvest(&directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "homeDirectory", Values: stringValues("/legacy/alice")},
			{Description: "uidNumber", Values: stringValues("1000")},
			{Description: "gidNumber", Values: stringValues("1000")},
		},
	})
	if !values.valid || values.path.absolute != filepath.Join(homes, "alice") {
		t.Fatalf("harvested values = %#v", values)
	}

	defaults, err := loadHomedirRuntimeConfiguration(directory.Entry{
		DN: testHomedirOverlayDN,
	})
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}
	if defaults.skeletonPath != defaultHomedirSkeletonPath ||
		defaults.minimumUID != defaultHomedirMinimumUID ||
		defaults.deleteStyle != homedirDeleteIgnore ||
		len(defaults.regexps) != 0 {
		t.Fatalf("default homedir configuration = %#v", defaults)
	}
}

func TestLoadHomedirRuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	tests := []struct {
		name      string
		attribute string
		values    []string
		contains  string
	}{
		{
			name:      "relative skeleton",
			attribute: "olcSkeletonPath",
			values:    []string{"relative/skel"},
			contains:  "absolute path",
		},
		{
			name:      "negative minimum uid",
			attribute: "olcMinimumUidNumber",
			values:    []string{"-1"},
			contains:  "invalid value",
		},
		{
			name:      "invalid regexp",
			attribute: "olcHomedirRegexp",
			values:    []string{"([ " + homes + "/$1"},
			contains:  "error parsing regexp",
		},
		{
			name:      "unbounded replacement",
			attribute: "olcHomedirRegexp",
			values:    []string{"^/legacy/(.*)$ /$1"},
			contains:  "trusted root",
		},
		{
			name:      "invalid expansion",
			attribute: "olcHomedirRegexp",
			values:    []string{"^/legacy/(.*)$ " + homes + "/$x"},
			contains:  "invalid match expansion",
		},
		{
			name:      "duplicate order",
			attribute: "olcHomedirRegexp",
			values: []string{
				"{0}^/legacy/(.*)$ " + homes + "/$1",
				"{0}^/other/(.*)$ " + homes + "/$1",
			},
			contains: "duplicate ordered value",
		},
		{
			name:      "mixed ordering",
			attribute: "olcHomedirRegexp",
			values: []string{
				"{0}^/legacy/(.*)$ " + homes + "/$1",
				"^/other/(.*)$ " + homes + "/$1",
			},
			contains: "cannot mix ordered and unordered",
		},
		{
			name:      "invalid delete style",
			attribute: "olcHomedirDeleteStyle",
			values:    []string{"REMOVE"},
			contains:  "invalid value",
		},
		{
			name:      "root archive",
			attribute: "olcHomedirArchivePath",
			values:    []string{"/"},
			contains:  "filesystem root",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{
				DN: testHomedirOverlayDN,
				Attributes: []directory.Attribute{
					{Description: test.attribute, Values: stringValues(test.values...)},
				},
			}
			_, err := loadHomedirRuntimeConfiguration(entry)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want substring %q", err, test.contains)
			}
		})
	}
}

func TestProvisionHomedirRejectsDestinationInsideSkeleton(t *testing.T) {
	t.Parallel()

	skeleton := t.TempDir()
	homes := filepath.Join(skeleton, "homes")
	if err := os.Mkdir(homes, 0o755); err != nil {
		t.Fatalf("Mkdir(homes): %v", err)
	}
	target := homedirPath{
		root:     homes,
		relative: "alice",
		absolute: filepath.Join(homes, "alice"),
	}
	err := provisionHomedir(
		target,
		skeleton,
		uint64(os.Getuid()),
		uint64(os.Getgid()),
	)
	if err == nil || !strings.Contains(err.Error(), "contains destination") {
		t.Fatalf("provisionHomedir() error = %v", err)
	}
	if _, statErr := os.Stat(target.absolute); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination stat error = %v", statErr)
	}
}

func TestProvisionHomedirRejectsSymlinkSkeletonContainingDestination(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	if err := os.Mkdir(homes, 0o755); err != nil {
		t.Fatalf("Mkdir(homes): %v", err)
	}
	skeletonLink := filepath.Join(root, "skeleton-link")
	if err := os.Symlink(homes, skeletonLink); err != nil {
		t.Fatalf("Symlink(skeleton): %v", err)
	}
	target := homedirPath{
		root:     homes,
		relative: "alice",
		absolute: filepath.Join(homes, "alice"),
	}
	err := provisionHomedir(
		target,
		skeletonLink,
		uint64(os.Getuid()),
		uint64(os.Getgid()),
	)
	if err == nil || !strings.Contains(err.Error(), "contains destination") {
		t.Fatalf("provisionHomedir() error = %v", err)
	}
	if _, statErr := os.Stat(target.absolute); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination stat error = %v", statErr)
	}
}

func TestArchiveHomedirRejectsArchiveInsideSource(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "alice")
	archive := filepath.Join(home, "archive")
	if err := os.MkdirAll(archive, 0o755); err != nil {
		t.Fatalf("MkdirAll(archive): %v", err)
	}
	marker := filepath.Join(home, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile(marker): %v", err)
	}
	archiveLink := filepath.Join(root, "archive-link")
	if err := os.Symlink(archive, archiveLink); err != nil {
		t.Fatalf("Symlink(archive): %v", err)
	}
	path := homedirPath{
		root:     homes,
		relative: "alice",
		absolute: home,
	}
	err := archiveHomedir(path, archiveLink, time.Unix(123, 0))
	if err == nil || !strings.Contains(err.Error(), "inside source home") {
		t.Fatalf("archiveHomedir() error = %v", err)
	}
	entries, readErr := os.ReadDir(archive)
	if readErr != nil {
		t.Fatalf("ReadDir(archive): %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("archive entries after rejection = %v", entries)
	}
	assertHomedirMarker(t, marker)
}

func TestHomedirOverlayLifecycle(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	skeleton := filepath.Join(root, "skel")
	homes := filepath.Join(root, "homes")
	archive := filepath.Join(root, "archive")
	for _, path := range []string{skeleton, homes, archive} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("Mkdir(%q): %v", path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(skeleton, "welcome.txt"), []byte("welcome\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(skeleton): %v", err)
	}
	if err := os.Mkdir(filepath.Join(skeleton, "profile"), 0o750); err != nil {
		t.Fatalf("Mkdir(profile): %v", err)
	}
	if err := os.WriteFile(filepath.Join(skeleton, "profile", "settings"), []byte("enabled"), 0o600); err != nil {
		t.Fatalf("WriteFile(settings): %v", err)
	}
	if err := os.Symlink("welcome.txt", filepath.Join(skeleton, "welcome-link")); err != nil {
		t.Fatalf("Symlink(skeleton): %v", err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedHomedirOverlay(t, store, homedirOverlayEntry(
		skeleton,
		homes,
		archive,
		"ARCHIVE",
	))
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindHomedirClient(t, address, "cn=admin,dc=example,dc=com", "admin-secret")
	defer client.Close()

	aliceDN := "uid=alice-home,ou=people,dc=example,dc=com"
	if err := client.Add(homedirAccountAddRequest(
		aliceDN,
		"alice-home",
		"/legacy/alice",
	)); err != nil {
		t.Fatalf("Add(alice): %v", err)
	}
	aliceHome := filepath.Join(homes, "alice")
	assertHomedirSkeleton(t, aliceHome)

	modifyHome := ldap.NewModifyRequest(aliceDN, nil)
	modifyHome.Replace("homeDirectory", []string{"/legacy/alicia"})
	if err := client.Modify(modifyHome); err != nil {
		t.Fatalf("Modify(homeDirectory): %v", err)
	}
	aliciaHome := filepath.Join(homes, "alicia")
	if _, err := os.Stat(aliceHome); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old home after rename stat error = %v", err)
	}
	assertHomedirSkeleton(t, aliciaHome)

	renameUID := ldap.NewModifyDNRequest(
		aliceDN,
		"uid=alice-renamed",
		true,
		"",
	)
	if err := client.ModifyDN(renameUID); err != nil {
		t.Fatalf("ModifyDN(uid): %v", err)
	}
	aliceDN = "uid=alice-renamed,ou=people,dc=example,dc=com"
	assertHomedirSkeleton(t, aliciaHome)

	homeRDN := "/legacy/rdn-old"
	homeRDNEntryDN := "homeDirectory=" + homeRDN + ",ou=people,dc=example,dc=com"
	if err := client.Add(homedirAccountAddRequest(
		homeRDNEntryDN,
		"rdn-user",
		homeRDN,
	)); err != nil {
		t.Fatalf("Add(homeDirectory RDN): %v", err)
	}
	rdnOldPath := filepath.Join(homes, "rdn-old")
	assertHomedirSkeleton(t, rdnOldPath)
	renameHomeRDN := ldap.NewModifyDNRequest(
		homeRDNEntryDN,
		"homeDirectory=/legacy/rdn-new",
		true,
		"",
	)
	if err := client.ModifyDN(renameHomeRDN); err != nil {
		t.Fatalf("ModifyDN(homeDirectory): %v", err)
	}
	rdnNewPath := filepath.Join(homes, "rdn-new")
	if _, err := os.Stat(rdnOldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old RDN home after rename stat error = %v", err)
	}
	assertHomedirSkeleton(t, rdnNewPath)

	if err := client.Del(ldap.NewDelRequest(aliceDN, nil)); err != nil {
		t.Fatalf("Delete(alice): %v", err)
	}
	if _, err := os.Stat(aliciaHome); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("archived home stat error = %v", err)
	}
	archiveFile := singleHomedirArchive(t, archive, "alicia-")
	assertHomedirArchiveContains(t, archiveFile, "alicia/welcome.txt", "welcome\n")
}

func TestHomedirOverlayRejectsTraversalAndSymlinkParents(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	skeleton := filepath.Join(root, "skel")
	homes := filepath.Join(root, "homes")
	outside := filepath.Join(root, "outside")
	for _, path := range []string{skeleton, homes, outside} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("Mkdir(%q): %v", path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(skeleton, "seed"), []byte("seed"), 0o600); err != nil {
		t.Fatalf("WriteFile(skeleton): %v", err)
	}
	outsideVictim := filepath.Join(outside, "victim")
	if err := os.Mkdir(outsideVictim, 0o755); err != nil {
		t.Fatalf("Mkdir(outside victim): %v", err)
	}
	marker := filepath.Join(outsideVictim, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile(marker): %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(homes, "linked")); err != nil {
		t.Fatalf("Symlink(parent): %v", err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	overlay := homedirOverlayEntry(skeleton, homes, "", "DELETE")
	overlay.ReplaceValues("olcHomedirRegexp", stringValues(
		"{0}^/legacy/(.*)$ "+homes+"/$1",
	))
	seedHomedirOverlay(t, store, overlay)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindHomedirClient(t, address, "cn=admin,dc=example,dc=com", "admin-secret")
	defer client.Close()

	traversalDN := "uid=traversal,ou=people,dc=example,dc=com"
	if err := client.Add(homedirAccountAddRequest(
		traversalDN,
		"traversal",
		"/legacy/../../outside/victim",
	)); err != nil {
		t.Fatalf("Add(traversal): %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(traversalDN, nil)); err != nil {
		t.Fatalf("Delete(traversal): %v", err)
	}
	assertHomedirMarker(t, marker)

	symlinkDN := "uid=symlink,ou=people,dc=example,dc=com"
	if err := client.Add(homedirAccountAddRequest(
		symlinkDN,
		"symlink",
		"/legacy/linked/victim",
	)); err != nil {
		t.Fatalf("Add(symlink parent): %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(symlinkDN, nil)); err != nil {
		t.Fatalf("Delete(symlink parent): %v", err)
	}
	assertHomedirMarker(t, marker)
}

func TestHomedirOverlayConfigurationRollback(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	skeleton := filepath.Join(root, "skel")
	homes := filepath.Join(root, "homes")
	for _, path := range []string{skeleton, homes} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("Mkdir(%q): %v", path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(skeleton, "seed"), []byte("seed"), 0o600); err != nil {
		t.Fatalf("WriteFile(seed): %v", err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	configClient := bindHomedirClient(t, address, "cn=config", "config-secret")
	defer configClient.Close()
	dataClient := bindHomedirClient(t, address, "cn=admin,dc=example,dc=com", "admin-secret")
	defer dataClient.Close()

	addOverlay := ldap.NewAddRequest(testHomedirOverlayDN, nil)
	addOverlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcHomedirConfig"})
	addOverlay.Attribute("olcOverlay", []string{"{0}homedir"})
	addOverlay.Attribute("olcSkeletonPath", []string{skeleton})
	addOverlay.Attribute("olcMinimumUidNumber", []string{"0"})
	validRegexp := "{0}^/legacy/([^/]+)$ " + homes + "/$1"
	addOverlay.Attribute("olcHomedirRegexp", []string{validRegexp})
	addOverlay.Attribute("olcHomedirDeleteStyle", []string{"DELETE"})
	if err := configClient.Add(addOverlay); err != nil {
		t.Fatalf("Add(homedir overlay): %v", err)
	}

	invalid := ldap.NewModifyRequest(testHomedirOverlayDN, nil)
	invalid.Replace("olcHomedirRegexp", []string{"{0}^/legacy/(.*)$ /$1"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	stored := readStoredEntry(t, store, testHomedirOverlayDN).Values("olcHomedirRegexp")
	if len(stored) != 1 || string(stored[0]) != validRegexp {
		t.Fatalf("olcHomedirRegexp after rollback = %q", stored)
	}

	duplicate := ldap.NewAddRequest(
		"olcOverlay={1}homedir,olcDatabase={1}mdb,cn=config",
		nil,
	)
	duplicate.Attribute("objectClass", []string{"olcOverlayConfig", "olcHomedirConfig"})
	duplicate.Attribute("olcOverlay", []string{"{1}homedir"})
	duplicate.Attribute("olcHomedirRegexp", []string{validRegexp})
	assertLDAPResultCode(
		t,
		configClient.Add(duplicate),
		ldap.LDAPResultConstraintViolation,
	)

	entryDN := "uid=after-rollback,ou=people,dc=example,dc=com"
	if err := dataClient.Add(homedirAccountAddRequest(
		entryDN,
		"after-rollback",
		"/legacy/after-rollback",
	)); err != nil {
		t.Fatalf("Add(after rollback): %v", err)
	}
	seed, err := os.ReadFile(filepath.Join(homes, "after-rollback", "seed"))
	if err != nil || string(seed) != "seed" {
		t.Fatalf("home after configuration rollback = %q, error %v", seed, err)
	}
	if err := dataClient.Del(ldap.NewDelRequest(entryDN, nil)); err != nil {
		t.Fatalf("Delete(after rollback): %v", err)
	}
	if _, err := os.Stat(filepath.Join(homes, "after-rollback")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("home after DELETE style stat error = %v", err)
	}
}

func TestHomedirFilesystemFailureDoesNotRollbackLDAPWrite(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	if err := os.Mkdir(homes, 0o755); err != nil {
		t.Fatalf("Mkdir(homes): %v", err)
	}
	missingSkeleton := filepath.Join(root, "missing-skeleton")

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedHomedirOverlay(t, store, homedirOverlayEntry(
		missingSkeleton,
		homes,
		"",
		"DELETE",
	))
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindHomedirClient(t, address, "cn=admin,dc=example,dc=com", "admin-secret")
	defer client.Close()

	entryDN := "uid=fs-failure,ou=people,dc=example,dc=com"
	if err := client.Add(homedirAccountAddRequest(
		entryDN,
		"fs-failure",
		"/legacy/fs-failure",
	)); err != nil {
		t.Fatalf("Add(with missing skeleton): %v", err)
	}
	_ = readStoredEntry(t, store, entryDN)
	if _, err := os.Stat(filepath.Join(homes, "fs-failure")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("home after failed provision stat error = %v", err)
	}
}

func homedirOverlayEntry(
	skeleton,
	homes,
	archive,
	deleteStyle string,
) directory.Entry {
	attributes := []directory.Attribute{
		{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcHomedirConfig")},
		{Description: "olcOverlay", Values: stringValues("{0}homedir")},
		{Description: "olcSkeletonPath", Values: stringValues(skeleton)},
		{Description: "olcMinimumUidNumber", Values: stringValues("0")},
		{
			Description: "olcHomedirRegexp",
			Values: stringValues(
				"{0}^/legacy/([^/]+)$ " + homes + "/$1",
			),
		},
		{Description: "olcHomedirDeleteStyle", Values: stringValues(deleteStyle)},
	}
	if archive != "" {
		attributes = append(attributes, directory.Attribute{
			Description: "olcHomedirArchivePath",
			Values:      stringValues(archive),
		})
	}
	return directory.Entry{DN: testHomedirOverlayDN, Attributes: attributes}
}

func seedHomedirOverlay(t *testing.T, store storage.Store, entry directory.Entry) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed homedir overlay: %v", err)
	}
}

func bindHomedirClient(t *testing.T, address, dn, password string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(dn, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", dn, err)
	}
	return client
}

func homedirAccountAddRequest(dn, uid, home string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{uid})
	request.Attribute("uidNumber", []string{strconv.Itoa(os.Getuid())})
	request.Attribute("gidNumber", []string{strconv.Itoa(os.Getgid())})
	request.Attribute("homeDirectory", []string{home})
	return request
}

func assertHomedirSkeleton(t *testing.T, home string) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(home, "welcome.txt"))
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", home, err)
	}
	if string(contents) != "welcome\n" {
		t.Fatalf("welcome contents = %q", contents)
	}
	settings, err := os.ReadFile(filepath.Join(home, "profile", "settings"))
	if err != nil || string(settings) != "enabled" {
		t.Fatalf("profile settings = %q, error %v", settings, err)
	}
	target, err := os.Readlink(filepath.Join(home, "welcome-link"))
	if err != nil || target != "welcome.txt" {
		t.Fatalf("welcome-link = %q, error %v", target, err)
	}
}

func singleHomedirArchive(t *testing.T, directoryPath, prefix string) string {
	t.Helper()
	entries, err := os.ReadDir(directoryPath)
	if err != nil {
		t.Fatalf("ReadDir(archive): %v", err)
	}
	var matches []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".tar") {
			matches = append(matches, filepath.Join(directoryPath, entry.Name()))
		}
	}
	if len(matches) != 1 {
		t.Fatalf("archive matches = %q, want one", matches)
	}
	return matches[0]
}

func assertHomedirArchiveContains(t *testing.T, archivePath, name, contents string) {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("Open(archive): %v", err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read archive: %v", err)
		}
		if header.Name != name {
			continue
		}
		value, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("Read archive member: %v", err)
		}
		if string(value) != contents {
			t.Fatalf("archive member %s = %q", name, value)
		}
		return
	}
	t.Fatalf("archive member %q not found", name)
}

func assertHomedirMarker(t *testing.T, marker string) {
	t.Helper()
	value, err := os.ReadFile(marker)
	if err != nil || string(value) != "keep" {
		t.Fatalf("outside marker = %q, error %v", value, err)
	}
}
