package buildcontract

import (
	"bytes"
	"encoding/json"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Inspect foreign targets with go list; only this host's test binary is run.
func TestProductionDependenciesPureGo(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	checkedSources := make(map[string]bool)
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "arm64"},
		{"darwin", "amd64"}, {"darwin", "arm64"},
		{"windows", "amd64"}, {"freebsd", "amd64"},
	} {
		t.Run(target.os+"/"+target.arch, func(t *testing.T) {
			command := exec.Command("go", "list", "-deps", "-json", "./...")
			command.Dir = root
			command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+target.os, "GOARCH="+target.arch)
			var stderr bytes.Buffer
			command.Stderr = &stderr
			output, err := command.Output()
			if err != nil {
				t.Fatalf("list pure-Go production dependencies: %v\n%s", err, &stderr)
			}
			buildContext := build.Default
			buildContext.GOOS, buildContext.GOARCH = target.os, target.arch
			buildContext.CgoEnabled = false
			decoder := json.NewDecoder(bytes.NewReader(output))
			packages := 0
			directModules := make(map[string]bool)
			for {
				var pkg struct {
					ImportPath     string
					Dir            string
					GoFiles        []string
					IgnoredGoFiles []string
					CgoFiles       []string
					SwigFiles      []string
					SwigCXXFiles   []string
					Module         *struct {
						Path     string
						Main     bool
						Indirect bool
					}
				}
				if err := decoder.Decode(&pkg); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				packages++
				if len(pkg.CgoFiles)+len(pkg.SwigFiles)+len(pkg.SwigCXXFiles) != 0 {
					t.Errorf("%s selects cgo/SWIG sources", pkg.ImportPath)
				}
				if pkg.Module == nil || pkg.Module.Indirect {
					continue
				}
				if !pkg.Module.Main {
					directModules[pkg.Module.Path] = true
				}
				// Include ignored sources so disabling cgo cannot silently hide an
				// unguarded C import. Upstream generators and optional tags are allowed.
				for _, name := range append(pkg.GoFiles, pkg.IgnoredGoFiles...) {
					if strings.HasSuffix(name, "_test.go") {
						continue
					}
					path := filepath.Join(pkg.Dir, name)
					hasCgo, checked := checkedSources[path]
					if !checked {
						hasCgo = sourceUsesCgo(t, path)
						checkedSources[path] = hasCgo
					}
					if !hasCgo {
						continue
					}
					matches, err := buildContext.MatchFile(pkg.Dir, name)
					if err != nil {
						t.Fatal(err)
					}
					if pkg.Module.Main || matches {
						t.Errorf("production source contains a C import or #cgo directive: %s", path)
					} else {
						t.Logf("excluded upstream cgo source: %s/%s", pkg.ImportPath, name)
					}
				}
			}
			if packages == 0 || len(directModules) == 0 {
				t.Fatal("production dependency audit was empty")
			}
			t.Logf("audited %d packages and %d direct production modules", packages, len(directModules))
		})
	}
}

func sourceUsesCgo(t *testing.T, path string) bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly|parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range file.Imports {
		if spec.Path.Value == `"C"` || spec.Path.Value == "`C`" {
			return true
		}
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if strings.Contains(comment.Text, "#cgo") {
				return true
			}
		}
	}
	return false
}
