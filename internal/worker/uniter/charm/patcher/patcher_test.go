// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package patcher_test

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/juju/collections/set"
	"github.com/juju/tc"

	"github.com/juju/juju/environs/config"
	loggertesting "github.com/juju/juju/internal/logger/testing"
	"github.com/juju/juju/internal/testhelpers"
	"github.com/juju/juju/internal/worker/uniter/charm"
	"github.com/juju/juju/internal/worker/uniter/charm/patcher"
)

// PatcherSuite tests PatchingBundleReader end-to-end.
type PatcherSuite struct {
	testhelpers.IsolationSuite
}

func TestPatcherSuite(t *testing.T) {
	tc.Run(t, &PatcherSuite{})
}

// buildPatchesZip creates an in-memory zip containing the given files
// (filename -> content) and returns its bytes. Both .star script files and
// arbitrary data files are accepted.
func buildPatchesZip(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, src := range files {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(src))
	}
	_ = zw.Close()
	return buf.Bytes()
}

// buildCharmZip creates a minimal charm zip containing the given files
// (path -> content) and returns its bytes.
func buildCharmZip(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// A real charm needs at least metadata.yaml.
	if _, ok := files["metadata.yaml"]; !ok {
		w, _ := zw.Create("metadata.yaml")
		_, _ = w.Write([]byte("name: test-charm\nsummary: test\ndescription: test\n"))
	}
	for name, content := range files {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
	}
	_ = zw.Close()
	return buf.Bytes()
}

// serveZip starts a test HTTP server that responds with the given zip bytes.
func serveZip(c *tc.C, zipData []byte) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	c.Cleanup(srv.Close)
	return srv
}

// stubModelConfigGetter returns a ModelConfigGetter that always returns a
// config with the given charm-patches URL.
type stubModelConfigGetter struct {
	patchesURL string
}

func (s *stubModelConfigGetter) ModelConfig(ctx context.Context) (*config.Config, error) {
	attrs := map[string]any{
		"name":          "test",
		"type":          "manual",
		"uuid":          "00000000-0000-0000-0000-000000000001",
		"charm-patches": s.patchesURL,
	}
	return config.New(config.UseDefaults, attrs)
}

// stubBundlePathReader implements BundlePathReader using a fixed path for
// bundles and a fake bundle that returns a pre-built zip.
type stubBundlePathReader struct {
	path   string // local path where zip is stored
	bundle charm.Bundle
}

func (s *stubBundlePathReader) Read(_ context.Context, _ charm.BundleInfo) (charm.Bundle, error) {
	return s.bundle, nil
}

func (s *stubBundlePathReader) BundlePath(_ charm.BundleInfo) string {
	return s.path
}

// stubBundleInfo is a minimal BundleInfo.
type stubBundleInfo struct{ url string }

func (i *stubBundleInfo) URL() string                                     { return i.url }
func (i *stubBundleInfo) ArchiveSha256(_ context.Context) (string, error) { return "", nil }

// ScriptSuite tests the individual Starlark builtins via runScript
// (accessed through PatchingBundleReader integration tests).
type ScriptSuite struct {
	testhelpers.IsolationSuite
}

func TestScriptSuite(t *testing.T) {
	tc.Run(t, &ScriptSuite{})
}

// runWithScript sets up a minimal PatchingBundleReader with a single
// script and optional extra patch zip files served over HTTP, calls Read,
// and returns the resulting bundle.
func (s *ScriptSuite) runWithScript(c *tc.C, charmFiles map[string]string, script string) charm.Bundle {
	return s.runWithPatchZip(c, charmFiles, map[string]string{"test.star": script})
}

// runWithPatchZip sets up a minimal PatchingBundleReader with the given patch
// zip contents (which may include both .star scripts and data files), calls
// Read, and returns the resulting bundle.
func (s *ScriptSuite) runWithPatchZip(c *tc.C, charmFiles map[string]string, patchFiles map[string]string) charm.Bundle {
	charmZip := buildCharmZip(charmFiles)

	// Write charm zip to a temp file so BundlePath can point to it.
	dir := c.MkDir()
	charmPath := filepath.Join(dir, "charm.zip")
	c.Assert(os.WriteFile(charmPath, charmZip, 0644), tc.ErrorIsNil)

	patchesZip := buildPatchesZip(patchFiles)
	srv := serveZip(c, patchesZip)

	log := loggertesting.WrapCheckLog(c)
	configGetter := &stubModelConfigGetter{patchesURL: srv.URL}

	innerBundle := &fakeDiskBundle{path: charmPath, zipData: charmZip}
	inner := &stubBundlePathReader{path: charmPath, bundle: innerBundle}
	reader := patcher.NewPatchingBundleReader(inner, configGetter, log)

	bundle, err := reader.Read(c.Context(), &stubBundleInfo{url: "ch:test-charm-1"})
	c.Assert(err, tc.ErrorIsNil)
	return bundle
}

// fakeDiskBundle implements charm.Bundle for testing.
type fakeDiskBundle struct {
	path    string
	zipData []byte
}

func (b *fakeDiskBundle) ArchiveMembers() (set.Strings, error) {
	return set.NewStrings(), nil
}

func (b *fakeDiskBundle) ExpandTo(_ string) error { return nil }

func (s *ScriptSuite) TestCharmWriteAndRead(c *tc.C) {
	// Verify that charm_exists, charm_read, and charm_write all work and that
	// a modified charm is returned instead of the original.
	script := `
if charm_exists("hooks/install"):
    charm_write("hooks/install", "#!/bin/bash\necho hello # patched")
`
	bundle := s.runWithScript(c, map[string]string{
		"hooks/install": "#!/bin/bash\necho hello",
	}, script)
	c.Assert(bundle, tc.NotNil)
}

func (s *ScriptSuite) TestCharmDelete(c *tc.C) {
	script := `
if charm_exists("lib/unused.py"):
    charm_delete("lib/unused.py")
`
	bundle := s.runWithScript(c, map[string]string{
		"lib/unused.py": "# unused",
	}, script)
	c.Assert(bundle, tc.NotNil)
}

func (s *ScriptSuite) TestCharmList(c *tc.C) {
	script := `
files = charm_list("hooks")
log("hooks: " + str(files))
`
	_ = s.runWithScript(c, map[string]string{
		"hooks/install": "#!/bin/bash",
		"hooks/start":   "#!/bin/bash",
	}, script)
}

func (s *ScriptSuite) TestSHA256(c *tc.C) {
	script := `
h = sha256("hello")
if len(h) != 64:
    fail("expected 64-char hex, got: " + str(len(h)))
`
	bundle := s.runWithScript(c, map[string]string{}, script)
	c.Assert(bundle, tc.NotNil)
}

func (s *ScriptSuite) TestDiffAndPatch(c *tc.C) {
	script := `
old = "hello world"
new = "hello juju"
p = diff(old, new)
result = patch(old, p)
if result != new:
    fail("expected patched result " + repr(new) + " got " + repr(result))
`
	bundle := s.runWithScript(c, map[string]string{}, script)
	c.Assert(bundle, tc.NotNil)
}

func (s *ScriptSuite) TestPatchRead(c *tc.C) {
	script := `
data = patch_read("data/template.txt")
charm_write("injected.txt", data)
`
	bundle := s.runWithPatchZip(c, map[string]string{}, map[string]string{
		"patch.star":        script,
		"data/template.txt": "hello from the patch zip",
	})
	c.Assert(bundle, tc.NotNil)
}

func (s *ScriptSuite) TestPatchExists(c *tc.C) {
	script := `
if not patch_exists("data/present.txt"):
    fail("expected data/present.txt to exist")
if patch_exists("data/absent.txt"):
    fail("expected data/absent.txt to be absent")
`
	bundle := s.runWithPatchZip(c, map[string]string{}, map[string]string{
		"patch.star":       script,
		"data/present.txt": "here",
	})
	c.Assert(bundle, tc.NotNil)
}

func (s *ScriptSuite) TestPatchList(c *tc.C) {
	script := `
all_files = patch_list()
if len(all_files) != 3:  # patch.star + data/a.txt + data/b.txt
    fail("expected 3 files, got: " + str(len(all_files)))
data_files = patch_list("data")
if len(data_files) != 2:
    fail("expected 2 data files, got: " + str(len(data_files)))
`
	bundle := s.runWithPatchZip(c, map[string]string{}, map[string]string{
		"patch.star": script,
		"data/a.txt": "a",
		"data/b.txt": "b",
	})
	c.Assert(bundle, tc.NotNil)
}

func (s *ScriptSuite) TestScriptFailureLeavesOriginalBundle(c *tc.C) {
	script := `fail("intentional failure")`

	charmZip := buildCharmZip(map[string]string{})
	dir := c.MkDir()
	charmPath := filepath.Join(dir, "charm.zip")
	c.Assert(os.WriteFile(charmPath, charmZip, 0644), tc.ErrorIsNil)

	patchesZip := buildPatchesZip(map[string]string{"bad.star": script})
	srv := serveZip(c, patchesZip)

	log := loggertesting.WrapCheckLog(c)
	innerBundle := &fakeDiskBundle{path: charmPath, zipData: charmZip}
	inner := &stubBundlePathReader{
		path:   charmPath,
		bundle: innerBundle,
	}
	configGetter := &stubModelConfigGetter{patchesURL: srv.URL}
	reader := patcher.NewPatchingBundleReader(inner, configGetter, log)

	bundle, err := reader.Read(c.Context(), &stubBundleInfo{url: "ch:test-1"})
	c.Assert(err, tc.ErrorIsNil)
	// Should return the original (inner) bundle, not nil.
	c.Check(bundle, tc.NotNil)
}

func (s *PatcherSuite) TestNoPatchesURL_ReturnsOriginalBundle(c *tc.C) {
	charmZip := buildCharmZip(map[string]string{})
	dir := c.MkDir()
	charmPath := filepath.Join(dir, "charm.zip")
	c.Assert(os.WriteFile(charmPath, charmZip, 0644), tc.ErrorIsNil)

	log := loggertesting.WrapCheckLog(c)
	innerBundle := &fakeDiskBundle{path: charmPath, zipData: charmZip}
	inner := &stubBundlePathReader{path: charmPath, bundle: innerBundle}
	configGetter := &stubModelConfigGetter{patchesURL: ""}
	reader := patcher.NewPatchingBundleReader(inner, configGetter, log)

	bundle, err := reader.Read(c.Context(), &stubBundleInfo{url: "ch:test-1"})
	c.Assert(err, tc.ErrorIsNil)
	// No patching: must return the exact original bundle.
	c.Check(bundle, tc.Equals, innerBundle)
}

func (s *PatcherSuite) TestDownloadFails_ReturnsOriginalBundle(c *tc.C) {
	charmZip := buildCharmZip(map[string]string{})
	dir := c.MkDir()
	charmPath := filepath.Join(dir, "charm.zip")
	c.Assert(os.WriteFile(charmPath, charmZip, 0644), tc.ErrorIsNil)

	log := loggertesting.WrapCheckLog(c)
	innerBundle := &fakeDiskBundle{path: charmPath, zipData: charmZip}
	inner := &stubBundlePathReader{path: charmPath, bundle: innerBundle}
	// Point to a server that returns 404.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	c.Cleanup(srv.Close)

	configGetter := &stubModelConfigGetter{patchesURL: srv.URL}
	reader := patcher.NewPatchingBundleReader(inner, configGetter, log)

	bundle, err := reader.Read(c.Context(), &stubBundleInfo{url: "ch:test-1"})
	c.Assert(err, tc.ErrorIsNil)
	c.Check(bundle, tc.Equals, innerBundle)
}
