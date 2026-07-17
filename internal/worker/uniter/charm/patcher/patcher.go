// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package patcher implements Starlark-based charm patch script execution.
// When a model operator configures the charm-patches model config key with a
// URL pointing to a zip of Starlark scripts, those scripts are run against
// each charm archive in memory before the charm is unpacked to disk.
package patcher

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/juju/errors"

	"github.com/juju/juju/core/logger"
	deploymentcharm "github.com/juju/juju/domain/deployment/charm"
	"github.com/juju/juju/environs/config"
	"github.com/juju/juju/internal/worker/uniter/charm"
)

// ModelConfigGetter retrieves the current model configuration.
type ModelConfigGetter interface {
	ModelConfig(context.Context) (*config.Config, error)
}

// BundlePathReader extends charm.BundleReader with the ability to look up the
// local filesystem path of a downloaded bundle zip.
type BundlePathReader interface {
	charm.BundleReader
	// BundlePath returns the local path to the zip file for the given bundle.
	// The bundle must already exist on disk (i.e. Read must have been called).
	BundlePath(charm.BundleInfo) string
}

// PatchingBundleReader wraps a BundlePathReader. On each Read it fetches the
// Starlark patch scripts nominated by the model's charm-patches config key,
// applies them to the charm's zip contents in memory, and returns the
// (possibly modified) bundle. On any error the original bundle is returned
// and the error is logged as a warning, so patching failures are never fatal.
type PatchingBundleReader struct {
	inner        BundlePathReader
	configGetter ModelConfigGetter
	logger       logger.Logger
}

// NewPatchingBundleReader constructs a PatchingBundleReader.
func NewPatchingBundleReader(
	inner BundlePathReader,
	configGetter ModelConfigGetter,
	logger logger.Logger,
) *PatchingBundleReader {
	return &PatchingBundleReader{
		inner:        inner,
		configGetter: configGetter,
		logger:       logger,
	}
}

// Read implements charm.BundleReader. It reads the bundle via the inner reader,
// then applies any configured Starlark patch scripts before returning.
// All patch failures are logged as warnings and the original bundle is
// returned as a fallback.
func (r *PatchingBundleReader) Read(ctx context.Context, bi charm.BundleInfo) (charm.Bundle, error) {
	bundle, err := r.inner.Read(ctx, bi)
	if err != nil {
		return nil, err
	}

	cfg, err := r.configGetter.ModelConfig(ctx)
	if err != nil {
		r.logger.Warningf(ctx, "charm patcher: cannot fetch model config, skipping patches: %v", err)
		return bundle, nil
	}
	patchesURL := cfg.CharmPatchesURL()
	if patchesURL == "" {
		return bundle, nil
	}

	patchVFS, err := downloadPatchZip(ctx, patchesURL)
	if err != nil {
		r.logger.Warningf(ctx, "charm patcher: cannot fetch patch scripts from %q: %v", patchesURL, err)
		return bundle, nil
	}
	scripts := extractScripts(patchVFS)
	if len(scripts) == 0 {
		return bundle, nil
	}

	bundlePath := r.inner.BundlePath(bi)
	zipData, err := os.ReadFile(bundlePath)
	if err != nil {
		r.logger.Warningf(ctx, "charm patcher: cannot read charm zip at %q: %v", bundlePath, err)
		return bundle, nil
	}

	patchedData, changed, err := applyPatchScripts(ctx, bi.URL(), zipData, scripts, patchVFS, r.logger)
	if err != nil {
		r.logger.Warningf(ctx, "charm patcher: error applying patches to charm %q: %v", bi.URL(), err)
		return bundle, nil
	}
	if !changed {
		return bundle, nil
	}

	patched, err := deploymentcharm.ReadCharmArchiveBytes(patchedData)
	if err != nil {
		r.logger.Warningf(ctx, "charm patcher: patched archive for charm %q is invalid: %v", bi.URL(), err)
		return bundle, nil
	}
	return patched, nil
}

// downloadPatchZip fetches the patches zip from url and returns a virtualFS
// containing every regular file in the archive. The caller can enumerate
// scripts via extractScripts.
func downloadPatchZip(ctx context.Context, url string) (*virtualFS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Annotatef(err, "building request for %q", url)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Annotatef(err, "downloading patches from %q", url)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("downloading patches from %q: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Annotate(err, "reading patches zip body")
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.Annotatef(err, "parsing patches zip from %q", url)
	}
	return newVirtualFS(zr)
}

// extractScripts returns a map of zip entry name to Starlark source text for
// every .star file present in patchVFS.
func extractScripts(patchVFS *virtualFS) map[string]string {
	scripts := make(map[string]string)
	for name, data := range patchVFS.files {
		if strings.HasSuffix(name, ".star") {
			scripts[name] = string(data)
		}
	}
	return scripts
}

// applyPatchScripts runs all scripts against an in-memory copy of the charm zip
// at zipData. Scripts are executed in alphabetical order so results are
// deterministic. patchVFS provides read-only access to all files in the patch
// zip for use by patch_read/exists/list. It returns the rewritten zip bytes
// and true when any script modifies the charm, or nil/false if unchanged.
func applyPatchScripts(
	ctx context.Context,
	charmURL string,
	zipData []byte,
	scripts map[string]string,
	patchVFS *virtualFS,
	log logger.Logger,
) ([]byte, bool, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, false, errors.Annotate(err, "parsing charm zip")
	}
	vfs, err := newVirtualFS(zr)
	if err != nil {
		return nil, false, errors.Annotate(err, "loading charm files into virtual fs")
	}

	names := make([]string, 0, len(scripts))
	for n := range scripts {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		if err := runScript(ctx, name, scripts[name], charmURL, vfs, patchVFS, log); err != nil {
			log.Warningf(ctx, "charm patcher: script %q failed for charm %q: %v", name, charmURL, err)
		}
	}

	if !vfs.changed {
		return nil, false, nil
	}
	out, err := vfs.zipBytes()
	if err != nil {
		return nil, false, errors.Annotate(err, "rebuilding patched charm zip")
	}
	return out, true, nil
}

// virtualFS holds an in-memory snapshot of a charm zip's regular files keyed
// by their zip entry path (forward-slash separated, no leading slash).
type virtualFS struct {
	files   map[string][]byte
	changed bool
}

// newVirtualFS reads all regular files from zr into a new virtualFS.
func newVirtualFS(zr *zip.Reader) (*virtualFS, error) {
	vfs := &virtualFS{files: make(map[string][]byte)}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, errors.Annotatef(err, "opening %q", f.Name)
		}
		data, readErr := io.ReadAll(rc)
		rc.Close()
		if readErr != nil {
			return nil, errors.Annotatef(readErr, "reading %q", f.Name)
		}
		vfs.files[f.Name] = data
	}
	return vfs, nil
}

// zipBytes serialises the virtual FS back to a zip archive. Entries are
// written in sorted path order for deterministic output.
func (vfs *virtualFS) zipBytes() ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	paths := make([]string, 0, len(vfs.files))
	for p := range vfs.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		w, err := zw.Create(p)
		if err != nil {
			return nil, errors.Annotatef(err, "creating zip entry %q", p)
		}
		if _, err := w.Write(vfs.files[p]); err != nil {
			return nil, errors.Annotatef(err, "writing zip entry %q", p)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, errors.Annotate(err, "closing zip writer")
	}
	return buf.Bytes(), nil
}

// cleanPath normalises a Starlark-supplied path to forward-slash form with no
// leading slash, suitable for use as a zip entry key.
func cleanPath(p string) string {
	cleaned := path.Clean(strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "/"))
	if cleaned == "." {
		return ""
	}
	return cleaned
}

// validateCharmPath returns an error when p would traverse outside the charm
// root (e.g. path traversal via "..").
func validateCharmPath(p string) error {
	if p == "" || p == ".." || strings.HasPrefix(p, "../") {
		return fmt.Errorf("invalid charm path %q", p)
	}
	return nil
}
