// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package patcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/canonical/starlark/starlark"
	"github.com/canonical/starlark/syntax"
	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/juju/juju/core/logger"
)

// runScript executes a single Starlark patch script against vfs. The script
// runs in a sandboxed environment with no access to the host filesystem and
// no ability to load external modules. All output from the Starlark print()
// builtin is forwarded to the Juju logger.
//
// The following names are predeclared for each script:
//
//   - charm_url  (str)  – the charm URL being deployed
//   - charm_read, charm_write, charm_delete, charm_list, charm_exists – charm file ops
//   - patch_read, patch_exists, patch_list – read-only access to the patch zip
//   - sha256, diff, patch – utility functions
//   - log – logging helper
func runScript(
	ctx context.Context,
	name, src, charmURL string,
	vfs *virtualFS,
	patchVFS *virtualFS,
	log logger.Logger,
) error {
	thread := &starlark.Thread{
		Name: name,
		Print: func(_ *starlark.Thread, msg string) {
			log.Infof(ctx, "charm patch script %q: %s", name, msg)
		},
		Load: func(_ *starlark.Thread, module string) (starlark.StringDict, error) {
			return nil, fmt.Errorf("load(%q): module loading is not permitted in charm patch scripts", module)
		},
	}
	thread.SetParentContext(ctx)

	predeclared := starlark.StringDict{
		"charm_url":    starlark.String(charmURL),
		"charm_read":   starlark.NewBuiltinWithSafety("charm_read", starlark.IOSafe, makeCharmRead(vfs)),
		"charm_write":  starlark.NewBuiltinWithSafety("charm_write", starlark.IOSafe, makeCharmWrite(vfs)),
		"charm_delete": starlark.NewBuiltinWithSafety("charm_delete", starlark.IOSafe, makeCharmDelete(vfs)),
		"charm_list":   starlark.NewBuiltinWithSafety("charm_list", starlark.IOSafe, makeCharmList(vfs)),
		"charm_exists": starlark.NewBuiltinWithSafety("charm_exists", starlark.IOSafe, makeCharmExists(vfs)),
		"patch_read":   starlark.NewBuiltinWithSafety("patch_read", starlark.IOSafe, makePatchRead(patchVFS)),
		"patch_exists": starlark.NewBuiltinWithSafety("patch_exists", starlark.IOSafe, makePatchExists(patchVFS)),
		"patch_list":   starlark.NewBuiltinWithSafety("patch_list", starlark.IOSafe, makePatchList(patchVFS)),
		"sha256":       starlark.NewBuiltinWithSafety("sha256", starlark.IOSafe, builtinSHA256),
		"diff":         starlark.NewBuiltinWithSafety("diff", starlark.IOSafe, builtinDiff),
		"patch":        starlark.NewBuiltinWithSafety("patch", starlark.IOSafe, builtinPatch),
		"log":          starlark.NewBuiltinWithSafety("log", starlark.IOSafe, makeLog(ctx, name, log)),
	}

	opts := &syntax.FileOptions{
		TopLevelControl: true,
	}
	_, err := starlark.ExecFileOptions(opts, thread, name, src, predeclared)
	return err
}

// makeCharmRead returns a builtin that reads a file from vfs.
//
// Starlark signature: charm_read(path) -> bytes
func makeCharmRead(vfs *virtualFS) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var p string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p); err != nil {
			return nil, err
		}
		data, ok := vfs.files[cleanPath(p)]
		if !ok {
			return nil, fmt.Errorf("charm_read: file not found: %q", p)
		}
		return starlark.Bytes(data), nil
	}
}

// makeCharmWrite returns a builtin that creates or overwrites a file in vfs.
//
// Starlark signature: charm_write(path, content)  # content: str or bytes
func makeCharmWrite(vfs *virtualFS) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var p string
		var content starlark.Value
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p, "content", &content); err != nil {
			return nil, err
		}
		cp := cleanPath(p)
		if err := validateCharmPath(cp); err != nil {
			return nil, err
		}
		var data []byte
		switch v := content.(type) {
		case starlark.Bytes:
			data = []byte(v)
		case starlark.String:
			data = []byte(string(v))
		default:
			return nil, fmt.Errorf("charm_write: content must be str or bytes, got %s", content.Type())
		}
		vfs.files[cp] = data
		vfs.changed = true
		return starlark.None, nil
	}
}

// makeCharmDelete returns a builtin that removes a file from vfs.
//
// Starlark signature: charm_delete(path)
func makeCharmDelete(vfs *virtualFS) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var p string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p); err != nil {
			return nil, err
		}
		cp := cleanPath(p)
		if _, ok := vfs.files[cp]; !ok {
			return nil, fmt.Errorf("charm_delete: file not found: %q", p)
		}
		delete(vfs.files, cp)
		vfs.changed = true
		return starlark.None, nil
	}
}

// makeCharmList returns a builtin that lists files in vfs, optionally
// filtered by a path prefix.
//
// Starlark signature: charm_list(prefix="") -> list[str]
func makeCharmList(vfs *virtualFS) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		prefix := ""
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "prefix?", &prefix); err != nil {
			return nil, err
		}
		prefix = cleanPath(prefix)

		var entries []starlark.Value
		for p := range vfs.files {
			if prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/") {
				entries = append(entries, starlark.String(p))
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			return string(entries[i].(starlark.String)) < string(entries[j].(starlark.String))
		})
		return starlark.NewList(entries), nil
	}
}

// makeCharmExists returns a builtin that reports whether a file is present
// in vfs.
//
// Starlark signature: charm_exists(path) -> bool
func makeCharmExists(vfs *virtualFS) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var p string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p); err != nil {
			return nil, err
		}
		_, ok := vfs.files[cleanPath(p)]
		return starlark.Bool(ok), nil
	}
}

// builtinSHA256 computes the hex-encoded SHA-256 digest of its argument.
//
// Starlark signature: sha256(content) -> str  # content: str or bytes
func builtinSHA256(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var content starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "content", &content); err != nil {
		return nil, err
	}
	var data []byte
	switch v := content.(type) {
	case starlark.Bytes:
		data = []byte(v)
	case starlark.String:
		data = []byte(string(v))
	default:
		return nil, fmt.Errorf("sha256: expected str or bytes, got %s", content.Type())
	}
	sum := sha256.Sum256(data)
	return starlark.String(hex.EncodeToString(sum[:])), nil
}

// builtinDiff produces a patch string (diff-match-patch format) that
// transforms old into new. The result can be applied with patch().
//
// Starlark signature: diff(old, new) -> str
func builtinDiff(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var oldText, newText string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "old", &oldText, "new", &newText); err != nil {
		return nil, err
	}
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(oldText, newText, false)
	patches := dmp.PatchMake(oldText, diffs)
	return starlark.String(dmp.PatchToText(patches)), nil
}

// builtinPatch applies a patch string produced by diff() to original and
// returns the patched text. An error is returned if any hunk fails to apply.
//
// Starlark signature: patch(original, patch_text) -> str
func builtinPatch(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var original, patchText string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "original", &original, "patch_text", &patchText); err != nil {
		return nil, err
	}
	dmp := diffmatchpatch.New()
	patches, err := dmp.PatchFromText(patchText)
	if err != nil {
		return nil, fmt.Errorf("patch: invalid patch text: %w", err)
	}
	result, applied := dmp.PatchApply(patches, original)
	for i, ok := range applied {
		if !ok {
			return nil, fmt.Errorf("patch: hunk %d did not apply", i)
		}
	}
	return starlark.String(result), nil
}

// makeLog returns a builtin that writes a message to the Juju logger at info
// level.
//
// Starlark signature: log(message)
func makeLog(ctx context.Context, scriptName string, log logger.Logger) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var msg string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "message", &msg); err != nil {
			return nil, err
		}
		log.Infof(ctx, "charm patch script %q: %s", scriptName, msg)
		return starlark.None, nil
	}
}

// makePatchRead returns a builtin that reads a file from the patch zip.
// The patch zip is read-only; use charm_write to modify the deployed charm.
//
// Starlark signature: patch_read(path) -> bytes
func makePatchRead(patchVFS *virtualFS) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var p string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p); err != nil {
			return nil, err
		}
		data, ok := patchVFS.files[cleanPath(p)]
		if !ok {
			return nil, fmt.Errorf("patch_read: file not found: %q", p)
		}
		return starlark.Bytes(data), nil
	}
}

// makePatchExists returns a builtin that reports whether a file is present
// in the patch zip.
//
// Starlark signature: patch_exists(path) -> bool
func makePatchExists(patchVFS *virtualFS) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var p string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p); err != nil {
			return nil, err
		}
		_, ok := patchVFS.files[cleanPath(p)]
		return starlark.Bool(ok), nil
	}
}

// makePatchList returns a builtin that lists files in the patch zip,
// optionally filtered by a path prefix.
//
// Starlark signature: patch_list(prefix="") -> list[str]
func makePatchList(patchVFS *virtualFS) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		prefix := ""
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "prefix?", &prefix); err != nil {
			return nil, err
		}
		prefix = cleanPath(prefix)

		var entries []starlark.Value
		for p := range patchVFS.files {
			if prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/") {
				entries = append(entries, starlark.String(p))
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			return string(entries[i].(starlark.String)) < string(entries[j].(starlark.String))
		})
		return starlark.NewList(entries), nil
	}
}
