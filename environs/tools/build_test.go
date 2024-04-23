// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package tools_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	exttest "github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/version/v2"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/core/arch"
	coreos "github.com/juju/juju/core/os"
	"github.com/juju/juju/environs/tools"
	"github.com/juju/juju/testing"
)

type buildSuite struct {
	testing.BaseSuite
	restore  func()
	cwd      string
	filePath string
	exttest.PatchExecHelper
}

var _ = gc.Suite(&buildSuite{})

func (b *buildSuite) SetUpTest(c *gc.C) {
	b.BaseSuite.SetUpTest(c)
	dir1 := c.MkDir()
	dir2 := c.MkDir()

	// Ensure we don't look in the real /usr/lib/juju for jujud-versions.yaml.
	b.PatchValue(&tools.VersionFileFallbackDir, c.MkDir())

	c.Log(dir1)
	c.Log(dir2)

	path := os.Getenv("PATH")
	os.Setenv("PATH", strings.Join([]string{dir1, dir2, path}, string(filepath.ListSeparator)))

	// Make an executable file called "juju-test" in dir2.
	b.filePath = filepath.Join(dir2, "juju-test")
	err := os.WriteFile(
		b.filePath,
		[]byte("doesn't matter, we don't execute it"),
		0755)
	c.Assert(err, jc.ErrorIsNil)

	cwd, err := os.Getwd()
	c.Assert(err, jc.ErrorIsNil)

	b.cwd = c.MkDir()
	err = os.Chdir(b.cwd)
	c.Assert(err, jc.ErrorIsNil)

	b.restore = func() {
		os.Setenv("PATH", path)
		os.Chdir(cwd)
	}
}

func (b *buildSuite) TearDownTest(c *gc.C) {
	b.restore()
	b.BaseSuite.TearDownTest(c)
}

func (b *buildSuite) TestFindExecutable(c *gc.C) {
	for _, test := range []struct {
		execFile   string
		expected   string
		errorMatch string
	}{{
		execFile: filepath.Join("/", "some", "absolute", "path"),
		expected: filepath.Join("/", "some", "absolute", "path"),
	}, {
		execFile: "./foo",
		expected: filepath.Join(b.cwd, "foo"),
	}, {
		execFile: "juju-test",
		expected: b.filePath,
	}, {
		execFile:   "non-existent-exec-file",
		errorMatch: `could not find "non-existent-exec-file" in the path`,
	}} {
		result, err := tools.FindExecutable(test.execFile)
		if test.errorMatch == "" {
			c.Assert(err, jc.ErrorIsNil)
			c.Assert(result, gc.Equals, test.expected)
		} else {
			c.Assert(err, gc.ErrorMatches, test.errorMatch)
			c.Assert(result, gc.Equals, "")
		}
	}
}

func (b *buildSuite) TestEmptyArchive(c *gc.C) {
	var buf bytes.Buffer
	dir := c.MkDir()
	err := tools.Archive(&buf, dir)
	c.Assert(err, jc.ErrorIsNil)

	gzr, err := gzip.NewReader(&buf)
	c.Assert(err, jc.ErrorIsNil)
	r := tar.NewReader(gzr)
	_, err = r.Next()
	c.Assert(err, gc.Equals, io.EOF)
}

func (b *buildSuite) TestArchiveAndSHA256(c *gc.C) {
	var buf bytes.Buffer
	dir := c.MkDir()
	sha256hash, err := tools.ArchiveAndSHA256(&buf, dir)
	c.Assert(err, jc.ErrorIsNil)

	h := sha256.New()
	h.Write(buf.Bytes())
	c.Assert(sha256hash, gc.Equals, fmt.Sprintf("%x", h.Sum(nil)))

	gzr, err := gzip.NewReader(&buf)
	c.Assert(err, jc.ErrorIsNil)
	r := tar.NewReader(gzr)
	_, err = r.Next()
	c.Assert(err, gc.Equals, io.EOF)
}

func (b *buildSuite) setUpFakeBinaries(c *gc.C, versionFile string) string {
	dir := c.MkDir()
	err := os.WriteFile(filepath.Join(dir, "juju"), []byte("some data"), 0755)
	c.Assert(err, jc.ErrorIsNil)
	err = os.WriteFile(filepath.Join(dir, "jujuc"), []byte(fakeBinary), 0755)
	c.Assert(err, jc.ErrorIsNil)
	err = os.WriteFile(filepath.Join(dir, "jujud"), []byte(fakeBinary), 0755)
	c.Assert(err, jc.ErrorIsNil)
	if versionFile != "" {
		err = os.WriteFile(filepath.Join(dir, "jujud-versions.yaml"), []byte(versionFile), 0755)
		c.Assert(err, jc.ErrorIsNil)
	}

	// Mock out args[0] so that copyExistingJujus can find our fake
	// binary. Tricky - we need to copy the test binary into the
	// directory so patching out exec can work.
	oldArg0 := os.Args[0]
	testBinary := filepath.Join(dir, "tst")
	os.Args[0] = testBinary
	err = os.Link(oldArg0, testBinary)
	if _, ok := err.(*os.LinkError); ok {
		// Soft link when cross device.
		err = os.Symlink(oldArg0, testBinary)
	}
	c.Assert(err, jc.ErrorIsNil)
	b.AddCleanup(func(c *gc.C) {
		os.Args[0] = oldArg0
	})
	return dir
}

func (b *buildSuite) TestBundleToolsMatchesBinaryUsingOsTypeArch(c *gc.C) {
	thisArch := arch.HostArch()
	thisHost := coreos.HostOSTypeName()
	b.patchExecCommand(c, thisHost, thisArch)
	dir := b.setUpFakeBinaries(c, "")

	bundleFile, err := os.Create(filepath.Join(dir, "bundle"))
	c.Assert(err, jc.ErrorIsNil)

	resultVersion, forceVersion, official, _, err := tools.BundleTools(false, bundleFile,
		func(localBinaryVersion version.Number) version.Number { return version.MustParse("1.2.3.1") },
	)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(resultVersion.String(), gc.Equals, fmt.Sprintf("1.2.3-%s-%s", thisHost, thisArch))
	c.Assert(forceVersion, gc.Equals, version.MustParse("1.2.3.1"))
	c.Assert(official, jc.IsFalse)
}

func (b *buildSuite) TestJujudVersion(c *gc.C) {
	b.patchExecCommand(c, "", "")
	dir := b.setUpFakeBinaries(c, "")

	resultVersion, official, err := tools.JujudVersion(dir)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(resultVersion.String(), gc.Equals, "1.2.3-ubuntu-amd64")
	c.Assert(official, jc.IsFalse)
}

func (b *buildSuite) TestBundleToolsWithNoVersionFile(c *gc.C) {
	b.patchExecCommand(c, "", "")
	dir := b.setUpFakeBinaries(c, "")
	bundleFile, err := os.Create(filepath.Join(dir, "bundle"))
	c.Assert(err, jc.ErrorIsNil)

	resultVersion, forceVersion, official, sha, err := tools.BundleTools(false, bundleFile,
		func(localBinaryVersion version.Number) version.Number { return version.MustParse("1.2.3.1") },
	)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(resultVersion.String(), gc.Equals, "1.2.3-ubuntu-amd64")
	c.Assert(forceVersion, gc.Equals, version.MustParse("1.2.3.1"))
	c.Assert(sha, gc.Not(gc.Equals), "")
	c.Assert(official, jc.IsFalse)
}

func (b *buildSuite) TestBundleToolsFailForOfficialBuildWithBuildAgent(c *gc.C) {
	b.patchExecCommand(c, "", "")
	dir := b.setUpFakeBinaries(c, "")
	bundleFile, err := os.Create(filepath.Join(dir, "bundle"))
	c.Assert(err, jc.ErrorIsNil)

	jujudVersion := func(dir string) (version.Binary, bool, error) {
		return version.Binary{}, true, nil
	}

	_, _, official, _, err := tools.BundleToolsForTest(true, bundleFile,
		func(localBinaryVersion version.Number) version.Number { return version.MustParse("1.2.3.1") },
		jujudVersion)
	c.Assert(err, gc.ErrorMatches, `cannot build agent for official build`)
	c.Assert(official, jc.IsTrue)
}

const (
	fakeBinary = "some binary content\n"
)
