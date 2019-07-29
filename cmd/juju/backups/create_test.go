// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package backups_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/juju/cmd.v2"
	"gopkg.in/juju/cmd.v2/cmdtesting"
	"github.com/juju/errors"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/cmd/juju/backups"
)

type createSuite struct {
	BaseBackupsSuite
	wrappedCommand  cmd.Command
	command         *backups.CreateCommand
	defaultFilename string
}

var _ = gc.Suite(&createSuite{})

func (s *createSuite) SetUpTest(c *gc.C) {
	s.BaseBackupsSuite.SetUpTest(c)
	s.wrappedCommand, s.command = backups.NewCreateCommandForTest(s.store)
	s.defaultFilename = "juju-backup-<date>-<time>.tar.gz"
}

func (s *createSuite) TearDownTest(c *gc.C) {
	// We do not need to cater here for s.BaseBackupsSuite.filename as it will be deleted by the base suite.
	// However, in situations where s.command.Filename is defined, we want to remove it as well.
	if s.command.Filename != backups.NotSet && s.command.Filename != s.filename {
		err := os.Remove(s.command.Filename)
		c.Assert(err, jc.ErrorIsNil)
	}
	s.BaseBackupsSuite.TearDownTest(c)
}

func (s *createSuite) setSuccess() *fakeAPIClient {
	client := &fakeAPIClient{metaresult: s.metaresult}
	s.patchGetAPI(client)
	return client
}

func (s *createSuite) setFailure(failure string) *fakeAPIClient {
	client := &fakeAPIClient{err: errors.New(failure)}
	s.patchGetAPI(client)
	return client
}

func (s *createSuite) setDownload() *fakeAPIClient {
	client := s.setSuccess()
	client.archive = ioutil.NopCloser(bytes.NewBufferString(s.data))
	return client
}

func (s *createSuite) checkDownloadStd(c *gc.C, ctx *cmd.Context) {
	c.Check(cmdtesting.Stdout(ctx), gc.Equals, MetaResultString)

	out := cmdtesting.Stderr(ctx)
	parts := strings.Split(out, "\n")
	c.Assert(parts, gc.HasLen, 3)
	if s.command.KeepCopy {
		c.Check(parts[0], gc.Equals, fmt.Sprintf("Remote backup stored on the controller as %v.", s.metaresult.ID))
	} else {
		c.Check(parts[0], gc.Equals, "Remote backup was not created.")
	}

	// Check the download message.
	parts = strings.Split(parts[1], "Downloaded to ")
	c.Assert(parts, gc.HasLen, 2)
	c.Assert(parts[0], gc.Equals, "")
	s.filename = parts[1][:len(parts[1])-1]
}

func (s *createSuite) checkDownload(c *gc.C, ctx *cmd.Context) {
	s.checkDownloadStd(c, ctx)
	s.checkArchive(c)
}

type createBackupArgParsing struct {
	title      string
	args       []string
	errMatch   string
	filename   string
	keepCopy   bool
	noDownload bool
	notes      string
}

var testCreateBackupArgParsing = []createBackupArgParsing{
	{
		title:      "no args",
		args:       []string{},
		filename:   backups.NotSet,
		keepCopy:   false,
		noDownload: false,
		notes:      "",
	},
	{
		title:      "filename",
		args:       []string{"--filename", "testname"},
		filename:   "testname",
		keepCopy:   false,
		noDownload: false,
		notes:      "",
	},
	{
		title:      "filename flag, no name",
		args:       []string{"--filename"},
		errMatch:   "option needs an argument: --filename",
		filename:   backups.NotSet,
		keepCopy:   false,
		noDownload: false,
		notes:      "",
	},
	{
		title:      "filename && no-download",
		args:       []string{"--filename", "testname", "--no-download"},
		errMatch:   "cannot mix --no-download and --filename",
		filename:   backups.NotSet,
		keepCopy:   false,
		noDownload: false,
		notes:      "",
	},
	{
		title:      "keep-copy",
		args:       []string{"--keep-copy"},
		errMatch:   "",
		filename:   backups.NotSet,
		keepCopy:   true,
		noDownload: false,
		notes:      "",
	},
	{
		title:      "notes",
		args:       []string{"note for the backup"},
		errMatch:   "",
		filename:   backups.NotSet,
		keepCopy:   false,
		noDownload: false,
		notes:      "note for the backup",
	},
}

func (s *createSuite) TestArgParsing(c *gc.C) {
	for i, test := range testCreateBackupArgParsing {
		c.Logf("%d: %s", i, test.title)
		err := cmdtesting.InitCommand(s.wrappedCommand, test.args)
		if test.errMatch == "" {
			c.Assert(err, jc.ErrorIsNil)
			c.Assert(s.command.Filename, gc.Equals, test.filename)
			c.Assert(s.command.KeepCopy, gc.Equals, test.keepCopy)
			c.Assert(s.command.NoDownload, gc.Equals, test.noDownload)
			c.Assert(s.command.Notes, gc.Equals, test.notes)
		} else {
			c.Assert(err, gc.ErrorMatches, test.errMatch)
		}
	}
}

func (s *createSuite) TestDefault(c *gc.C) {
	client := s.setDownload()
	ctx, err := cmdtesting.RunCommand(c, s.wrappedCommand)
	c.Assert(err, jc.ErrorIsNil)

	client.CheckCalls(c, "Create", "Download")
	client.CheckArgs(c, "", "false", "false", "filename")
	s.checkDownload(c, ctx)
	c.Check(s.command.Filename, gc.Equals, backups.NotSet)
}

func (s *createSuite) TestDefaultV1(c *gc.C) {
	s.apiVersion = 1
	client := s.setDownload()
	ctx, err := cmdtesting.RunCommand(c, s.wrappedCommand)
	c.Assert(err, jc.ErrorIsNil)

	client.CheckCalls(c, "Create", "Download")
	client.CheckArgs(c, "", "true", "false", "spam")
	c.Assert(s.command.KeepCopy, jc.IsTrue)
	s.checkDownload(c, ctx)
	c.Check(s.command.Filename, gc.Equals, backups.NotSet)
}

func (s *createSuite) TestDefaultQuiet(c *gc.C) {
	client := s.setDownload()
	ctx, err := cmdtesting.RunCommand(c, s.wrappedCommand, "--quiet")
	c.Assert(err, jc.ErrorIsNil)

	client.CheckCalls(c, "Create", "Download")
	client.CheckArgs(c, "", "false", "false", "filename")

	c.Check(ctx.Stderr.(*bytes.Buffer).String(), gc.Equals, "")
	c.Check(ctx.Stdout.(*bytes.Buffer).String(), gc.Equals, "")
}

func (s *createSuite) TestNotes(c *gc.C) {
	client := s.setDownload()
	ctx, err := cmdtesting.RunCommand(c, s.wrappedCommand, "test notes")
	c.Assert(err, jc.ErrorIsNil)

	client.CheckCalls(c, "Create", "Download")
	client.CheckArgs(c, "test notes", "false", "false", "filename")
	s.checkDownload(c, ctx)
}

func (s *createSuite) TestFilename(c *gc.C) {
	client := s.setDownload()
	ctx, err := cmdtesting.RunCommand(c, s.wrappedCommand, "--filename", "backup.tgz")
	c.Assert(err, jc.ErrorIsNil)

	client.CheckCalls(c, "Create", "Download")
	client.CheckArgs(c, "", "false", "false", "filename")
	s.checkDownload(c, ctx)
	c.Check(s.command.Filename, gc.Equals, "backup.tgz")
}

func (s *createSuite) TestNoDownload(c *gc.C) {
	client := s.setSuccess()
	ctx, err := cmdtesting.RunCommand(c, s.wrappedCommand, "--no-download")
	c.Assert(err, jc.ErrorIsNil)

	client.CheckCalls(c, "Create")
	client.CheckArgs(c, "", "true", "true")
	out := MetaResultString
	expectedMsg := fmt.Sprintf("WARNING %v\nRemote backup stored on the controller as %v.\n", backups.DownloadWarning, s.metaresult.ID)
	s.checkStd(c, ctx, out, expectedMsg)
	c.Check(s.command.Filename, gc.Equals, backups.NotSet)
}

func (s *createSuite) TestKeepCopy(c *gc.C) {
	client := s.setDownload()
	ctx, err := cmdtesting.RunCommand(c, s.wrappedCommand, "--keep-copy")
	c.Assert(err, jc.ErrorIsNil)

	client.CheckCalls(c, "Create", "Download")
	client.CheckArgs(c, "", "true", "false", "filename")

	s.checkDownload(c, ctx)
}

func (s *createSuite) TestFailKeepCopyNoDownload(c *gc.C) {
	s.setDownload()
	_, err := cmdtesting.RunCommand(c, s.wrappedCommand, "--keep-copy", "--no-download")
	c.Check(err, jc.ErrorIsNil)
}

func (s *createSuite) TestFailKeepCopyFalseNoDownload(c *gc.C) {
	s.setDownload()
	_, err := cmdtesting.RunCommand(c, s.wrappedCommand, "--keep-copy=false", "--no-download")
	c.Check(err, gc.ErrorMatches, "--no-download cannot be set when --keep-copy is not: the backup will not be created")
}

func (s *createSuite) TestKeepCopyV1Fail(c *gc.C) {
	s.apiVersion = 1
	s.setDownload()
	_, err := cmdtesting.RunCommand(c, s.wrappedCommand, "--keep-copy")

	c.Assert(err, gc.ErrorMatches, "--keep-copy is not supported by this controller")
}

func (s *createSuite) TestFilenameAndNoDownload(c *gc.C) {
	s.setSuccess()
	_, err := cmdtesting.RunCommand(c, s.wrappedCommand, "--no-download", "--filename", "backup.tgz")

	c.Check(err, gc.ErrorMatches, "cannot mix --no-download and --filename")
}

func (s *createSuite) TestError(c *gc.C) {
	s.setFailure("failed!")
	_, err := cmdtesting.RunCommand(c, s.wrappedCommand)

	c.Check(errors.Cause(err), gc.ErrorMatches, "failed!")
}
