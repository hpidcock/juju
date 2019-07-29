// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package jujuc_test

import (
	"strings"

	"gopkg.in/juju/cmd.v2"
	"gopkg.in/juju/cmd.v2/cmdtesting"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/core/network"
	"github.com/juju/juju/worker/uniter/runner/jujuc"
)

type OpenedPortsSuite struct {
	ContextSuite
}

var _ = gc.Suite(&OpenedPortsSuite{})

func (s *OpenedPortsSuite) TestRunAllFormats(c *gc.C) {
	expectedPorts := []network.PortRange{
		{10, 20, "tcp"},
		{80, 80, "tcp"},
		{53, 55, "udp"},
		{63, 63, "udp"},
	}
	network.SortPortRanges(expectedPorts)
	portsAsStrings := make([]string, len(expectedPorts))
	for i, portRange := range expectedPorts {
		portsAsStrings[i] = portRange.String()
	}
	defaultOutput := strings.Join(portsAsStrings, "\n") + "\n"
	jsonOutput := `["` + strings.Join(portsAsStrings, `","`) + `"]` + "\n"
	yamlOutput := "- " + strings.Join(portsAsStrings, "\n- ") + "\n"

	formatToOutput := map[string]string{
		"":      defaultOutput,
		"smart": defaultOutput,
		"json":  jsonOutput,
		"yaml":  yamlOutput,
	}
	for format, expectedOutput := range formatToOutput {
		hctx := s.getContextAndOpenPorts(c)
		stdout := ""
		stderr := ""
		if format == "" {
			stdout, stderr = s.runCommand(c, hctx)
		} else {
			stdout, stderr = s.runCommand(c, hctx, "--format", format)
		}
		c.Check(stdout, gc.Equals, expectedOutput)
		c.Check(stderr, gc.Equals, "")
		hctx.info.CheckPorts(c, expectedPorts)
	}
}

func (s *OpenedPortsSuite) TestBadArgs(c *gc.C) {
	hctx := s.GetHookContext(c, -1, "")
	com, err := jujuc.NewCommand(hctx, cmdString("opened-ports"))
	c.Assert(err, jc.ErrorIsNil)
	err = cmdtesting.InitCommand(jujuc.NewJujucCommandWrappedForTest(com), []string{"foo"})
	c.Assert(err, gc.ErrorMatches, `unrecognized args: \["foo"\]`)
}

func (s *OpenedPortsSuite) TestHelp(c *gc.C) {
	hctx := s.GetHookContext(c, -1, "")
	openedPorts, err := jujuc.NewCommand(hctx, cmdString("opened-ports"))
	c.Assert(err, jc.ErrorIsNil)
	flags := cmdtesting.NewFlagSet()
	c.Assert(string(openedPorts.Info().Help(flags)), gc.Equals, `
Usage: opened-ports

Summary:
lists all ports or ranges opened by the unit

Details:
Each list entry has format <port>/<protocol> (e.g. "80/tcp") or
<from>-<to>/<protocol> (e.g. "8080-8088/udp").
`[1:])
}

func (s *OpenedPortsSuite) getContextAndOpenPorts(c *gc.C) *Context {
	hctx := s.GetHookContext(c, -1, "")
	hctx.OpenPorts("tcp", 80, 80)
	hctx.OpenPorts("tcp", 10, 20)
	hctx.OpenPorts("udp", 63, 63)
	hctx.OpenPorts("udp", 53, 55)
	return hctx
}

func (s *OpenedPortsSuite) runCommand(c *gc.C, hctx *Context, args ...string) (stdout, stderr string) {
	com, err := jujuc.NewCommand(hctx, cmdString("opened-ports"))
	c.Assert(err, jc.ErrorIsNil)
	ctx := cmdtesting.Context(c)
	code := cmd.Main(jujuc.NewJujucCommandWrappedForTest(com), ctx, args)
	c.Assert(code, gc.Equals, 0)
	return bufferString(ctx.Stdout), bufferString(ctx.Stderr)
}
