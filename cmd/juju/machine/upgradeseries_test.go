// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package machine_test

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/golang/mock/gomock"
	"gopkg.in/juju/cmd.v2"
	"gopkg.in/juju/cmd.v2/cmdtesting"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/cmd/juju/machine"
	"github.com/juju/juju/cmd/juju/machine/mocks"
	"github.com/juju/juju/testing"
)

type UpgradeSeriesSuite struct {
	testing.BaseSuite

	prepareExpectation  *upgradeSeriesPrepareExpectation
	completeExpectation *upgradeSeriesCompleteExpectation
}

var _ = gc.Suite(&UpgradeSeriesSuite{})

func (s *UpgradeSeriesSuite) SetUpTest(c *gc.C) {
	s.BaseSuite.SetUpTest(c)
	s.prepareExpectation = &upgradeSeriesPrepareExpectation{gomock.Any(), gomock.Any(), gomock.Any()}
	s.completeExpectation = &upgradeSeriesCompleteExpectation{gomock.Any()}
}

const machineArg = "1"
const seriesArg = "xenial"

var units = []string{"bar/0", "foo/0"}

func (s *UpgradeSeriesSuite) runUpgradeSeriesCommand(c *gc.C, args ...string) error {
	_, err := s.runUpgradeSeriesCommandWithConfirmation(c, "y", args...)
	return err
}

func (s *UpgradeSeriesSuite) runUpgradeSeriesCommandWithConfirmation(
	c *gc.C, confirmation string, args ...string,
) (*cmd.Context, error) {
	var stdin, stdout, stderr bytes.Buffer
	ctx, err := cmd.DefaultContext()
	c.Assert(err, jc.ErrorIsNil)
	ctx.Stderr = &stderr
	ctx.Stdout = &stdout
	ctx.Stdin = &stdin
	stdin.WriteString(confirmation)

	mockController := gomock.NewController(c)
	defer mockController.Finish()

	mockUpgradeSeriesAPI := mocks.NewMockUpgradeMachineSeriesAPI(mockController)

	uExp := mockUpgradeSeriesAPI.EXPECT()
	prep := s.prepareExpectation
	uExp.UpgradeSeriesValidate(prep.machineArg, prep.seriesArg).AnyTimes().Return(units, nil)
	uExp.UpgradeSeriesPrepare(prep.machineArg, prep.seriesArg, prep.force).AnyTimes()
	uExp.UpgradeSeriesComplete(s.completeExpectation.machineNumber).AnyTimes()

	com := machine.NewUpgradeSeriesCommandForTest(mockUpgradeSeriesAPI)

	err = cmdtesting.InitCommand(com, args)
	if err != nil {
		return nil, err
	}
	err = com.Run(ctx)
	if err != nil {
		return nil, err
	}
	return ctx, nil
}

func (s *UpgradeSeriesSuite) TestPrepareCommand(c *gc.C) {
	s.prepareExpectation = &upgradeSeriesPrepareExpectation{machineArg, seriesArg, gomock.Eq(false)}
	err := s.runUpgradeSeriesCommand(c, machineArg, machine.PrepareCommand, seriesArg)
	c.Assert(err, jc.ErrorIsNil)
}

func (s *UpgradeSeriesSuite) TestTooFewArgs(c *gc.C) {
	err := s.runUpgradeSeriesCommand(c, machineArg)
	c.Assert(err, gc.ErrorMatches, "wrong number of arguments")
}

func (s *UpgradeSeriesSuite) TestPrepareCommandShouldAcceptForceOption(c *gc.C) {
	s.prepareExpectation = &upgradeSeriesPrepareExpectation{machineArg, seriesArg, gomock.Eq(true)}
	err := s.runUpgradeSeriesCommand(c, machineArg, machine.PrepareCommand, seriesArg, "--force")
	c.Assert(err, jc.ErrorIsNil)
}

func (s *UpgradeSeriesSuite) TestPrepareCommandShouldAbortOnFailedConfirmation(c *gc.C) {
	_, err := s.runUpgradeSeriesCommandWithConfirmation(c, "n", machineArg, machine.PrepareCommand, seriesArg)
	c.Assert(err, gc.ErrorMatches, "upgrade series: aborted")
}

func (s *UpgradeSeriesSuite) TestUpgradeCommandShouldNotAcceptInvalidPrepCommands(c *gc.C) {
	invalidPrepCommand := "actuate"
	err := s.runUpgradeSeriesCommand(c, machineArg, invalidPrepCommand, seriesArg)
	c.Assert(err, gc.ErrorMatches,
		".* \"actuate\" is an invalid upgrade-series command; valid commands are: prepare, complete.")
}

func (s *UpgradeSeriesSuite) TestUpgradeCommandShouldNotAcceptInvalidMachineArgs(c *gc.C) {
	invalidMachineArg := "machine5"
	err := s.runUpgradeSeriesCommand(c, invalidMachineArg, machine.PrepareCommand, seriesArg)
	c.Assert(err, gc.ErrorMatches, "\"machine5\" is an invalid machine name")
}

func (s *UpgradeSeriesSuite) TestPrepareCommandShouldOnlyAcceptSupportedSeries(c *gc.C) {
	BadSeries := "Combative Caribou"
	err := s.runUpgradeSeriesCommand(c, machineArg, machine.PrepareCommand, BadSeries)
	c.Assert(err, gc.ErrorMatches, ".* is an unsupported series")
}

func (s *UpgradeSeriesSuite) TestPrepareCommandShouldSupportSeriesRegardlessOfCase(c *gc.C) {
	capitalizedCaseXenial := "Xenial"
	err := s.runUpgradeSeriesCommand(c, machineArg, machine.PrepareCommand, capitalizedCaseXenial)
	c.Assert(err, jc.ErrorIsNil)
}

func (s *UpgradeSeriesSuite) TestCompleteCommand(c *gc.C) {
	s.completeExpectation.machineNumber = machineArg
	err := s.runUpgradeSeriesCommand(c, machineArg, machine.CompleteCommand)
	c.Assert(err, jc.ErrorIsNil)
}

func (s *UpgradeSeriesSuite) TestCompleteCommandDoesNotAcceptSeries(c *gc.C) {
	err := s.runUpgradeSeriesCommand(c, machineArg, machine.CompleteCommand, seriesArg)
	c.Assert(err, gc.ErrorMatches, "wrong number of arguments")
}

func (s *UpgradeSeriesSuite) TestPrepareCommandShouldAcceptYes(c *gc.C) {
	err := s.runUpgradeSeriesCommand(c, machineArg, machine.PrepareCommand, seriesArg, "--yes")
	c.Assert(err, jc.ErrorIsNil)
}

func (s *UpgradeSeriesSuite) TestPrepareCommandShouldAcceptYesAbbreviation(c *gc.C) {
	err := s.runUpgradeSeriesCommand(c, machineArg, machine.PrepareCommand, seriesArg, "-y")
	c.Assert(err, jc.ErrorIsNil)
}

func (s *UpgradeSeriesSuite) TestPrepareCommandShouldPromptUserForConfirmation(c *gc.C) {
	ctx, err := s.runUpgradeSeriesCommandWithConfirmation(c, "y", machineArg, machine.PrepareCommand, seriesArg)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(ctx.Stdout.(*bytes.Buffer).String(), jc.HasSuffix, "Continue [y/N]?")
}

func (s *UpgradeSeriesSuite) TestPrepareCommandShouldAcceptYesFlagAndNotPrompt(c *gc.C) {
	ctx, err := s.runUpgradeSeriesCommandWithConfirmation(c, "n", machineArg, machine.PrepareCommand, seriesArg, "-y")
	c.Assert(err, jc.ErrorIsNil)

	//There is no confirmation message since the `-y/--yes` flag is being used to avoid the prompt.
	confirmationMessage := ""

	finishedMessage := fmt.Sprintf(machine.UpgradeSeriesPrepareFinishedMessage, machineArg)
	displayedMessage := strings.Join([]string{confirmationMessage, finishedMessage}, "") + "\n"
	out := ctx.Stderr.(*bytes.Buffer).String()
	c.Assert(out, gc.Equals, displayedMessage)
	c.Assert(out, jc.Contains, fmt.Sprintf("juju upgrade-series %s complete", machineArg))
}

type upgradeSeriesPrepareExpectation struct {
	machineArg, seriesArg, force interface{}
}

type upgradeSeriesCompleteExpectation struct {
	machineNumber interface{}
}
