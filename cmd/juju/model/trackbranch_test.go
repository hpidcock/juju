// Copyright 2019 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package model_test

import (
	"github.com/golang/mock/gomock"
	"gopkg.in/juju/cmd.v2"
	"gopkg.in/juju/cmd.v2/cmdtesting"
	"github.com/juju/errors"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/cmd/juju/model"
	"github.com/juju/juju/cmd/juju/model/mocks"
	coremodel "github.com/juju/juju/core/model"
	"github.com/juju/juju/jujuclient"
	"github.com/juju/juju/testing"
)

type trackBranchSuite struct {
	generationBaseSuite
}

var _ = gc.Suite(&trackBranchSuite{})

func (s *trackBranchSuite) SetUpTest(c *gc.C) {
	s.generationBaseSuite.SetUpTest(c)

	// Update the local store to indicate we are on the "new-branch" branch.
	c.Assert(s.store.UpdateModel("testing", "admin/mymodel", jujuclient.ModelDetails{
		ModelUUID:    testing.ModelTag.Id(),
		ModelType:    coremodel.IAAS,
		ActiveBranch: s.branchName,
	}), jc.ErrorIsNil)
}

func (s *trackBranchSuite) TestInitApplication(c *gc.C) {
	err := s.runInit(s.branchName, "ubuntu")
	c.Assert(err, jc.ErrorIsNil)
}

func (s *trackBranchSuite) TestInitUnit(c *gc.C) {
	err := s.runInit(s.branchName, "ubuntu/0")
	c.Assert(err, jc.ErrorIsNil)
}

func (s *trackBranchSuite) TestInitEmpty(c *gc.C) {
	err := s.runInit()
	c.Assert(err, gc.ErrorMatches, `expected a branch name plus unit and/or application names\(s\)`)
}

func (s *trackBranchSuite) TestInitInvalid(c *gc.C) {
	err := s.runInit(s.branchName, "test me")
	c.Assert(err, gc.ErrorMatches, `invalid application or unit name "test me"`)
}

func (s *trackBranchSuite) TestRunCommand(c *gc.C) {
	mockController, api := setUpAdvanceMocks(c)
	defer mockController.Finish()

	api.EXPECT().TrackBranch(s.branchName, []string{"ubuntu/0", "redis"}).Return(nil)

	_, err := s.runCommand(c, api, s.branchName, "ubuntu/0", "redis")
	c.Assert(err, jc.ErrorIsNil)
}

func (s *trackBranchSuite) TestRunCommandFail(c *gc.C) {
	ctrl, api := setUpAdvanceMocks(c)
	defer ctrl.Finish()

	api.EXPECT().TrackBranch(s.branchName, []string{"ubuntu/0"}).Return(errors.Errorf("fail"))

	_, err := s.runCommand(c, api, s.branchName, "ubuntu/0")
	c.Assert(err, gc.ErrorMatches, "fail")
}

func (s *trackBranchSuite) runInit(args ...string) error {
	return cmdtesting.InitCommand(model.NewTrackBranchCommandForTest(nil, s.store), args)
}

func (s *trackBranchSuite) runCommand(c *gc.C, api model.TrackBranchCommandAPI, args ...string) (*cmd.Context, error) {
	return cmdtesting.RunCommand(c, model.NewTrackBranchCommandForTest(api, s.store), args...)
}

func setUpAdvanceMocks(c *gc.C) (*gomock.Controller, *mocks.MockTrackBranchCommandAPI) {
	ctrl := gomock.NewController(c)
	api := mocks.NewMockTrackBranchCommandAPI(ctrl)
	api.EXPECT().Close()
	return ctrl, api
}
