// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package upgradeseries_test

import (
	"context"

	"github.com/juju/juju/internal/charm/hooks"
	"github.com/juju/testing"
	"go.uber.org/mock/gomock"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/core/model"
	loggertesting "github.com/juju/juju/internal/logger/testing"
	"github.com/juju/juju/internal/worker/uniter/hook"
	"github.com/juju/juju/internal/worker/uniter/operation"
	"github.com/juju/juju/internal/worker/uniter/operation/mocks"
	"github.com/juju/juju/internal/worker/uniter/remotestate"
	"github.com/juju/juju/internal/worker/uniter/resolver"
	"github.com/juju/juju/internal/worker/uniter/upgradeseries"
)

type ResolverSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&ResolverSuite{})

func (ResolverSuite) NewResolver(c *gc.C) resolver.Resolver {
	logger := loggertesting.WrapCheckLog(c)
	return upgradeseries.NewResolver(logger)
}

func (s ResolverSuite) TestNextOpWithValidationStatus(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	mockFactory := mocks.NewMockFactory(ctrl)
	res := s.NewResolver(c)
	_, err := res.NextOp(context.Background(), resolver.LocalState{}, remotestate.Snapshot{
		UpgradeMachineStatus: model.UpgradeSeriesValidate,
	}, mockFactory)
	c.Assert(err, gc.Equals, resolver.ErrDoNotProceed)
}

func (s ResolverSuite) TestNextOpWithRemoveStateCompleted(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	mockFactory := mocks.NewMockFactory(ctrl)
	res := s.NewResolver(c)
	_, err := res.NextOp(context.Background(), resolver.LocalState{}, remotestate.Snapshot{
		UpgradeMachineStatus: model.UpgradeSeriesPrepareCompleted,
	}, mockFactory)
	c.Assert(err, gc.Equals, resolver.ErrDoNotProceed)
}

func (s ResolverSuite) TestNextOpWithPreSeriesUpgrade(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	mockOp := mocks.NewMockOperation(ctrl)

	mockFactory := mocks.NewMockFactory(ctrl)
	mockFactory.EXPECT().NewRunHook(hook.Info{Kind: hooks.PreSeriesUpgrade}).Return(mockOp, nil)

	res := s.NewResolver(c)
	op, err := res.NextOp(context.Background(), resolver.LocalState{
		State: operation.State{
			Kind: operation.Continue,
		},
		UpgradeMachineStatus: model.UpgradeSeriesNotStarted,
	}, remotestate.Snapshot{
		UpgradeMachineStatus: model.UpgradeSeriesPrepareStarted,
	}, mockFactory)
	c.Assert(err, gc.IsNil)
	c.Assert(op, gc.NotNil)
}

func (s ResolverSuite) TestNextOpWithPostSeriesUpgrade(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	mockOp := mocks.NewMockOperation(ctrl)

	mockFactory := mocks.NewMockFactory(ctrl)
	mockFactory.EXPECT().NewRunHook(hook.Info{Kind: hooks.PostSeriesUpgrade}).Return(mockOp, nil)

	res := s.NewResolver(c)
	op, err := res.NextOp(context.Background(), resolver.LocalState{
		State: operation.State{
			Kind: operation.Continue,
		},
		UpgradeMachineStatus: model.UpgradeSeriesNotStarted,
	}, remotestate.Snapshot{
		UpgradeMachineStatus: model.UpgradeSeriesCompleteStarted,
	}, mockFactory)
	c.Assert(err, gc.IsNil)
	c.Assert(op, gc.NotNil)
}

func (s ResolverSuite) TestNextOpWithFinishUpgradeSeries(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	mockOp := mocks.NewMockOperation(ctrl)

	mockFactory := mocks.NewMockFactory(ctrl)
	mockFactory.EXPECT().NewNoOpFinishUpgradeSeries().Return(mockOp, nil)

	res := s.NewResolver(c)
	op, err := res.NextOp(context.Background(), resolver.LocalState{
		State: operation.State{
			Kind: operation.Continue,
		},
		UpgradeMachineStatus: model.UpgradeSeriesCompleted,
	}, remotestate.Snapshot{
		UpgradeMachineStatus: model.UpgradeSeriesNotStarted,
	}, mockFactory)
	c.Assert(err, gc.IsNil)
	c.Assert(op, gc.NotNil)
}

func (s ResolverSuite) TestNextOpWithNoState(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	mockFactory := mocks.NewMockFactory(ctrl)

	res := s.NewResolver(c)
	_, err := res.NextOp(context.Background(), resolver.LocalState{}, remotestate.Snapshot{}, mockFactory)
	c.Assert(err, gc.Equals, resolver.ErrNoOperation)
}
