// Copyright 2019 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package apiserver_test

import (
	"github.com/juju/clock"
	"github.com/juju/loggo"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/worker/v3/workertest"
	"github.com/prometheus/client_golang/prometheus"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/api"
	"github.com/juju/juju/apiserver"
	"github.com/juju/juju/apiserver/testserver"
	"github.com/juju/juju/state"
	statetesting "github.com/juju/juju/state/testing"
	"github.com/juju/juju/worker/multiwatcher"
)

type baseSuite struct {
	statetesting.StateSuite

	cfg apiserver.ServerConfig
}

func (s *baseSuite) SetUpTest(c *gc.C) {
	s.StateSuite.SetUpTest(c)
	loggo.GetLogger("juju.apiserver").SetLogLevel(loggo.TRACE)

	allWatcherBacking, err := state.NewAllWatcherBacking(s.StatePool)
	c.Assert(err, jc.ErrorIsNil)
	multiWatcherWorker, err := multiwatcher.NewWorker(multiwatcher.Config{
		Clock:                clock.WallClock,
		Logger:               loggo.GetLogger("test"),
		Backing:              allWatcherBacking,
		PrometheusRegisterer: noopRegisterer{},
	})
	c.Assert(err, jc.ErrorIsNil)
	// The worker itself is a coremultiwatcher.Factory.
	s.AddCleanup(func(c *gc.C) { workertest.CleanKill(c, multiWatcherWorker) })

	s.cfg = testserver.DefaultServerConfig(c, s.Clock)
}

func (s *baseSuite) newServer(c *gc.C) *api.Info {
	server := testserver.NewServerWithConfig(c, s.StatePool, s.cfg)
	s.AddCleanup(func(c *gc.C) {
		workertest.CleanKill(c, server.APIServer)
		server.HTTPServer.Close()
	})
	server.Info.ModelTag = s.Model.ModelTag()
	return server.Info
}

func (s *baseSuite) openAPIWithoutLogin(c *gc.C, info0 *api.Info) api.Connection {
	info := *info0
	info.Tag = nil
	info.Password = ""
	info.SkipLogin = true
	info.Macaroons = nil
	st, err := api.Open(&info, fastDialOpts)
	c.Assert(err, jc.ErrorIsNil)
	s.AddCleanup(func(*gc.C) { _ = st.Close() })
	return st
}

// derivedSuite is just here to test newServer is clean.
type derivedSuite struct {
	baseSuite
}

var _ = gc.Suite(&derivedSuite{})

func (s *derivedSuite) TestNewServer(c *gc.C) {
	_ = s.newServer(c)
}

type noopRegisterer struct {
	prometheus.Registerer
}

func (noopRegisterer) Register(prometheus.Collector) error {
	return nil
}

func (noopRegisterer) Unregister(prometheus.Collector) bool {
	return true
}
