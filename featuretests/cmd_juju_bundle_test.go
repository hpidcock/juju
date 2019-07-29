// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.
package featuretests

import (
	"gopkg.in/juju/cmd.v2/cmdtesting"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/cmd/juju/model"
	"github.com/juju/juju/feature"
	jujutesting "github.com/juju/juju/juju/testing"
	"github.com/juju/juju/state"
	"github.com/juju/juju/testing/factory"
)

type CmdExportBundleSuite struct {
	jujutesting.JujuConnSuite
}

func (s *CmdExportBundleSuite) setupApplications(c *gc.C) {
	s.Factory.MakeSpace(c, &factory.SpaceParams{Name: "vlan2"})
	// make an application with 2 endpoints
	application1 := s.Factory.MakeApplication(c, &factory.ApplicationParams{
		Charm: s.Factory.MakeCharm(c, &factory.CharmParams{
			Name:     "wordpress",
			Revision: "23",
		}),
	})
	endpoint1, err := application1.Endpoint("juju-info")
	c.Assert(err, jc.ErrorIsNil)
	endpoint2, err := application1.Endpoint("logging-dir")
	c.Assert(err, jc.ErrorIsNil)

	// make another application with 2 endpoints
	application2 := s.Factory.MakeApplication(c, &factory.ApplicationParams{
		Charm: s.Factory.MakeCharm(c, &factory.CharmParams{
			Name:     "logging",
			Revision: "43",
		}),
		CharmConfig:      map[string]interface{}{"foo": "bar"},
		EndpointBindings: map[string]string{"info": "vlan2"},
	})
	endpoint3, err := application2.Endpoint("info")
	c.Assert(err, jc.ErrorIsNil)
	endpoint4, err := application2.Endpoint("logging-directory")
	c.Assert(err, jc.ErrorIsNil)

	// create relation between a1:e1 and a2:e3
	relation1 := s.Factory.MakeRelation(c, &factory.RelationParams{
		Endpoints: []state.Endpoint{endpoint1, endpoint3},
	})
	c.Assert(relation1, gc.NotNil)

	// create relation between a1:e2 and a2:e4
	relation2 := s.Factory.MakeRelation(c, &factory.RelationParams{
		Endpoints: []state.Endpoint{endpoint2, endpoint4},
	})
	c.Assert(relation2, gc.NotNil)
}

func (s *CmdExportBundleSuite) TestExportBundle(c *gc.C) {
	s.SetFeatureFlags(feature.DeveloperMode)

	s.setupApplications(c)

	ctx, err := cmdtesting.RunCommand(c, model.NewExportBundleCommand())
	c.Assert(err, jc.ErrorIsNil)
	output := cmdtesting.Stdout(ctx)
	c.Assert(output, gc.Equals, `
series: quantal
applications:
  logging:
    charm: cs:quantal/logging-43
    options:
      foo: bar
    bindings:
      info: vlan2
  wordpress:
    charm: cs:quantal/wordpress-23
relations:
- - wordpress:juju-info
  - logging:info
- - wordpress:logging-dir
  - logging:logging-directory
`[1:])
}
