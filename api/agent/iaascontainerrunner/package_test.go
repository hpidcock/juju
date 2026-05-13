// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"testing"

	"github.com/juju/tc"

	"github.com/juju/juju/core/resource"
	domainresource "github.com/juju/juju/domain/deployment/charm/resource"
)

type baseSuite struct{}

func TestPackage(t *testing.T) {
	tc.Run(t, new(baseSuite))
}

func (s *baseSuite) TestResourceInfoFromResourceNotOCI(c *tc.C) {
	info, err := resourceInfoFromResource(resource.Resource{
		Resource: domainresource.Resource{
			Meta: domainresource.Meta{
				Type: domainresource.TypeFile,
				Path: "file.tgz",
			},
		},
	})
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(info, tc.IsNil)
}

func (s *baseSuite) TestResourceInfoFromResourceOCI(c *tc.C) {
	info, err := resourceInfoFromResource(resource.Resource{
		Resource: domainresource.Resource{
			Meta: domainresource.Meta{
				Type: domainresource.TypeContainerImage,
				Path: "registry.example.com/myorg/myimage:v1.0",
			},
		},
	})
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(info, tc.NotNil)
	c.Check(info.RegistryPath, tc.Equals, "registry.example.com/myorg/myimage:v1.0")
	c.Check(info.Username, tc.Equals, "")
	c.Check(info.Password, tc.Equals, "")
}
