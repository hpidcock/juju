// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"io"
	"strings"
	"testing"

	"github.com/juju/tc"

	"github.com/juju/juju/core/resource"
	domainresource "github.com/juju/juju/domain/deployment/charm/resource"
)

type baseSuite struct{}

func TestPackage(t *testing.T) {
	tc.Run(t, new(baseSuite))
}

func (s *baseSuite) TestResourceInfoFromBodyNotOCI(c *tc.C) {
	body := io.NopCloser(strings.NewReader(""))
	info, err := resourceInfoFromBody(resource.Resource{
		Resource: domainresource.Resource{
			Meta: domainresource.Meta{
				Type: domainresource.TypeFile,
				Path: "file.tgz",
			},
		},
	}, body)
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(info, tc.IsNil)
}

func (s *baseSuite) TestResourceInfoFromBodyOCI(c *tc.C) {
	// JSON format produced by the container image metadata service.
	const data = `{"ImageName":"registry.example.com/myorg/myimage:v1.0","username":"user","password":"pass"}`
	body := io.NopCloser(strings.NewReader(data))
	info, err := resourceInfoFromBody(resource.Resource{
		Resource: domainresource.Resource{
			Meta: domainresource.Meta{
				Type: domainresource.TypeContainerImage,
			},
		},
	}, body)
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(info, tc.NotNil)
	c.Check(info.RegistryPath, tc.Equals, "registry.example.com/myorg/myimage:v1.0")
	c.Check(info.Username, tc.Equals, "user")
	c.Check(info.Password, tc.Equals, "pass")
}

func (s *baseSuite) TestResourceInfoFromBodyOCINoCredentials(c *tc.C) {
	// Public image: only RegistryPath set, no credentials.
	const data = `{"ImageName":"docker.io/library/ubuntu:22.04"}`
	body := io.NopCloser(strings.NewReader(data))
	info, err := resourceInfoFromBody(resource.Resource{
		Resource: domainresource.Resource{
			Meta: domainresource.Meta{
				Type: domainresource.TypeContainerImage,
			},
		},
	}, body)
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(info, tc.NotNil)
	c.Check(info.RegistryPath, tc.Equals, "docker.io/library/ubuntu:22.04")
	c.Check(info.Username, tc.Equals, "")
	c.Check(info.Password, tc.Equals, "")
}

func (s *baseSuite) TestResourceInfoFromBodyOCIBadJSON(c *tc.C) {
	body := io.NopCloser(strings.NewReader("not-valid-json-or-yaml"))
	_, err := resourceInfoFromBody(resource.Resource{
		Resource: domainresource.Resource{
			Meta: domainresource.Meta{
				Type: domainresource.TypeContainerImage,
			},
		},
	}, body)
	c.Assert(err, tc.ErrorMatches, `(?s)parsing container image resource: .*`)
}
