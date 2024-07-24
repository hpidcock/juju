// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package charm_test

import (
	"encoding/json"
	"strings"

	"github.com/juju/os/v2"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/core/arch"
	"github.com/juju/juju/internal/charm"
)

type baseSuite struct {
	testing.CleanupSuite
}

var _ = gc.Suite(&baseSuite{})

func (s *baseSuite) TestParseBase(c *gc.C) {
	tests := []struct {
		str        string
		parsedBase charm.Base
		err        string
	}{
		{
			str:        "ubuntu",
			parsedBase: charm.Base{},
			err:        `base string must contain exactly one @. "ubuntu" not valid`,
		}, {
			str:        "ubuntu@20.04/edge",
			parsedBase: charm.Base{Name: strings.ToLower(os.Ubuntu.String()), Channel: mustParseChannel("20.04/edge")},
		},
	}
	for i, v := range tests {
		comment := gc.Commentf("test %d", i)
		s, err := charm.ParseBase(v.str)
		if v.err != "" {
			c.Check(err, gc.ErrorMatches, v.err, comment)
		} else {
			c.Assert(err, jc.ErrorIsNil, comment)
		}
		c.Check(s, jc.DeepEquals, v.parsedBase, comment)
	}
}

func (s *baseSuite) TestParseBaseWithArchitectures(c *gc.C) {
	tests := []struct {
		str        string
		baseString string
		archs      []string
		parsedBase charm.Base
	}{
		{
			baseString: "ubuntu@20.04/stable",
			archs:      []string{arch.AMD64, "ppc64"},
			str:        "ubuntu@20.04/stable on amd64, ppc64el",
			parsedBase: charm.Base{
				Name:          strings.ToLower(os.Ubuntu.String()),
				Channel:       mustParseChannel("20.04/stable"),
				Architectures: []string{arch.AMD64, arch.PPC64EL}},
		},
	}
	for i, v := range tests {
		comment := gc.Commentf("test %d", i)
		s, err := charm.ParseBase(v.baseString, v.archs...)

		c.Assert(err, jc.ErrorIsNil, comment)

		c.Check(s, jc.DeepEquals, v.parsedBase, comment)
	}
}

func (s *baseSuite) TestStringifyBase(c *gc.C) {
	tests := []struct {
		base charm.Base
		str  string
	}{
		{
			base: charm.Base{Name: strings.ToLower(os.Ubuntu.String()), Channel: mustParseChannel("20.04/stable")},
			str:  "ubuntu@20.04/stable",
		}, {
			base: charm.Base{Name: strings.ToLower(os.Ubuntu.String()), Channel: mustParseChannel("20.04/edge")},
			str:  "ubuntu@20.04/edge",
		}, {
			base: charm.Base{
				Name:          strings.ToLower(os.Ubuntu.String()),
				Channel:       mustParseChannel("20.04/stable"),
				Architectures: []string{arch.AMD64},
			},
			str: "ubuntu@20.04/stable on amd64",
		}, {
			base: charm.Base{
				Name:          strings.ToLower(os.Ubuntu.String()),
				Channel:       mustParseChannel("20.04/stable"),
				Architectures: []string{arch.AMD64, arch.PPC64EL},
			},
			str: "ubuntu@20.04/stable on amd64, ppc64el",
		},
	}
	for i, v := range tests {
		comment := gc.Commentf("test %d", i)
		c.Assert(v.base.Validate(), jc.ErrorIsNil)
		c.Assert(v.base.String(), gc.Equals, v.str, comment)
	}
}

func (s *baseSuite) TestJSONEncoding(c *gc.C) {
	sys := charm.Base{
		Name:    "ubuntu",
		Channel: mustParseChannel("20.04/stable"),
	}
	bytes, err := json.Marshal(sys)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(string(bytes), gc.Equals, `{"name":"ubuntu","channel":{"track":"20.04","risk":"stable"}}`)
	sys2 := charm.Base{}
	err = json.Unmarshal(bytes, &sys2)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(sys2, jc.DeepEquals, sys)
}

// MustParseChannel parses a given string or returns a panic.
// Used for unit tests.
func mustParseChannel(s string) charm.Channel {
	c, err := charm.ParseChannelNormalize(s)
	if err != nil {
		panic(err)
	}
	return c
}
