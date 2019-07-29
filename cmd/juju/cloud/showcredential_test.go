// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package cloud_test

import (
	"gopkg.in/juju/cmd.v2/cmdtesting"
	"github.com/juju/errors"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/apiserver/common"
	"github.com/juju/juju/apiserver/params"
	jujucloud "github.com/juju/juju/cloud"
	"github.com/juju/juju/cmd/juju/cloud"
	"github.com/juju/juju/jujuclient"
	_ "github.com/juju/juju/provider/all"
	coretesting "github.com/juju/juju/testing"
)

type ShowCredentialSuite struct {
	coretesting.BaseSuite

	api   *fakeCredentialContentAPI
	store *jujuclient.MemStore
}

var _ = gc.Suite(&ShowCredentialSuite{})

func (s *ShowCredentialSuite) SetUpTest(c *gc.C) {
	s.BaseSuite.SetUpTest(c)

	s.store = &jujuclient.MemStore{
		Controllers: map[string]jujuclient.ControllerDetails{
			"controller": {},
		},
		CurrentControllerName: "controller",
	}
	s.api = &fakeCredentialContentAPI{v: 2}
}

func (s *ShowCredentialSuite) putCredentialsInStore(c *gc.C) {
	authCreds := map[string]string{"access-key": "key", "secret-key": "secret"}
	s.store.Accounts = map[string]jujuclient.AccountDetails{
		"controller": {
			User: "admin@local",
		},
	}
	s.store.Credentials = map[string]jujucloud.CloudCredential{
		"aws": {
			AuthCredentials: map[string]jujucloud.Credential{
				"my-credential": jujucloud.NewCredential(jujucloud.AccessKeyAuthType, authCreds),
			},
		},
		"somecloud": {
			AuthCredentials: map[string]jujucloud.Credential{
				"its-credential":         jujucloud.NewCredential(jujucloud.AccessKeyAuthType, authCreds),
				"its-another-credential": jujucloud.NewCredential(jujucloud.AccessKeyAuthType, authCreds),
			},
		},
	}
}

func (s *ShowCredentialSuite) TestShowCredentialBadArgs(c *gc.C) {
	cmd := cloud.NewShowCredentialCommandForTest(s.store, s.api)
	_, err := cmdtesting.RunCommand(c, cmd, "cloud")
	c.Assert(err, gc.ErrorMatches, "both cloud and credential name are needed")
	_, err = cmdtesting.RunCommand(c, cmd, "cloud", "credential", "extra")
	c.Assert(err, gc.ErrorMatches, `only cloud and credential names are supported`)
}

func (s *ShowCredentialSuite) TestShowCredentialAPIVersion(c *gc.C) {
	s.api.v = 1
	cmd := cloud.NewShowCredentialCommandForTest(s.store, s.api)
	ctx, err := cmdtesting.RunCommand(c, cmd)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(cmdtesting.Stderr(ctx), gc.Equals, `
remote credential content lookup failed: remote credential content lookup in Juju v1 not supported
No local or remote credentials to display.
`[1:])
	c.Assert(cmdtesting.Stdout(ctx), gc.Equals, ``)
	s.api.CheckCallNames(c, "BestAPIVersion", "Close")
}

func (s *ShowCredentialSuite) TestShowCredentialAPICallError(c *gc.C) {
	s.api.SetErrors(errors.New("boom"), nil)
	cmd := cloud.NewShowCredentialCommandForTest(s.store, s.api)
	ctx, err := cmdtesting.RunCommand(c, cmd)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(cmdtesting.Stderr(ctx), gc.Equals, `
remote credential content lookup failed: boom
No local or remote credentials to display.
`[1:])
	c.Assert(cmdtesting.Stdout(ctx), gc.Equals, ``)
	s.api.CheckCallNames(c, "BestAPIVersion", "CredentialContents", "Close")
}

func (s *ShowCredentialSuite) TestShowCredentialNone(c *gc.C) {
	s.api.contents = []params.CredentialContentResult{}
	cmd := cloud.NewShowCredentialCommandForTest(s.store, s.api)
	ctx, err := cmdtesting.RunCommand(c, cmd)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(cmdtesting.Stderr(ctx), gc.Equals, "No local or remote credentials to display.\n")
	c.Assert(cmdtesting.Stdout(ctx), gc.Equals, ``)
	s.api.CheckCallNames(c, "BestAPIVersion", "CredentialContents", "Close")
}

func (s *ShowCredentialSuite) TestShowCredentialOne(c *gc.C) {
	_true := true
	s.api.contents = []params.CredentialContentResult{
		{
			Result: &params.ControllerCredentialInfo{
				Content: params.CredentialContent{
					Cloud:    "aws",
					Name:     "credential-name",
					AuthType: "userpass",
					Valid:    &_true,
					Attributes: map[string]string{
						"username": "fred",
						"password": "sekret"},
				},
				Models: []params.ModelAccess{
					{Model: "abcmodel", Access: "admin"},
					{Model: "xyzmodel", Access: "read"},
					{Model: "no-access-model"},
				},
			},
		},
	}
	cmd := cloud.NewShowCredentialCommandForTest(s.store, s.api)
	ctx, err := cmdtesting.RunCommand(c, cmd, "--show-secrets")
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(cmdtesting.Stderr(ctx), gc.Equals, ``)
	c.Assert(cmdtesting.Stdout(ctx), gc.Equals, `
local-credentials: {}
controller-credentials:
  aws:
    credential-name:
      content:
        auth-type: userpass
        validity-check: valid
        password: sekret
        username: fred
      models:
        abcmodel: admin
        no-access-model: no access
        xyzmodel: read
`[1:])
	s.api.CheckCallNames(c, "BestAPIVersion", "CredentialContents", "Close")
	c.Assert(s.api.inclsecrets, jc.IsTrue)
}

func (s *ShowCredentialSuite) TestShowCredentialMany(c *gc.C) {
	_true := true
	_false := false
	s.api.contents = []params.CredentialContentResult{
		{
			Result: &params.ControllerCredentialInfo{
				Content: params.CredentialContent{
					Cloud:      "cloud-name",
					Name:       "one",
					AuthType:   "userpass",
					Valid:      &_true,
					Attributes: map[string]string{"username": "fred"},
				},
				// Don't have models here.
			},
		}, {
			Error: common.ServerError(errors.New("boom")),
		}, {
			Result: &params.ControllerCredentialInfo{
				Content: params.CredentialContent{
					Cloud:    "cloud-name",
					Name:     "two",
					AuthType: "userpass",
					Valid:    &_false,
					Attributes: map[string]string{
						"username":  "fred",
						"something": "visible-attr",
						"password":  "sekret",
						"hidden":    "very-very-sekret",
					},
				},
				Models: []params.ModelAccess{
					{Model: "abcmodel", Access: "admin"},
					{Model: "xyzmodel", Access: "read"},
					{Model: "no-access-model"},
				},
			},
		}, {
			Result: &params.ControllerCredentialInfo{
				Content: params.CredentialContent{
					Cloud:    "diff-cloud",
					Name:     "three",
					AuthType: "oauth1",
					Valid:    &_true,
					Attributes: map[string]string{
						"something": "visible-attr",
					},
				},
				Models: []params.ModelAccess{
					{Model: "klmmodel", Access: "write"},
				},
			},
		},
	}
	cmd := cloud.NewShowCredentialCommandForTest(s.store, s.api)
	ctx, err := cmdtesting.RunCommand(c, cmd)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(cmdtesting.Stderr(ctx), gc.Equals, "boom\n")
	c.Assert(cmdtesting.Stdout(ctx), gc.Equals, `
local-credentials: {}
controller-credentials:
  cloud-name:
    one:
      content:
        auth-type: userpass
        validity-check: valid
        username: fred
    two:
      content:
        auth-type: userpass
        validity-check: invalid
        hidden: very-very-sekret
        password: sekret
        something: visible-attr
        username: fred
      models:
        abcmodel: admin
        no-access-model: no access
        xyzmodel: read
  diff-cloud:
    three:
      content:
        auth-type: oauth1
        validity-check: valid
        something: visible-attr
      models:
        klmmodel: write
`[1:])
	s.api.CheckCallNames(c, "BestAPIVersion", "CredentialContents", "Close")
}

type fakeCredentialContentAPI struct {
	testing.Stub
	v           int
	contents    []params.CredentialContentResult
	inclsecrets bool
}

func (f *fakeCredentialContentAPI) CredentialContents(cloud, credential string, withSecrets bool) ([]params.CredentialContentResult, error) {
	f.AddCall("CredentialContents", cloud, credential, withSecrets)
	f.inclsecrets = withSecrets
	return f.contents, f.NextErr()
}

func (f *fakeCredentialContentAPI) Close() error {
	f.AddCall("Close")
	return f.NextErr()
}

func (f *fakeCredentialContentAPI) BestAPIVersion() int {
	f.AddCall("BestAPIVersion")
	return f.v
}
