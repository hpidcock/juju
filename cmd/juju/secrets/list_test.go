// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package secrets_test

import (
	"time"

	"github.com/golang/mock/gomock"
	"github.com/juju/cmd/v3/cmdtesting"
	jujutesting "github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	apisecrets "github.com/juju/juju/api/secrets"
	"github.com/juju/juju/cmd/juju/secrets"
	"github.com/juju/juju/cmd/juju/secrets/mocks"
	coresecrets "github.com/juju/juju/core/secrets"
	"github.com/juju/juju/jujuclient"
)

type ListSuite struct {
	jujutesting.IsolationSuite
	store      *jujuclient.MemStore
	secretsAPI *mocks.MockListSecretsAPI
}

var _ = gc.Suite(&ListSuite{})

func (s *ListSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	store := jujuclient.NewMemStore()
	store.Controllers["mycontroller"] = jujuclient.ControllerDetails{}
	store.CurrentControllerName = "mycontroller"
	s.store = store
}

func (s *ListSuite) setup(c *gc.C) *gomock.Controller {
	ctrl := gomock.NewController(c)

	s.secretsAPI = mocks.NewMockListSecretsAPI(ctrl)

	return ctrl
}

func (s *ListSuite) TestListTabular(c *gc.C) {
	defer s.setup(c).Finish()

	s.secretsAPI.EXPECT().ListSecrets(false).Return(
		[]apisecrets.SecretDetails{{
			Metadata: coresecrets.SecretMetadata{
				ID: 666, RotateInterval: time.Hour,
				Revision: 2, Path: "app.password", Provider: "juju"},
		}, {
			Metadata: coresecrets.SecretMetadata{
				ID:       667,
				Revision: 1, Path: "app.apitoken", Provider: "juju"},
		}}, nil)
	s.secretsAPI.EXPECT().Close().Return(nil)

	ctx, err := cmdtesting.RunCommand(c, secrets.NewListCommandForTest(s.store, s.secretsAPI))
	c.Assert(err, jc.ErrorIsNil)
	out := cmdtesting.Stdout(ctx)
	c.Assert(out, gc.Equals, `
ID   Revision  Rotate  Backend  Path          Age
666         2  1h      juju     app.password  0001-01-01  
667         1  never   juju     app.apitoken  0001-01-01  

`[1:])
}

func (s *ListSuite) TestListYAML(c *gc.C) {
	defer s.setup(c).Finish()

	URL, err := coresecrets.ParseURL("secret://v1/app.password")
	c.Assert(err, jc.ErrorIsNil)
	URL2, err := coresecrets.ParseURL("secret://v1/app.apitoken")
	c.Assert(err, jc.ErrorIsNil)
	s.secretsAPI.EXPECT().ListSecrets(true).Return(
		[]apisecrets.SecretDetails{{
			Metadata: coresecrets.SecretMetadata{
				URL: URL, ID: 666, RotateInterval: time.Hour,
				Version: 1, Revision: 2, Path: "app.password", Provider: "juju"},
			Value: coresecrets.NewSecretValue(map[string]string{"foo": "YmFy"}),
		}, {
			Metadata: coresecrets.SecretMetadata{
				URL: URL2, ID: 667, Version: 1, Revision: 1, Path: "app.apitoken", Provider: "juju"},
			Error: "boom",
		}}, nil)
	s.secretsAPI.EXPECT().Close().Return(nil)

	ctx, err := cmdtesting.RunCommand(c, secrets.NewListCommandForTest(s.store, s.secretsAPI), "--format", "yaml", "--show-secrets")
	c.Assert(err, jc.ErrorIsNil)
	out := cmdtesting.Stdout(ctx)
	c.Assert(out, gc.Equals, `
- ID: 666
  URL: secret://v1/app.password
  revision: 2
  path: app.password
  rotate-interval: 1h0m0s
  version: 1
  backend: juju
  create-time: 0001-01-01T00:00:00Z
  update-time: 0001-01-01T00:00:00Z
  value:
    foo: bar
- ID: 667
  URL: secret://v1/app.apitoken
  revision: 1
  path: app.apitoken
  version: 1
  backend: juju
  create-time: 0001-01-01T00:00:00Z
  update-time: 0001-01-01T00:00:00Z
  error: boom
`[1:])
}

func (s *ListSuite) TestListJSON(c *gc.C) {
	defer s.setup(c).Finish()

	URL, err := coresecrets.ParseURL("secret://v1/app.password")
	c.Assert(err, jc.ErrorIsNil)
	s.secretsAPI.EXPECT().ListSecrets(true).Return(
		[]apisecrets.SecretDetails{{
			Metadata: coresecrets.SecretMetadata{
				URL: URL, ID: 666,
				Version: 1, Revision: 2, Path: "app.password", Provider: "juju"},
			Value: coresecrets.NewSecretValue(map[string]string{"foo": "YmFy"}),
		}}, nil)
	s.secretsAPI.EXPECT().Close().Return(nil)

	ctx, err := cmdtesting.RunCommand(c, secrets.NewListCommandForTest(s.store, s.secretsAPI), "--format", "json", "--show-secrets")
	c.Assert(err, jc.ErrorIsNil)
	out := cmdtesting.Stdout(ctx)
	c.Assert(out, gc.Equals, `
[{"ID":666,"URL":"secret://v1/app.password","revision":2,"path":"app.password","version":1,"backend":"juju","create-time":"0001-01-01T00:00:00Z","update-time":"0001-01-01T00:00:00Z","value":{"Data":{"foo":"bar"}}}]
`[1:])
}
