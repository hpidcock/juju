// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package jujuc

import (
	"fmt"
	"time"

	"github.com/juju/cmd/v3"
	"github.com/juju/errors"
	"github.com/juju/gnuflag"
	"github.com/juju/juju/core/secrets"

	jujucmd "github.com/juju/juju/cmd"
)

type secretCreateCommand struct {
	cmd.CommandBase
	ctx Context

	id             string
	asBase64       bool
	rotateInterval time.Duration
	data           map[string]string
}

// NewSecretCreateCommand returns a command to create a secret.
func NewSecretCreateCommand(ctx Context) (cmd.Command, error) {
	return &secretCreateCommand{
		ctx:            ctx,
		rotateInterval: -1,
	}, nil
}

// Info implements cmd.Command.
func (c *secretCreateCommand) Info() *cmd.Info {
	doc := `
Create a secret with either a single value or a list of key values.
If --base64 is specified, the values are already in base64 format and no
encoding will be performed, otherwise the values will be base64 encoded
prior to being stored.

Examples:
    secret-create apitoken 34ae35facd4
    secret-create --base64 password AA==
    secret-create --rotate 5d password s3cret 
`
	return jujucmd.Info(&cmd.Info{
		Name:    "secret-create",
		Args:    "<id> [value|key=value...]",
		Purpose: "create a new secret",
		Doc:     doc,
	})
}

// SetFlags implements cmd.Command.
func (c *secretCreateCommand) SetFlags(f *gnuflag.FlagSet) {
	f.BoolVar(&c.asBase64, "base64", false,
		`specify the supplied values are base64 encoded strings`)
	f.DurationVar(&c.rotateInterval, "rotate", 0, "how often the secret should be rotated")
}

// Init implements cmd.Command.
func (c *secretCreateCommand) Init(args []string) error {
	if len(args) < 1 {
		return errors.New("missing secret id")
	}
	if len(args) < 2 {
		return errors.New("missing secret value")
	}
	if c.rotateInterval < 0 {
		return errors.NotValidf("rotate interval %q", c.rotateInterval)
	}
	c.id = args[0]

	var err error
	c.data, err = secrets.CreatSecretData(c.asBase64, args[1:])
	return err
}

// Run implements cmd.Command.
func (c *secretCreateCommand) Run(ctx *cmd.Context) error {
	value := secrets.NewSecretValue(c.data)
	id, err := c.ctx.CreateSecret(c.id, &UpsertArgs{
		Type:           secrets.TypeBlob,
		Value:          value,
		RotateInterval: c.rotateInterval,
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(ctx.Stdout, id)
	return nil
}
