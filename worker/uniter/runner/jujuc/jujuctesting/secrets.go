// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package jujuctesting

import (
	"github.com/juju/juju/core/secrets"
	"github.com/juju/juju/worker/uniter/runner/jujuc"
)

// ContextSecrets is a test double for jujuc.ContextSecrets.
type ContextSecrets struct {
	contextBase

	SecretValue secrets.SecretValue
}

// GetSecret implements jujuc.ContextSecrets.
func (c *ContextSecrets) GetSecret(ID string) (secrets.SecretValue, error) {
	c.stub.AddCall("GetSecret", ID)
	return c.SecretValue, nil
}

// CreateSecret implements jujuc.ContextSecrets.
func (c *ContextSecrets) CreateSecret(name string, args *jujuc.UpsertArgs) (string, error) {
	c.stub.AddCall("CreateSecret", name, args)
	return "secret://app." + name, nil
}

// UpdateSecret implements jujuc.ContextSecrets.
func (c *ContextSecrets) UpdateSecret(name string, args *jujuc.UpsertArgs) (string, error) {
	c.stub.AddCall("UpdateSecret", name, args)
	return "secret://app." + name, nil
}
