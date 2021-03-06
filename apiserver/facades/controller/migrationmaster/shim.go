// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package migrationmaster

import (
	"github.com/juju/errors"
	"github.com/juju/version"
	"gopkg.in/juju/names.v3"

	"github.com/juju/juju/apiserver/facade"
	"github.com/juju/juju/migration"
	"github.com/juju/juju/state"
)

// NewFacade exists to provide the required signature for API
// registration, converting st to backend.
func NewFacade(ctx facade.Context) (*API, error) {
	controllerState := ctx.StatePool().SystemState()
	precheckBackend, err := migration.PrecheckShim(ctx.State(), controllerState)
	if err != nil {
		return nil, errors.Annotate(err, "creating precheck backend")
	}
	return NewAPI(
		&backendShim{ctx.State()},
		precheckBackend,
		migration.PoolShim(ctx.StatePool()),
		ctx.Resources(),
		ctx.Auth(),
		ctx.Presence(),
	)
}

// backendShim wraps a *state.State to implement Backend. It is
// untested, but is simple enough to be verified by inspection.
type backendShim struct {
	*state.State
}

// ModelName implements Backend.
func (s *backendShim) ModelName() (string, error) {
	model, err := s.Model()
	if err != nil {
		return "", errors.Trace(err)
	}
	return model.Name(), nil
}

// ModelOwner implements Backend.
func (s *backendShim) ModelOwner() (names.UserTag, error) {
	model, err := s.Model()
	if err != nil {
		return names.UserTag{}, errors.Trace(err)
	}
	return model.Owner(), nil
}

// AgentVersion implements Backend.
func (s *backendShim) AgentVersion() (version.Number, error) {
	m, err := s.Model()
	if err != nil {
		return version.Zero, errors.Trace(err)
	}

	cfg, err := m.ModelConfig()
	if err != nil {
		return version.Zero, errors.Trace(err)
	}
	vers, ok := cfg.AgentVersion()
	if !ok {
		return version.Zero, errors.New("no agent version")
	}
	return vers, nil
}
