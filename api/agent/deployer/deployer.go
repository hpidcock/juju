// Copyright 2012, 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package deployer

import (
	"context"
	"fmt"

	"github.com/juju/names/v6"

	"github.com/juju/juju/api/base"
	"github.com/juju/juju/api/common"
	"github.com/juju/juju/core/life"
	"github.com/juju/juju/rpc/params"
)

// Option is a function that can be used to configure a Client.
type Option = base.Option

// WithTracer returns an Option that configures the Client to use the
// supplied tracer.
var WithTracer = base.WithTracer

const deployerFacade = "Deployer"

// Client provides access to the deployer worker's idea of the state.
type Client struct {
	facade base.FacadeCaller
}

// NewClient creates a new Client instance that makes API calls
// through the given caller.
func NewClient(caller base.APICaller, options ...Option) *Client {
	facadeCaller := base.NewFacadeCaller(caller, deployerFacade, options...)
	return &Client{facade: facadeCaller}

}

// unitLife returns the lifecycle state of the given unit.
func (c *Client) unitLife(ctx context.Context, tag names.UnitTag) (life.Value, error) {
	return common.OneLife(ctx, c.facade, tag)
}

// Unit returns the unit with the given tag.
func (c *Client) Unit(ctx context.Context, tag names.UnitTag) (*Unit, error) {
	life, err := c.unitLife(ctx, tag)
	if err != nil {
		return nil, err
	}
	return &Unit{
		tag:    tag,
		life:   life,
		client: c,
	}, nil
}

// Machine returns the machine with the given tag.
func (c *Client) Machine(tag names.MachineTag) (*Machine, error) {
	// TODO(dfc) this cannot return an error any more
	return &Machine{
		tag:    tag,
		client: c,
	}, nil
}

// UnitContainerNames returns the container names from the charm metadata
// for the given unit.
func (c *Client) UnitContainerNames(ctx context.Context, tag names.UnitTag) ([]string, error) {
	var result params.StringsResults
	args := params.Entities{
		Entities: []params.Entity{{Tag: tag.String()}},
	}
	err := c.facade.FacadeCall(ctx, "UnitContainerNames", args, &result)
	if err != nil {
		return nil, err
	}
	if len(result.Results) != 1 {
		return nil, fmt.Errorf("expected 1 result, got %d", len(result.Results))
	}
	if result.Results[0].Error != nil {
		return nil, result.Results[0].Error
	}
	return result.Results[0].Result, nil
}
