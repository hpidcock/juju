// Copyright 2012, 2013 Canonical Ltd.
// Copyright 2014 Cloudbase Solutions SRL
// Licensed under the AGPLv3, see LICENCE file for details.

package jujuc

import (
	"gopkg.in/juju/cmd.v2"
)

func HandleSettingsFile(c *RelationSetCommand, ctx *cmd.Context) error {
	return c.handleSettingsFile(ctx)
}

func NewJujuLogCommandWithMocks(ctx JujuLogContext, loggerFactory JujuLogCommandLoggerFactory) cmd.Command {
	return &JujuLogCommand{
		ctx:           ctx,
		loggerFactory: loggerFactory,
	}
}

func NewJujucCommandWrappedForTest(c cmd.Command) cmd.Command {
	return &cmdWrapper{c, nil}
}
