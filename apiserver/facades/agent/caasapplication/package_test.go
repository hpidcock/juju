// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package caasapplication_test

// TODO - only needed until controller state is removed.
//go:generate go tool mockgen -typed -package caasapplication -destination state_mock_test.go github.com/juju/juju/apiserver/facades/agent/caasapplication ControllerState

//go:generate go tool mockgen -typed -package caasapplication -destination package_mock_test.go github.com/juju/juju/apiserver/facades/agent/caasapplication ControllerConfigService,ApplicationService,ModelAgentService
