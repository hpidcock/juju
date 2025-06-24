// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package runner_test

//go:generate go tool mockgen -typed -package mocks -destination mocks/factory_mock.go github.com/juju/juju/internal/worker/uniter/runner Factory,Runner
//go:generate go tool mockgen -typed -package mocks -destination mocks/context_mock.go github.com/juju/juju/internal/worker/uniter/runner/context Context
