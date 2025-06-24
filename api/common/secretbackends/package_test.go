// Copyright 2023 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package secretbackends

//go:generate go tool mockgen -typed -package mocks -destination mocks/facade_mock.go github.com/juju/juju/api/base FacadeCaller
