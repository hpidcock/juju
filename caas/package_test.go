// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package caas_test

//go:generate go tool mockgen -typed -package mocks -destination mocks/broker_mock.go github.com/juju/juju/caas Broker
//go:generate go tool mockgen -typed -package mocks -destination mocks/application_mock.go github.com/juju/juju/caas Application
