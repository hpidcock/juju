// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package facade_test

//go:generate go tool mockgen -typed -package mocks -destination mocks/facade_mock.go github.com/juju/juju/apiserver/facade Resources,Authorizer,WatcherRegistry
