// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package remoterelations_test

//go:generate go tool mockgen -typed -package mocks -destination mocks/remoterelations_mocks.go github.com/juju/juju/apiserver/facades/controller/remoterelations ControllerConfigAPI,ExternalControllerService,SecretService
