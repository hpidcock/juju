// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package externalcontrollerupdater_test

//go:generate go tool mockgen -typed -package externalcontrollerupdater_test -destination package_mock_test.go github.com/juju/juju/internal/worker/externalcontrollerupdater ExternalControllerWatcherClientCloser,ExternalControllerUpdaterClient
