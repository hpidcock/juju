// Copyright 2023 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package service_test

//go:generate go tool mockgen -typed -package service -destination service_mock_test.go github.com/juju/juju/domain/modelconfig/service ProviderState,State
