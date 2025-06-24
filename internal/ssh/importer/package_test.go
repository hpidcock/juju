// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package importer

//go:generate go tool mockgen -typed -package importer -destination http_mock_test.go github.com/juju/juju/internal/ssh/importer Client
//go:generate go tool mockgen -typed -package importer -destination resolver_mock_test.go github.com/juju/juju/internal/ssh/importer Resolver
