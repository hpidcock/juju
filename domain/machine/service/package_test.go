// Copyright 2023 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package service

//go:generate go tool mockgen -typed -package service -destination state_mock_test.go -source=./service.go
//go:generate go tool mockgen -typed -package service -destination migration_mock_test.go -source=./migration.go
