// Copyright 2023 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package internal

//go:generate go tool mockgen -typed -package internal_test -destination watcher_mock_test.go -source=./watcher.go
