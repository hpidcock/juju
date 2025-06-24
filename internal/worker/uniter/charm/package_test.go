// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package charm_test

//go:generate go tool mockgen -typed -package mocks -destination mocks/mocks.go github.com/juju/juju/internal/worker/uniter/charm BundleReader,BundleInfo,Bundle
