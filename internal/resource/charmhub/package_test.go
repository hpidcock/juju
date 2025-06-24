// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package charmhub_test

//go:generate go tool mockgen -typed -package charmhub_test -destination charmhub_mock_test.go github.com/juju/juju/internal/resource/charmhub ResourceClient,CharmHub,Downloader
