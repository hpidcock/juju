// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package dependency

import (
	"github.com/juju/juju/internal/packaging/manager"
)

// InstallPebble installs the pebble snap with classic confinement.
func InstallPebble() error {
	snapManager := manager.NewSnapPackageManager()
	return snapManager.Install("--classic pebble")
}
