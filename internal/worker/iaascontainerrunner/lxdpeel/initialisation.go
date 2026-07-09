// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package lxdpeel

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/juju/juju/internal/packaging/dependency"
	"github.com/juju/juju/internal/packaging/manager"
)

// DefaultLXDSnapChannel is the LXD snap channel used when installing LXD
// for running peel-based charm workload containers.
const DefaultLXDSnapChannel = "5.0/stable"

// SnapManager is the subset of the snap package manager needed to check
// and change the channel of an installed snap.
type SnapManager interface {
	InstalledChannel(string) string
	ChangeChannel(string, string) error
}

// getSnapManager returns the snap package manager. Defined as a variable
// so it can be overridden in tests.
var getSnapManager = func() SnapManager {
	return manager.NewSnapPackageManager()
}

// lxdViaSnap reports whether the LXD snap is installed and running (i.e.
// its unix socket is present). Defined as a variable for testing.
var lxdViaSnap = func() bool {
	_, err := os.Stat("/var/snap/lxd/common/lxd/unix.socket")
	return err == nil
}

// pebbleViaSnap reports whether the pebble snap is installed. Defined as a
// variable for testing.
var pebbleViaSnap = func() bool {
	_, err := os.Stat("/snap/pebble/current/bin/pebble")
	return err == nil
}

// Initialise ensures that:
//   - The LXD snap is installed at the given channel and has been
//     initialised (lxd init --auto).
//   - The pebble snap is installed (so its binary can be bind-mounted into
//     workload containers at /charm/bin/pebble).
//
// It is called by New before connecting to the LXD unix socket and follows
// the same pattern as internal/container/lxd.Initialise.
func Initialise(lxdSnapChannel string) error {
	if err := ensureLXD(lxdSnapChannel); err != nil {
		return fmt.Errorf("ensuring LXD: %w", err)
	}
	if err := initialiseLXD(); err != nil {
		return fmt.Errorf("initialising LXD: %w", err)
	}
	if err := ensurePebble(); err != nil {
		return fmt.Errorf("ensuring pebble snap: %w", err)
	}
	return nil
}

// ensureLXD installs the LXD snap at the requested channel, or switches to
// it if the snap is already installed at a different channel.
func ensureLXD(snapChannel string) error {
	if lxdViaSnap() {
		sm := getSnapManager()
		tracked := sm.InstalledChannel("lxd")
		if strings.HasPrefix(tracked, snapChannel) {
			return nil
		}
		return sm.ChangeChannel("lxd", snapChannel)
	}
	return dependency.InstallLXD(snapChannel)
}

// initialiseLXD waits for LXD to be ready and runs lxd init --auto.
// "You have existing containers or images" is treated as a success so the
// call is idempotent.
func initialiseLXD() error {
	if out, err := exec.Command("lxd", "waitready", "--timeout=300").CombinedOutput(); err != nil {
		return fmt.Errorf("lxd waitready: %s: %w", strings.TrimSpace(string(out)), err)
	}
	out, err := exec.Command("lxd", "init", "--auto").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "You have existing containers or images") {
			return nil
		}
		return fmt.Errorf("lxd init: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ensurePebble installs the pebble snap if it is not already present.
func ensurePebble() error {
	if pebbleViaSnap() {
		return nil
	}
	return dependency.InstallPebble()
}
