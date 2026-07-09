// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package iaascontainerrunner manages OCI workload containers for units on
// IAAS machines.
//
// Workload containers are declared in a charm's metadata (see
// domain/deployment/charm.Meta.Containers); no "assumes" feature is
// required to unlock this support. For each declared container, the Worker
// resolves an OCI image from the charm's resources and asks a
// ContainerRuntime to ensure a matching container is running, with the
// host's pebble binary mounted in at /charm/bin/pebble and the pebble
// socket exposed at a path the uniter can reach. ContainerRuntime
// abstracts away the underlying container technology; the Worker itself
// has no knowledge of it. The Worker is gated on a non-empty
// ContainerNames list, and does nothing for traditional FormatV1 charms.
//
// See the lxdpeel sub-package for the LXD+peel ContainerRuntime
// implementation used today. See domain/deployment/charm for the
// Containers metadata that drives this package.
package iaascontainerrunner
