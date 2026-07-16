// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package iaascontainerrunner manages OCI workload containers for units on
// IAAS machines.
//
// Workload containers are declared in a charm's metadata (see
// domain/deployment/charm.Meta.Containers); no "assumes" feature is
// required to unlock this support. The Worker is started by the unit-agent
// manifold alongside the uniter, but does NOT start containers immediately.
// Instead it exposes a Runner interface, which the uniter calls via
// EnsureContainers once the unit is ready: storage attachments are committed
// before containers are started so that charm-declared storage mounts are
// available when a container first runs. On charm upgrade the uniter calls
// EnsureContainers again to stop the old containers and start new ones.
//
// ContainerRuntime abstracts the underlying container technology; the Worker
// has no knowledge of it. The Worker is gated on a non-empty ContainerNames
// list and is a no-op for traditional FormatV1 charms.
//
// See the lxdpeel sub-package for the LXD+peel ContainerRuntime
// implementation used today. See domain/deployment/charm for the
// Containers metadata that drives this package.
package iaascontainerrunner
