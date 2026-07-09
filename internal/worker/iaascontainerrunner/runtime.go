// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
)

// ContainerRuntime abstracts the underlying mechanism used to create, run
// and monitor OCI-image backed workload containers for a unit on an IAAS
// machine.
//
// The only implementation today is LXD+peel (see the lxdpeel sub-package),
// but the abstraction leaves room for future implementations based on
// containerd, podman or docker without requiring any changes to Worker.
type ContainerRuntime interface {
	// EnsureRunning ensures that a container matching spec exists and is
	// running. If a container with the same name already exists but no
	// longer matches spec (e.g. its image changed), implementations
	// should replace it.
	EnsureRunning(ctx context.Context, spec ContainerSpec) error

	// Status returns the current status of the named container. It must
	// not return an error solely because the container does not exist;
	// implementations should report that as a ContainerStatus instead.
	Status(ctx context.Context, name string) (ContainerStatus, error)

	// Stop stops and removes the named container. It must not return an
	// error if the container does not exist.
	Stop(ctx context.Context, name string) error
}

// LogTailer is optionally implemented by a ContainerRuntime that can stream
// a container's log/console output to a LogSink. The lxdpeel runtime
// implements this on top of LXD's console log.
type LogTailer interface {
	// TailLogs streams log lines for the named container to sink until ctx
	// is cancelled. Implementations should treat this as best-effort.
	TailLogs(ctx context.Context, name string, sink LogSink) error
}

// ContainerSpec describes the desired state of a single workload container,
// resolved from charm metadata, resources and runtime configuration. It is
// the input to ContainerRuntime.EnsureRunning.
type ContainerSpec struct {
	// Name is the fully-qualified, runtime-unique container identifier.
	Name string

	// Image is the OCI image to run, along with any registry credentials
	// required to pull it.
	Image ImageDetails

	// PebbleBinaryPath is the host path of the pebble binary that should
	// be made available to the container at /charm/bin/pebble. Pebble is
	// installed on the host as a snap (see cloudinit provisioning); it is
	// never bundled or copied by this worker.
	PebbleBinaryPath string

	// SocketDir is a host directory mounted into the container at
	// /charm/container, so that the pebble socket started inside the
	// container can be reached by the unit agent.
	SocketDir string

	// Pod is the name of the unit pod that groups all workload containers
	// (e.g. "unit-mysql-0"). Container runtimes use this to associate
	// related containers: a future podman runtime would use it to create
	// a named podman pod.
	Pod string

	// Env holds additional environment variables to set inside the
	// container.
	Env map[string]string

	// Mounts are additional charm-declared storage mounts.
	Mounts []ResolvedMount
}

// ResolvedMount is a charm storage mount that has been resolved to a host
// path by a StorageResolver.
type ResolvedMount struct {
	// HostPath is the resolved host-side path for the mount.
	HostPath string
	// Location is the path inside the container the mount should appear
	// at.
	Location string
}
