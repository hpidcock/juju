// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package lxdpeel implements iaascontainerrunner.ContainerRuntime on top of
// LXD, using peel (https://github.com/canonical/peel) as the in-container
// init that unpacks and runs an OCI image.
//
// Each workload container is run as its own LXD container, created from an
// otherwise-empty LXD image whose /sbin/init is peel. peel is configured
// entirely through LXD instance configuration keys (user.oci.*): it pulls
// the OCI image referenced by user.oci.image when the container first
// starts, unpacks it directly onto the container's rootfs, and execs its
// entrypoint -- which this package always overrides to the pebble binary,
// bind-mounted into the container from the host's pebble snap at
// /charm/bin/pebble. Every container belonging to the same unit also gets
// a shared "loopback" disk device mounted at /peel/lo, letting them share
// loopback listeners much like containers within the same Kubernetes pod.
//
// See the parent iaascontainerrunner package for the ContainerRuntime
// contract this package implements.
package lxdpeel
