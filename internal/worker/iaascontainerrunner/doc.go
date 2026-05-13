// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package iaascontainerrunner manages OCI workload containers on IAAS VMs
// using nerdctl/containerd. It provides the runtime environment needed for
// FormatV2 (sidecar) charms to run on non-Kubernetes machines.
//
// For each container declared in the charm's metadata, the worker:
//   - Resolves the OCI image from the charm's resources
//   - Pulls the image via nerdctl
//   - Runs the container with pebble as the entrypoint
//   - Exposes the pebble socket for the uniter to connect to
//
// The worker is gated on non-empty ContainerNames - it does nothing for
// traditional FormatV1 charms or when no containers are declared.
package iaascontainerrunner
