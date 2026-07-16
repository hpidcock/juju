// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package uniter

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/juju/errors"
	"github.com/juju/names/v6"

	"github.com/juju/juju/core/logger"
	"github.com/juju/juju/core/model"
	coreres "github.com/juju/juju/core/resource"
	jujucharm "github.com/juju/juju/domain/deployment/charm"
	charmresource "github.com/juju/juju/domain/deployment/charm/resource"
	"github.com/juju/juju/internal/docker"
	"github.com/juju/juju/internal/worker/iaascontainerrunner"
	"github.com/juju/juju/internal/worker/uniter/operation"
	"github.com/juju/juju/internal/worker/uniter/remotestate"
	"github.com/juju/juju/internal/worker/uniter/resolver"
	"github.com/juju/juju/internal/worker/uniter/storage"
)

// containerImageFetcher fetches OCI image resource content by resource name.
// It is satisfied by resources.OpenedResourceClient.
type containerImageFetcher interface {
	GetResource(ctx context.Context, resourceName string) (coreres.Resource, io.ReadCloser, error)
}

// containerResolverConfig holds the configuration for a containerResolver.
type containerResolverConfig struct {
	// Runner is the iaascontainerrunner.Runner used to start containers.
	Runner iaascontainerrunner.Runner
	// ContainerNames are the names of the workload containers declared in
	// the charm metadata.
	ContainerNames []string
	// Storage is used to check whether all initial storage attachments have
	// been committed before containers are started.
	Storage *storage.Attachments
	// ImageFetcher fetches OCI image resource content by resource name.
	ImageFetcher containerImageFetcher
	// CharmDir is the path to the deployed charm directory, used to read
	// container mount declarations from metadata.yaml.
	CharmDir string
	// ModelType determines IAAS-specific storage waiting behaviour.
	ModelType model.ModelType
	// GetStartedVersion returns the charm modified version for which
	// containers were last successfully started.
	GetStartedVersion func() int
	// SetStartedVersion records the charm modified version after a
	// successful EnsureContainers call.
	SetStartedVersion func(int)
	// Logger is used for debug/warning/error logging.
	Logger logger.Logger
}

// containerResolver is a resolver.Resolver that manages the lifecycle of
// IAAS workload containers on behalf of the uniter. It ensures containers
// are started once all required storage is available and re-created after
// charm upgrades.
type containerResolver struct {
	cfg containerResolverConfig
}

// newContainerResolver constructs a containerResolver.
func newContainerResolver(cfg containerResolverConfig) *containerResolver {
	return &containerResolver{cfg: cfg}
}

// NextOp implements resolver.Resolver. It blocks the resolver loop (returns
// ErrWaiting) until all initial storage attachments are committed, then
// calls runner.EnsureContainers. On charm upgrades it calls
// EnsureContainers again to recreate containers with the updated
// configuration.
func (r *containerResolver) NextOp(
	ctx context.Context,
	localState resolver.LocalState,
	remoteState remotestate.Snapshot,
	_ operation.Factory,
) (operation.Operation, error) {
	if len(r.cfg.ContainerNames) == 0 || r.cfg.Runner == nil {
		return nil, resolver.ErrNoOperation
	}

	// For IAAS models: wait for all initial storage attachments to be
	// committed before starting containers so that storage mounts are
	// available when the containers first start.
	if r.cfg.ModelType == model.IAAS &&
		!localState.Installed &&
		r.cfg.Storage != nil &&
		r.cfg.Storage.Pending() > 0 {
		return nil, resolver.ErrWaiting
	}

	// Check whether containers need to be (re)started. The started version
	// is stored on the Uniter so it persists across resolver-loop restarts
	// (e.g. after an ErrRestart from a charm upgrade).
	targetVersion := remoteState.CharmModifiedVersion
	if r.cfg.GetStartedVersion() == targetVersion {
		return nil, resolver.ErrNoOperation
	}

	// Read container mount and resource declarations from the deployed charm.
	// This is done first because resource names are needed for image fetching.
	charmMeta, err := r.readCharmMeta()
	if err != nil {
		r.cfg.Logger.Warningf(ctx, "reading charm metadata for containers: %v", err)
		return nil, resolver.ErrWaiting
	}

	// Fetch current OCI image details using the resource names from the
	// charm metadata, avoiding any guesswork about naming conventions.
	imageDetails, err := r.fetchImageDetails(ctx, charmMeta)
	if err != nil {
		r.cfg.Logger.Warningf(ctx, "fetching container image details: %v", err)
		return nil, resolver.ErrWaiting
	}

	// Build a StorageResolver from the current remote-state snapshot.
	storageResolver := &snapshotStorageResolver{storage: remoteState.Storage}

	runnerCfg := iaascontainerrunner.RunnerConfig{
		CharmMeta:       charmMeta,
		ImageDetails:    imageDetails,
		StorageResolver: storageResolver,
	}
	if err := r.cfg.Runner.EnsureContainers(ctx, runnerCfg); err != nil {
		r.cfg.Logger.Errorf(ctx, "ensuring containers running: %v", err)
		return nil, resolver.ErrWaiting
	}

	r.cfg.SetStartedVersion(targetVersion)
	return nil, resolver.ErrNoOperation
}

// fetchImageDetails retrieves OCI image credentials for each container by
// looking up the resource name declared in the charm metadata. This avoids
// guessing naming conventions: the resource name is always taken directly
// from ContainerMeta.ResourceName.
func (r *containerResolver) fetchImageDetails(
	ctx context.Context,
	charmMeta map[string]iaascontainerrunner.ContainerMeta,
) (map[string]iaascontainerrunner.ImageDetails, error) {
	if r.cfg.ImageFetcher == nil {
		return nil, nil
	}
	result := make(map[string]iaascontainerrunner.ImageDetails, len(charmMeta))
	for containerName, meta := range charmMeta {
		if meta.ResourceName == "" {
			// No resource name declared for this container; the runner
			// will fall back to the default image.
			continue
		}
		res, body, err := r.cfg.ImageFetcher.GetResource(ctx, meta.ResourceName)
		if err != nil {
			if errors.Is(err, errors.NotFound) {
				r.cfg.Logger.Debugf(ctx, "no OCI image resource %q for container %q, using default", meta.ResourceName, containerName)
				continue
			}
			return nil, fmt.Errorf("fetching image resource %q for container %q: %w", meta.ResourceName, containerName, err)
		}
		if res.Type != charmresource.TypeContainerImage {
			// Resource exists but is not a container image; skip it.
			_ = body.Close()
			r.cfg.Logger.Debugf(ctx, "resource %q for container %q is not an OCI image (%s), skipping", meta.ResourceName, containerName, res.Type)
			continue
		}
		data, err := io.ReadAll(body)
		body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading image resource %q for container %q: %w", meta.ResourceName, containerName, err)
		}
		details, err := docker.UnmarshalDockerResource(data)
		if err != nil {
			return nil, fmt.Errorf("parsing image resource %q for container %q: %w", meta.ResourceName, containerName, err)
		}
		result[containerName] = iaascontainerrunner.ImageDetails{
			RegistryPath: details.RegistryPath,
			Username:     details.Username,
			Password:     details.Password,
		}
	}
	return result, nil
}

// readCharmMeta reads the charm's metadata.yaml and converts container
// mount declarations into the ContainerMeta map expected by the runner.
func (r *containerResolver) readCharmMeta() (map[string]iaascontainerrunner.ContainerMeta, error) {
	meta, err := jujucharm.ReadCharmDirMetadata(r.cfg.CharmDir)
	if err != nil {
		return nil, fmt.Errorf("reading charm metadata from %q: %w", r.cfg.CharmDir, err)
	}

	result := make(map[string]iaascontainerrunner.ContainerMeta, len(meta.Containers))
	for name, container := range meta.Containers {
		mounts := make([]iaascontainerrunner.Mount, 0, len(container.Mounts))
		for _, m := range container.Mounts {
			mounts = append(mounts, iaascontainerrunner.Mount{
				StorageName: m.Storage,
				Location:    m.Location,
			})
		}
		result[name] = iaascontainerrunner.ContainerMeta{
			ResourceName: container.Resource,
			Mounts:       mounts,
		}
	}
	return result, nil
}

// snapshotStorageResolver implements iaascontainerrunner.StorageResolver using
// the host paths recorded in the most recent remote-state snapshot.
type snapshotStorageResolver struct {
	storage map[names.StorageTag]remotestate.StorageSnapshot
}

// GetStorageMountPath implements iaascontainerrunner.StorageResolver.
// It finds the first attached storage instance whose name matches storageName
// (storage tag IDs are formatted as "name/index", e.g. "data/0").
func (s *snapshotStorageResolver) GetStorageMountPath(_ context.Context, storageName string) (string, error) {
	for tag, snap := range s.storage {
		// tag.Id() is "name/index"; extract just the name part.
		name, _, _ := strings.Cut(tag.Id(), "/")
		if name != storageName {
			continue
		}
		if !snap.Attached || snap.Location == "" {
			return "", fmt.Errorf("storage %q not yet attached", storageName)
		}
		return snap.Location, nil
	}
	return "", fmt.Errorf("storage %q not found", storageName)
}
