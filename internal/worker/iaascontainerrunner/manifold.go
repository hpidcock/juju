// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"fmt"

	"github.com/juju/names/v6"
	"github.com/juju/worker/v5"
	"github.com/juju/worker/v5/dependency"

	"github.com/juju/juju/agent"
	"github.com/juju/juju/agent/engine"
	apiclient "github.com/juju/juju/api/agent/iaascontainerrunner"
	"github.com/juju/juju/api/base"
	"github.com/juju/juju/core/logger"
)

// defaultPebbleBinaryPath is the host path where the pebble snap installs
// its binary. iaascontainerrunner mounts this binary directly into every
// workload container; it never bundles or copies pebble itself, relying
// instead on cloudinit provisioning to have installed the pebble snap.
const defaultPebbleBinaryPath = "/snap/pebble/current/bin/pebble"

// ManifoldConfig defines the configuration for the container runner manifold.
type ManifoldConfig struct {
	AgentName      string
	APICallerName  string
	ContainerNames []string
	Logger         logger.Logger

	// NewRuntime constructs the ContainerRuntime used to run workload
	// containers. This is a factory, rather than a concrete value, kept
	// out of this package to avoid a dependency on any specific container
	// technology (e.g. the LXD+peel implementation in the lxdpeel
	// sub-package) - callers wire in the implementation they want.
	// dataDir is the agent data directory, which the runtime may use for
	// its own host-side storage (e.g. the peel loopback directory).
	NewRuntime func(dataDir string) (ContainerRuntime, error)
}

// Manifold returns a dependency.Manifold that runs OCI containers for units.
// If ContainerNames is empty, it returns a no-op manifold that never starts.
func Manifold(config ManifoldConfig) dependency.Manifold {
	if len(config.ContainerNames) == 0 {
		return dependency.Manifold{
			Inputs: nil,
			Start: func(ctx context.Context, getter dependency.Getter) (worker.Worker, error) {
				return nil, dependency.ErrMissing
			},
		}
	}

	return engine.AgentAPIManifold(engine.AgentAPIManifoldConfig{
		AgentName:     config.AgentName,
		APICallerName: config.APICallerName,
	}, config.start)
}

func (config ManifoldConfig) start(ctx context.Context, a agent.Agent, apiCaller base.APICaller) (worker.Worker, error) {
	agentConfig := a.CurrentConfig()
	unitTag, err := names.ParseUnitTag(agentConfig.Tag().String())
	if err != nil {
		return nil, fmt.Errorf("invalid unit tag %q: %w", agentConfig.Tag(), err)
	}

	// Resolve charm container resources via the uniter's resources API.
	client, err := apiclient.NewClient(apiCaller, unitTag)
	if err != nil {
		return nil, fmt.Errorf("creating iaas container runner client: %w", err)
	}

	// Resolve image details and charm metadata for each container.
	imageDetails := make(map[string]ImageDetails, len(config.ContainerNames))
	charmMeta := make(map[string]ContainerMeta, len(config.ContainerNames))

	for _, name := range config.ContainerNames {
		info, err := client.GetContainerResourceInfo(ctx, name)
		if err != nil {
			config.Logger.Warningf(ctx, "could not get resource info for container %q: %v", name, err)
			charmMeta[name] = ContainerMeta{ResourceName: name}
			continue
		}
		if info != nil {
			imageDetails[name] = ImageDetails{
				RegistryPath: info.RegistryPath,
				Username:     info.Username,
				Password:     info.Password,
			}
		}
		if charmMeta[name].ResourceName == "" {
			charmMeta[name] = ContainerMeta{ResourceName: name}
		}
	}

	if config.NewRuntime == nil {
		return nil, fmt.Errorf("no container runtime configured")
	}
	runtime, err := config.NewRuntime(agentConfig.Dir())
	if err != nil {
		return nil, fmt.Errorf("creating container runtime: %w", err)
	}

	return New(Config{
		Logger:           config.Logger,
		DataDir:          agentConfig.Dir(),
		ContainerNames:   config.ContainerNames,
		CharmMeta:        charmMeta,
		ImageDetails:     imageDetails,
		Runtime:          runtime,
		PebbleBinaryPath: defaultPebbleBinaryPath,
	})
}
