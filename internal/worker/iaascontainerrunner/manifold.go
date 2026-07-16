// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"fmt"

	"github.com/juju/worker/v5"
	"github.com/juju/worker/v5/dependency"

	"github.com/juju/juju/agent"
	"github.com/juju/juju/agent/engine"
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
			Output: output,
		}
	}

	m := engine.AgentManifold(engine.AgentManifoldConfig{
		AgentName: config.AgentName,
	}, config.start)
	m.Output = output
	return m
}

func output(in worker.Worker, out any) error {
	w, ok := in.(*Worker)
	if !ok {
		return fmt.Errorf("expected *Worker, got %T", in)
	}
	switch outPtr := out.(type) {
	case *Runner:
		*outPtr = w
	default:
		return fmt.Errorf("expected *Runner output, got %T", out)
	}
	return nil
}

func (config ManifoldConfig) start(a agent.Agent) (worker.Worker, error) {
	agentConfig := a.CurrentConfig()

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
		Runtime:          runtime,
		PebbleBinaryPath: defaultPebbleBinaryPath,
	})
}
