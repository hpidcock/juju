// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"os/exec"
	"strings"

	"github.com/juju/worker/v5"
	"github.com/juju/worker/v5/dependency"

	"github.com/juju/juju/agent"
	"github.com/juju/juju/agent/engine"
	"github.com/juju/juju/core/logger"
)

// ManifoldConfig defines the configuration for the container runner manifold.
type ManifoldConfig struct {
	AgentName      string
	ContainerNames []string
	Logger         logger.Logger
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

	return engine.AgentManifold(engine.AgentManifoldConfig{
		AgentName: config.AgentName,
	}, config.start)
}

func (config ManifoldConfig) start(a agent.Agent) (worker.Worker, error) {
	agentConfig := a.CurrentConfig()

	return New(Config{
		Logger:         config.Logger,
		DataDir:        agentConfig.Dir(),
		ContainerNames: config.ContainerNames,
		CommandRunner:  &defaultCommandRunner{},
	})
}

// defaultCommandRunner executes commands on the host system.
type defaultCommandRunner struct{}

func (r *defaultCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func (r *defaultCommandRunner) RunStdin(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.CombinedOutput()
}
