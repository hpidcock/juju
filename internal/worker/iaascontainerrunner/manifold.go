// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/juju/names/v6"
	"github.com/juju/worker/v5"
	"github.com/juju/worker/v5/dependency"

	"github.com/juju/juju/agent"
	"github.com/juju/juju/agent/engine"
	apiclient "github.com/juju/juju/api/agent/iaascontainerrunner"
	"github.com/juju/juju/api/base"
	"github.com/juju/juju/core/logger"
)

// ManifoldConfig defines the configuration for the container runner manifold.
type ManifoldConfig struct {
	AgentName      string
	APICallerName  string
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
			Output: output,
		}
	}

	m := engine.AgentAPIManifold(engine.AgentAPIManifoldConfig{
		AgentName:     config.AgentName,
		APICallerName: config.APICallerName,
	}, config.start)
	m.Output = output
	return m
}

func output(in worker.Worker, out any) error {
	switch outPtr := out.(type) {
	case *worker.Worker:
		*outPtr = in
	default:
		return fmt.Errorf("expected *worker.Worker output, got %T", out)
	}
	return nil
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

	return New(Config{
		Logger:         config.Logger,
		DataDir:        agentConfig.Dir(),
		ContainerNames: config.ContainerNames,
		CharmMeta:      charmMeta,
		ImageDetails:   imageDetails,
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
