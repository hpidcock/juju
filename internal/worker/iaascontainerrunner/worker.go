// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/tomb.v2"

	"github.com/juju/juju/core/logger"
)

// CommandRunner is an interface for executing system commands.
// It enables testing without actually running nerdctl.
type CommandRunner interface {
	// Run executes a command and returns combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// RunStdin executes a command with stdin input and returns combined output.
	RunStdin(ctx context.Context, stdin string, name string, args ...string) ([]byte, error)
}

// Config holds the configuration for the container runner worker.
type Config struct {
	Logger          logger.Logger
	DataDir         string
	ContainerNames  []string
	CharmMeta       map[string]ContainerMeta
	CommandRunner   CommandRunner
	StorageResolver StorageResolver
	StatusReporter  StatusReporter
}

// ContainerMeta describes IAAS-specific runtime metadata for a charm
// container.
type ContainerMeta struct {
	ResourceName string
	Mounts       []Mount
}

// Mount describes a charm-declared storage mount for a container.
type Mount struct {
	StorageName string
	Location    string
}

// StorageResolver resolves charm storage names to host mount paths.
type StorageResolver interface {
	GetStorageMountPath(ctx context.Context, storageName string) (string, error)
}

// ContainerStatus captures the runtime status of a workload container.
type ContainerStatus struct {
	State   string
	Message string
}

// StatusReporter optionally receives container status updates.
type StatusReporter interface {
	ReportContainerStatus(ctx context.Context, containerName string, status ContainerStatus) error
}

// Validate returns an error if the config is invalid.
func (c Config) Validate() error {
	if c.Logger == nil {
		return fmt.Errorf("nil Logger not valid")
	}
	if c.DataDir == "" {
		return fmt.Errorf("empty DataDir not valid")
	}
	if len(c.ContainerNames) == 0 {
		return fmt.Errorf("empty ContainerNames not valid")
	}
	if c.CommandRunner == nil {
		return fmt.Errorf("nil CommandRunner not valid")
	}
	return nil
}

// Worker manages OCI workload containers for a unit on an IAAS machine.
type Worker struct {
	tomb           tomb.Tomb
	config         Config
	pebbleUpgraded bool
}

// New creates and starts a new container runner worker.
func New(config Config) (*Worker, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	w := &Worker{config: config}
	w.tomb.Go(w.loop)
	return w, nil
}

// Kill implements worker.Worker.
func (w *Worker) Kill() {
	w.tomb.Kill(nil)
}

// Wait implements worker.Worker.
func (w *Worker) Wait() error {
	return w.tomb.Wait()
}

func (w *Worker) loop() error {
	ctx := w.tomb.Context(context.Background())

	if err := w.ensurePebbleBinary(ctx); err != nil {
		return fmt.Errorf("ensuring pebble binary: %w", err)
	}

	if err := w.ensurePebbleCurrent(ctx); err != nil {
		return fmt.Errorf("ensuring pebble current: %w", err)
	}

	if err := w.ensureNerdctl(ctx); err != nil {
		return fmt.Errorf("ensuring nerdctl: %w", err)
	}

	for _, name := range w.config.ContainerNames {
		if err := w.ensureContainerDirs(name); err != nil {
			return fmt.Errorf("creating container dirs for %q: %w", name, err)
		}
		if err := w.ensureRunning(ctx, name); err != nil {
			return fmt.Errorf("ensuring container %q running: %w", name, err)
		}
	}

	w.config.Logger.Infof(ctx, "all containers started, entering monitor loop")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.tomb.Dying():
			// Stop all containers gracefully.
			for _, name := range w.config.ContainerNames {
				if err := w.stopContainer(context.Background(), name); err != nil {
					w.config.Logger.Errorf(context.Background(), "stopping container %q: %v", name, err)
				}
			}
			return tomb.ErrDying
		case <-ticker.C:
			w.monitorContainers(ctx)
		}
	}
}

func (w *Worker) monitorContainers(ctx context.Context) {
	for _, name := range w.config.ContainerNames {
		id := w.containerID(name)
		running, err := w.isRunning(ctx, id)
		if err != nil {
			w.reportStatus(ctx, name, ContainerStatus{State: "unknown", Message: err.Error()})
			continue
		}
		if running {
			w.reportStatus(ctx, name, ContainerStatus{State: "running", Message: "container running"})
			continue
		}

		w.config.Logger.Warningf(ctx, "container %q is not running, attempting restart", name)
		if _, err := w.config.CommandRunner.Run(ctx, "nerdctl", "start", id); err != nil {
			w.reportStatus(ctx, name, ContainerStatus{State: "crashed", Message: err.Error()})
			continue
		}
		w.reportStatus(ctx, name, ContainerStatus{State: "running", Message: "container restarted"})
	}
}

func (w *Worker) reportStatus(ctx context.Context, containerName string, status ContainerStatus) {
	if w.config.StatusReporter == nil {
		return
	}
	if err := w.config.StatusReporter.ReportContainerStatus(ctx, containerName, status); err != nil {
		w.config.Logger.Errorf(ctx, "reporting container status for %q failed: %v", containerName, err)
	}
}

// containerID returns the nerdctl container name for a given container.
func (w *Worker) containerID(containerName string) string {
	// Use the unit's directory name as a unique prefix.
	// DataDir is like /var/lib/juju/agents/unit-app-0
	base := filepath.Base(w.config.DataDir)
	return fmt.Sprintf("juju-%s-%s", base, containerName)
}

// ensurePebbleBinary ensures the pebble binary is available in the unit's
// charm/bin/ directory.
func (w *Worker) ensurePebbleBinary(ctx context.Context) error {
	destDir := filepath.Join(w.config.DataDir, "charm", "bin")
	destPath := filepath.Join(destDir, "pebble")

	// Check if already exists.
	if _, err := os.Stat(destPath); err == nil {
		return nil
	}

	// Look for pebble in the snap.
	sourcePath := "/snap/juju/current/bin/pebble"
	if _, err := os.Stat(sourcePath); err != nil {
		return fmt.Errorf("pebble binary not found at %s: %w", sourcePath, err)
	}

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("creating charm bin dir: %w", err)
	}

	// Copy the binary.
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("reading pebble binary: %w", err)
	}
	if err := os.WriteFile(destPath, data, 0755); err != nil {
		return fmt.Errorf("writing pebble binary: %w", err)
	}

	w.config.Logger.Infof(ctx, "copied pebble binary to %s", destPath)
	return nil
}

// ensurePebbleCurrent checks if the pebble binary has been upgraded (e.g., after
// a juju snap update). If the source and deployed binaries differ, it replaces
// the deployed binary and sets pebbleUpgraded so containers are restarted.
func (w *Worker) ensurePebbleCurrent(ctx context.Context) error {
	sourcePath := "/snap/juju/current/bin/pebble"
	destPath := filepath.Join(w.config.DataDir, "charm", "bin", "pebble")

	sourceHash, err := fileHash(sourcePath)
	if err != nil {
		// Source not available (e.g., not running from snap) - skip check.
		return nil
	}
	destHash, err := fileHash(destPath)
	if err != nil {
		// Destination doesn't exist - ensurePebbleBinary should have handled this.
		return nil
	}

	if sourceHash == destHash {
		return nil
	}

	w.config.Logger.Infof(ctx, "pebble binary changed, updating deployed binary")
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("reading updated pebble binary: %w", err)
	}
	if err := os.WriteFile(destPath, data, 0755); err != nil {
		return fmt.Errorf("writing updated pebble binary: %w", err)
	}
	w.pebbleUpgraded = true
	return nil
}

// fileHash computes the SHA256 hash of a file.
func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// ensureNerdctl checks that nerdctl is available on the system.
func (w *Worker) ensureNerdctl(ctx context.Context) error {
	_, err := w.config.CommandRunner.Run(ctx, "nerdctl", "version")
	if err == nil {
		return nil
	}

	w.config.Logger.Infof(ctx, "nerdctl not found, attempting snap install")
	_, err = w.config.CommandRunner.Run(ctx, "snap", "install", "nerdctl", "--classic")
	if err != nil {
		return fmt.Errorf("installing nerdctl: %w", err)
	}
	return nil
}

// ensureContainerDirs creates the socket directory for the container.
func (w *Worker) ensureContainerDirs(containerName string) error {
	socketDir := filepath.Join(w.config.DataDir, "charm", "containers", containerName)
	return os.MkdirAll(socketDir, 0755)
}

// ensureRunning checks if a container is running and starts it if not.
func (w *Worker) ensureRunning(ctx context.Context, containerName string) error {
	id := w.containerID(containerName)

	// Check if already running.
	running, err := w.isRunning(ctx, id)
	if err == nil && running {
		// If pebble was upgraded, force container replacement to pick up new binary.
		if w.pebbleUpgraded {
			w.config.Logger.Infof(ctx, "pebble upgraded, replacing container %q", containerName)
			if err := w.stopContainer(ctx, containerName); err != nil {
				return fmt.Errorf("stopping container for pebble upgrade: %w", err)
			}
			return w.runContainer(ctx, containerName)
		}
		w.config.Logger.Debugf(ctx, "container %q already running", containerName)
		return nil
	}

	// Check if container exists but is stopped.
	if w.isCreated(ctx, id) {
		w.config.Logger.Infof(ctx, "starting existing container %q", containerName)
		_, err := w.config.CommandRunner.Run(ctx, "nerdctl", "start", id)
		return err
	}

	// Run a new container.
	return w.runContainer(ctx, containerName)
}

// runContainer starts a new container with nerdctl.
func (w *Worker) runContainer(ctx context.Context, containerName string) error {
	id := w.containerID(containerName)
	pebbleBin := filepath.Join(w.config.DataDir, "charm", "bin", "pebble")
	socketDir := filepath.Join(w.config.DataDir, "charm", "containers", containerName)

	args := []string{
		"run", "-d",
		"--name", id,
		"--network", "host",
		"--restart", "unless-stopped",
		"-v", fmt.Sprintf("%s:/charm/bin/pebble:ro", pebbleBin),
		"-v", fmt.Sprintf("%s:/charm/container", socketDir),
		"-e", fmt.Sprintf("JUJU_CONTAINER_NAME=%s", containerName),
		"-e", "PEBBLE_SOCKET=/charm/container/pebble.socket",
		"-e", "PEBBLE=/charm/bin/pebble",
		"-e", "PEBBLE_COPY_ONCE=/var/lib/pebble/default",
		"--entrypoint", "/charm/bin/pebble",
	}
	storageArgs, err := w.storageMountArgs(ctx, containerName)
	if err != nil {
		return err
	}
	args = append(args, storageArgs...)
	args = append(args,
		// Use ubuntu as a default base image; real implementation will
		// resolve from charm resources.
		"ubuntu:22.04",
		"run", "--create-dirs", "--hold", "--http", "", "--verbose",
	)

	w.config.Logger.Infof(ctx, "running container %q", containerName)
	_, err = w.config.CommandRunner.Run(ctx, "nerdctl", args...)
	return err
}

func (w *Worker) storageMountArgs(ctx context.Context, containerName string) ([]string, error) {
	if w.config.StorageResolver == nil {
		return nil, nil
	}
	meta := w.config.CharmMeta[containerName]
	args := make([]string, 0, len(meta.Mounts)*2)
	for _, mount := range meta.Mounts {
		hostPath, err := w.config.StorageResolver.GetStorageMountPath(ctx, mount.StorageName)
		if err != nil {
			w.config.Logger.Warningf(ctx, "skipping storage mount %q for container %q: %v", mount.StorageName, containerName, err)
			continue
		}
		args = append(args, "-v", fmt.Sprintf("%s:%s", hostPath, mount.Location))
	}
	return args, nil
}

// stopContainer gracefully stops and removes a container.
func (w *Worker) stopContainer(ctx context.Context, containerName string) error {
	id := w.containerID(containerName)

	if !w.isCreated(ctx, id) {
		return nil
	}

	w.config.Logger.Infof(ctx, "stopping container %q", containerName)
	_, _ = w.config.CommandRunner.Run(ctx, "nerdctl", "stop", "--time", "30", id)
	_, err := w.config.CommandRunner.Run(ctx, "nerdctl", "rm", id)
	return err
}

// isRunning checks if a container is currently running.
func (w *Worker) isRunning(ctx context.Context, id string) (bool, error) {
	out, err := w.config.CommandRunner.Run(ctx, "nerdctl", "inspect", "--format", "{{.State.Running}}", id)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

// isCreated checks if a container exists (running or stopped).
func (w *Worker) isCreated(ctx context.Context, id string) bool {
	_, err := w.config.CommandRunner.Run(ctx, "nerdctl", "inspect", id)
	return err == nil
}
