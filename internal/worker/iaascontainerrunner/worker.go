// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/tomb.v2"

	"github.com/juju/juju/core/logger"
)

// Config holds the configuration for the container runner worker.
type Config struct {
	Logger           logger.Logger
	DataDir          string
	ContainerNames   []string
	CharmMeta        map[string]ContainerMeta
	ImageDetails     map[string]ImageDetails
	Runtime          ContainerRuntime
	StorageResolver  StorageResolver
	StatusReporter   StatusReporter
	LogSink          LogSink
	PebbleBinaryPath string // host path of the pebble binary to mount into every container
	// ContainerSocketRoot is the root directory under which
	// /charm/containers/<name> socket directories are created on the host.
	// It defaults to "/" and is overridden in tests.
	ContainerSocketRoot string
}

// ImageDetails holds the information needed to pull and run an OCI image.
type ImageDetails struct {
	RegistryPath string
	Username     string
	Password     string
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

// LogSink optionally receives workload log messages emitted by containers.
type LogSink interface {
	Log(containerName string, timestamp time.Time, message string)
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
	if c.Runtime == nil {
		return fmt.Errorf("nil Runtime not valid")
	}
	return nil
}

// Worker manages OCI workload containers for a unit on an IAAS machine,
// delegating the actual container lifecycle to a ContainerRuntime.
type Worker struct {
	tomb       tomb.Tomb
	config     Config
	logCancels map[string]context.CancelFunc
}

// New creates and starts a new container runner worker.
func New(config Config) (*Worker, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if config.ContainerSocketRoot == "" {
		config.ContainerSocketRoot = "/"
	}
	w := &Worker{
		config:     config,
		logCancels: make(map[string]context.CancelFunc),
	}
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

	for _, name := range w.config.ContainerNames {
		if err := w.ensureContainerDirs(name); err != nil {
			return fmt.Errorf("creating container dirs for %q: %w", name, err)
		}
		spec, err := w.buildContainerSpec(ctx, name)
		if err != nil {
			return fmt.Errorf("building container spec for %q: %w", name, err)
		}
		if err := w.config.Runtime.EnsureRunning(ctx, spec); err != nil {
			return fmt.Errorf("ensuring container %q running: %w", name, err)
		}
		w.startLogTailing(name)
	}

	w.config.Logger.Infof(ctx, "all containers started, entering monitor loop")

	// If the runtime implements PortProxyRunner, start it in a background
	// goroutine under the worker's tomb so it is cancelled when the worker
	// stops.
	if runner, ok := w.config.Runtime.(PortProxyRunner); ok {
		w.tomb.Go(func() error {
			if err := runner.RunPortProxy(w.tomb.Context(context.Background())); err != nil {
				w.config.Logger.Warningf(context.Background(), "port proxy stopped: %v", err)
			}
			return nil
		})
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.tomb.Dying():
			w.cancelLogTails()
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

func (w *Worker) startLogTailing(containerName string) {
	if w.config.LogSink == nil {
		return
	}
	tailer, ok := w.config.Runtime.(LogTailer)
	if !ok {
		return
	}
	if w.logCancels == nil {
		w.logCancels = make(map[string]context.CancelFunc)
	}
	if cancel, ok := w.logCancels[containerName]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.logCancels[containerName] = cancel
	id := w.containerID(containerName)
	sink := containerLogSink{name: containerName, sink: w.config.LogSink}
	w.tomb.Go(func() error {
		return tailer.TailLogs(ctx, id, sink)
	})
}

func (w *Worker) cancelLogTails() {
	for _, cancel := range w.logCancels {
		cancel()
	}
}

// containerLogSink adapts a LogSink so that log lines reported against a
// runtime-specific container id are attributed to the charm's container
// name instead.
type containerLogSink struct {
	name string
	sink LogSink
}

func (c containerLogSink) Log(_ string, timestamp time.Time, message string) {
	c.sink.Log(c.name, timestamp, message)
}

func (w *Worker) monitorContainers(ctx context.Context) {
	for _, name := range w.config.ContainerNames {
		id := w.containerID(name)
		status, err := w.config.Runtime.Status(ctx, id)
		if err != nil {
			w.reportStatus(ctx, name, ContainerStatus{State: "unknown", Message: err.Error()})
			continue
		}
		if status.State == "running" {
			w.reportStatus(ctx, name, status)
			continue
		}

		w.config.Logger.Warningf(ctx, "container %q is not running (%s), attempting restart", name, status.State)
		spec, err := w.buildContainerSpec(ctx, name)
		if err != nil {
			w.reportStatus(ctx, name, ContainerStatus{State: "crashed", Message: err.Error()})
			continue
		}
		if err := w.config.Runtime.EnsureRunning(ctx, spec); err != nil {
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

// containerID returns the runtime-unique container name for a given charm
// container. The result only ever contains characters valid in an LXD
// instance name (letters, digits and hyphens).
func (w *Worker) containerID(containerName string) string {
	// Use the unit's directory name as a unique prefix.
	// DataDir is like /var/lib/juju/agents/unit-app-0
	base := filepath.Base(w.config.DataDir)
	id := fmt.Sprintf("juju-%s-%s", base, containerName)
	if len(id) <= 63 {
		return id
	}
	// Truncate and append a short hash to keep the name unique but within
	// LXD's 63 character instance name limit.
	sum := sha256.Sum256([]byte(id))
	suffix := fmt.Sprintf("-%x", sum[:4])
	return id[:63-len(suffix)] + suffix
}

// ensureContainerDirs creates the socket directory hierarchy for the
// container at <ContainerSocketRoot>/charm/containers/<containerName> on
// the host. Each directory is created owned by root (this worker always
// runs as root) and restricted to root-only access (0700).
func (w *Worker) ensureContainerDirs(containerName string) error {
	for _, dir := range []string{
		filepath.Join(w.config.ContainerSocketRoot, "charm"),
		filepath.Join(w.config.ContainerSocketRoot, "charm", "containers"),
		w.socketDir(containerName),
	} {
		if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) socketDir(containerName string) string {
	return filepath.Join(w.config.ContainerSocketRoot, "charm", "containers", containerName)
}

// buildContainerSpec resolves the desired ContainerSpec for a charm
// container, ready to be passed to the ContainerRuntime.
func (w *Worker) buildContainerSpec(ctx context.Context, containerName string) (ContainerSpec, error) {
	mounts, err := w.resolveMounts(ctx, containerName)
	if err != nil {
		return ContainerSpec{}, err
	}

	return ContainerSpec{
		Name:             w.containerID(containerName),
		Pod:              filepath.Base(w.config.DataDir),
		Image:            w.containerImageDetails(containerName),
		PebbleBinaryPath: w.config.PebbleBinaryPath,
		SocketDir:        w.socketDir(containerName),
		Env: map[string]string{
			"JUJU_CONTAINER_NAME": containerName,
			"PEBBLE_SOCKET":       "/charm/container/pebble.socket",
			"PEBBLE":              "/charm/container",
			"PEBBLE_COPY_ONCE":    "/var/lib/pebble/default",
		},
		Mounts: mounts,
	}, nil
}

// defaultImage is used when the charm resource for a container has not
// resolved to a specific OCI image reference.
const defaultImage = "docker.io/library/ubuntu:22.04"

func (w *Worker) containerImageDetails(containerName string) ImageDetails {
	image, ok := w.config.ImageDetails[containerName]
	if !ok || image.RegistryPath == "" {
		return ImageDetails{RegistryPath: defaultImage}
	}
	return image
}

func (w *Worker) resolveMounts(ctx context.Context, containerName string) ([]ResolvedMount, error) {
	if w.config.StorageResolver == nil {
		return nil, nil
	}
	meta := w.config.CharmMeta[containerName]
	mounts := make([]ResolvedMount, 0, len(meta.Mounts))
	for _, mount := range meta.Mounts {
		hostPath, err := w.config.StorageResolver.GetStorageMountPath(ctx, mount.StorageName)
		if err != nil {
			w.config.Logger.Warningf(ctx, "skipping storage mount %q for container %q: %v", mount.StorageName, containerName, err)
			continue
		}
		mounts = append(mounts, ResolvedMount{HostPath: hostPath, Location: mount.Location})
	}
	return mounts, nil
}

// stopContainer gracefully stops and removes a container.
func (w *Worker) stopContainer(ctx context.Context, containerName string) error {
	return w.config.Runtime.Stop(ctx, w.containerID(containerName))
}
