// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
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
	Logger           logger.Logger
	DataDir          string
	ContainerNames   []string
	CharmMeta        map[string]ContainerMeta
	ImageDetails     map[string]ImageDetails
	CommandRunner    CommandRunner
	StorageResolver  StorageResolver
	StatusReporter   StatusReporter
	LogSink          LogSink
	PebbleSourcePath string // optional override for pebble binary source path
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
	logCancels     map[string]context.CancelFunc
	nerdctlBin     string
}

// New creates and starts a new container runner worker.
func New(config Config) (*Worker, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	w := &Worker{
		config:     config,
		logCancels: make(map[string]context.CancelFunc),
		nerdctlBin: "nerdctl",
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
		w.startLogTailing(name)
	}

	w.config.Logger.Infof(ctx, "all containers started, entering monitor loop")
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
	if w.logCancels == nil {
		w.logCancels = make(map[string]context.CancelFunc)
	}
	if cancel, ok := w.logCancels[containerName]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.logCancels[containerName] = cancel
	w.tomb.Go(func() error {
		return w.tailLogs(ctx, containerName)
	})
}

func (w *Worker) cancelLogTails() {
	for _, cancel := range w.logCancels {
		cancel()
	}
}

func (w *Worker) nerdctlCmd() string {
	if w.nerdctlBin != "" {
		return w.nerdctlBin
	}
	return "nerdctl"
}

func (w *Worker) tailLogs(ctx context.Context, containerName string) error {
	id := w.containerID(containerName)
	cmd := exec.CommandContext(ctx, w.nerdctlCmd(), "logs", "--follow", "--timestamps", id)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	go func() {
		w.forwardLogLines(containerName, stdout)
		done <- struct{}{}
	}()
	go func() {
		w.forwardLogLines(containerName, stderr)
		done <- struct{}{}
	}()
	<-done
	<-done
	return cmd.Wait()
}

func (w *Worker) forwardLogLines(containerName string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		ts, message := parseLogLine(scanner.Text())
		w.config.LogSink.Log(containerName, ts, message)
	}
}

func parseLogLine(line string) (time.Time, string) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return time.Time{}, line
	}
	ts, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, line
	}
	return ts, parts[1]
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
		if _, err := w.config.CommandRunner.Run(ctx, w.nerdctlCmd(), "start", id); err != nil {
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

// pebbleSourcePaths is the ordered list of paths to search for the pebble
// binary. The snap path is preferred; the /usr/lib/juju/bin fallback is for
// deb/rpm installations.
var pebbleSourcePaths = []string{
	"/snap/juju/current/bin/pebble",
	"/usr/lib/juju/bin/pebble",
}

// findPebbleSource returns the first existing pebble source path, or "" if none
// are found. If PebbleSourcePath is set in config, that takes precedence.
func (w *Worker) findPebbleSource() string {
	if w.config.PebbleSourcePath != "" {
		if _, err := os.Stat(w.config.PebbleSourcePath); err == nil {
			return w.config.PebbleSourcePath
		}
	}
	for _, p := range pebbleSourcePaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
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

	sourcePath := w.findPebbleSource()
	if sourcePath == "" {
		return fmt.Errorf("pebble binary not found in any of %v", pebbleSourcePaths)
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

	w.config.Logger.Infof(ctx, "copied pebble binary from %s to %s", sourcePath, destPath)
	return nil
}

// ensurePebbleCurrent checks if the pebble binary has been upgraded (e.g., after
// a juju snap update). If the source and deployed binaries differ, it replaces
// the deployed binary and sets pebbleUpgraded so containers are restarted.
func (w *Worker) ensurePebbleCurrent(ctx context.Context) error {
	sourcePath := w.findPebbleSource()
	if sourcePath == "" {
		// Source not available - skip check.
		return nil
	}
	destPath := filepath.Join(w.config.DataDir, "charm", "bin", "pebble")

	sourceHash, err := fileHash(sourcePath)
	if err != nil {
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

// ensureNerdctl checks that an OCI runtime CLI is available on the system.
// It expects a containerd + nerdctl setup.
func (w *Worker) ensureNerdctl(ctx context.Context) error {
	if bin, ok := w.detectNerdctl(ctx); ok {
		w.nerdctlBin = bin
		return nil
	}
	return fmt.Errorf("no supported container runtime found in PATH or known locations")
}

func (w *Worker) detectNerdctl(ctx context.Context) (string, bool) {
	if _, err := w.config.CommandRunner.Run(ctx, "nerdctl", "version"); err == nil {
		return "nerdctl", true
	}
	if _, err := w.config.CommandRunner.Run(ctx, "/snap/bin/nerdctl", "version"); err == nil {
		return "/snap/bin/nerdctl", true
	}
	if _, err := w.config.CommandRunner.Run(ctx, "/usr/lib/juju/bin/nerdctl", "version"); err == nil {
		return "/usr/lib/juju/bin/nerdctl", true
	}
	if _, err := w.config.CommandRunner.Run(ctx, "/snap/juju/current/usr/lib/juju/bin/nerdctl", "version"); err == nil {
		return "/snap/juju/current/usr/lib/juju/bin/nerdctl", true
	}
	local := filepath.Join(w.config.DataDir, "charm", "bin", "nerdctl")
	if _, err := w.config.CommandRunner.Run(ctx, local, "version"); err == nil {
		return local, true
	}
	return "", false
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
		if w.pebbleUpgraded || w.imageMismatch(ctx, id, containerName) {
			w.config.Logger.Infof(ctx, "replacing container %q", containerName)
			return w.replaceContainer(ctx, containerName)
		}
		w.config.Logger.Debugf(ctx, "container %q already running", containerName)
		return nil
	}

	// Check if container exists but is stopped.
	if w.isCreated(ctx, id) {
		w.config.Logger.Infof(ctx, "starting existing container %q", containerName)
		out, err := w.config.CommandRunner.Run(ctx, w.nerdctlCmd(), "start", id)
		if err != nil {
			return fmt.Errorf("starting container %q: %w (output: %s)", containerName, err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// Run a new container.
	return w.runContainer(ctx, containerName)
}

func (w *Worker) replaceContainer(ctx context.Context, containerName string) error {
	if err := w.stopContainer(ctx, containerName); err != nil {
		return fmt.Errorf("stopping container for replacement: %w", err)
	}
	return w.runContainer(ctx, containerName)
}

func (w *Worker) imageMismatch(ctx context.Context, id, containerName string) bool {
	image, ok := w.config.ImageDetails[containerName]
	if !ok || image.RegistryPath == "" {
		return false
	}
	expected := image.RegistryPath
	actual, err := w.currentImage(ctx, id)
	if err != nil {
		w.config.Logger.Warningf(ctx, "could not inspect image for container %q: %v", containerName, err)
		return false
	}
	return actual != expected
}

func (w *Worker) currentImage(ctx context.Context, id string) (string, error) {
	out, err := w.config.CommandRunner.Run(ctx, w.nerdctlCmd(), "inspect", "--format", "{{.Image}}", id)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (w *Worker) containerImage(containerName string) string {
	if image, ok := w.config.ImageDetails[containerName]; ok && image.RegistryPath != "" {
		return image.RegistryPath
	}
	return "ubuntu:22.04"
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
		"-v", fmt.Sprintf("%s:/charm/container", socketDir),
		"-e", fmt.Sprintf("JUJU_CONTAINER_NAME=%s", containerName),
		"-e", "PEBBLE_SOCKET=/charm/container/pebble.socket",
		"-e", "PEBBLE=/charm/container",
		"-e", "PEBBLE_COPY_ONCE=/var/lib/pebble/default",
		"--entrypoint", "/charm/bin/pebble",
	}
	if _, err := os.Stat(pebbleBin); err == nil {
		args = append(args, "-v", fmt.Sprintf("%s:/charm/bin/pebble:ro", pebbleBin))
	} else {
		w.config.Logger.Warningf(ctx, "local pebble binary %q not present; relying on image-provided /charm/bin/pebble", pebbleBin)
	}
	storageArgs, err := w.storageMountArgs(ctx, containerName)
	if err != nil {
		return err
	}
	args = append(args, storageArgs...)
	args = append(args,
		w.containerImage(containerName),
		"run", "--create-dirs", "--hold", "--verbose",
	)

	w.config.Logger.Infof(ctx, "running container %q", containerName)
	out, err := w.config.CommandRunner.Run(ctx, w.nerdctlCmd(), args...)
	if err != nil {
		return fmt.Errorf("running container %q: %w (output: %s)", containerName, err, strings.TrimSpace(string(out)))
	}
	return nil
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
	_, _ = w.config.CommandRunner.Run(ctx, w.nerdctlCmd(), "stop", "--time", "30", id)
	_, err := w.config.CommandRunner.Run(ctx, w.nerdctlCmd(), "rm", id)
	return err
}

// isRunning checks if a container is currently running.
func (w *Worker) isRunning(ctx context.Context, id string) (bool, error) {
	out, err := w.config.CommandRunner.Run(ctx, w.nerdctlCmd(), "inspect", "--format", "{{.State.Running}}", id)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

// isCreated checks if a container exists (running or stopped).
func (w *Worker) isCreated(ctx context.Context, id string) bool {
	_, err := w.config.CommandRunner.Run(ctx, w.nerdctlCmd(), "inspect", id)
	return err == nil
}
