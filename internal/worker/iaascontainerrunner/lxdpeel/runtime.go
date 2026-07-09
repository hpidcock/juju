// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package lxdpeel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	lxdclient "github.com/canonical/lxd/client"
	lxdapi "github.com/canonical/lxd/shared/api"

	"github.com/juju/juju/internal/worker/iaascontainerrunner"
)

const (
	// DefaultImageServer is the simplestreams server peel images are
	// published to, as documented at https://github.com/canonical/peel.
	DefaultImageServer = "https://github.com/canonical/peel/releases/download"

	// DefaultImageAlias is the image alias peel images are published
	// under on DefaultImageServer.
	DefaultImageAlias = "peel"

	// pebbleEntrypoint is where the pebble binary is bind-mounted inside
	// every container, and is always used as peel's entrypoint override.
	pebbleEntrypoint = "/charm/bin/pebble"

	// zfsMagic is the filesystem type constant for ZFS (ZFS_SUPER_MAGIC
	// from include/uapi/linux/magic.h).
	zfsMagic = 0x2fc12fc1
)

// pebbleArgs are the arguments passed to the pebble entrypoint.
var pebbleArgs = []string{"run", "--create-dirs", "--hold", "--verbose"}

// isOnZFS reports whether the directory at path resides on a ZFS
// filesystem. Defined as a variable for overriding in tests.
var isOnZFS = func(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	return st.Type == zfsMagic
}

// isNestedLXDContainer reports whether the current process is running inside
// a LXD container by checking for the devlxd socket. Defined as a variable
// for overriding in tests.
var isNestedLXDContainer = func() bool {
	_, err := os.Stat("/dev/lxd/sock")
	return err == nil
}

// instanceServer is the subset of the LXD client.InstanceServer interface
// used by this package. It is defined locally so tests can supply a fake
// implementation without needing a running LXD daemon.
type instanceServer interface {
	GetInstance(name string) (*lxdapi.Instance, string, error)
	CreateInstance(instance lxdapi.InstancesPost) (lxdclient.Operation, error)
	UpdateInstanceState(name string, state lxdapi.InstanceStatePut, ETag string) (lxdclient.Operation, error)
	DeleteInstance(name string) (lxdclient.Operation, error)
	GetInstanceState(name string) (*lxdapi.InstanceState, string, error)
	GetInstanceConsoleLog(name string, args *lxdclient.InstanceConsoleLogArgs) (io.ReadCloser, error)
}

// Runtime implements iaascontainerrunner.ContainerRuntime using LXD and
// peel.
type Runtime struct {
	client      instanceServer
	imageServer string
	imageAlias  string
	dataDir     string
}

var (
	_ iaascontainerrunner.ContainerRuntime = (*Runtime)(nil)
	_ iaascontainerrunner.LogTailer        = (*Runtime)(nil)
)

// New returns a Runtime that talks to the local LXD daemon over its default
// unix socket. It installs and initialises LXD and pebble if they are not
// already present on the host.
func New(dataDir string) (*Runtime, error) {
	if err := Initialise(DefaultLXDSnapChannel); err != nil {
		return nil, fmt.Errorf("initialising lxdpeel: %w", err)
	}
	client, err := lxdclient.ConnectLXDUnix("", nil)
	if err != nil {
		return nil, fmt.Errorf("connecting to local LXD: %w", err)
	}
	return NewWithClient(client, dataDir), nil
}

// NewWithClient returns a Runtime that uses the given LXD instance server.
// It is exposed primarily for testing.
func NewWithClient(client instanceServer, dataDir string) *Runtime {
	return &Runtime{
		client:      client,
		imageServer: DefaultImageServer,
		imageAlias:  DefaultImageAlias,
		dataDir:     dataDir,
	}
}

// EnsureRunning implements iaascontainerrunner.ContainerRuntime.
func (r *Runtime) EnsureRunning(ctx context.Context, spec iaascontainerrunner.ContainerSpec) error {
	loopbackDir := r.loopbackDir()
	if err := ensureLoopbackDir(loopbackDir); err != nil {
		return fmt.Errorf("creating peel loopback dir for %q: %w", spec.Name, err)
	}

	// Use privileged mode when the source directories are on ZFS and the
	// host is itself a LXD container. In a nested LXD setup, mount_setattr
	// idmapped mounts (shift=true) do not work on ZFS because the nested
	// kernel's access to ZFS idmap operations is restricted. On bare-metal
	// ZFS, LXD uses the native ZFS idmap path and shift=true works there.
	privileged := isOnZFS(spec.SocketDir) && isNestedLXDContainer()

	config, devices, err := renderConfig(spec, privileged, loopbackDir)
	if err != nil {
		return fmt.Errorf("rendering LXD config for container %q: %w", spec.Name, err)
	}

	inst, _, err := r.client.GetInstance(spec.Name)
	if err != nil {
		if !lxdapi.StatusErrorCheck(err, http.StatusNotFound) {
			return fmt.Errorf("getting container %q: %w", spec.Name, err)
		}
		return r.createInstance(ctx, spec.Name, config, devices)
	}

	if !configMatches(inst.Config, config) || !devicesMatch(inst.Devices, devices) {
		if err := r.Stop(ctx, spec.Name); err != nil {
			return fmt.Errorf("replacing container %q: %w", spec.Name, err)
		}
		return r.createInstance(ctx, spec.Name, config, devices)
	}

	if inst.StatusCode == lxdapi.Running {
		return nil
	}

	op, err := r.client.UpdateInstanceState(spec.Name, lxdapi.InstanceStatePut{
		Action:  "start",
		Timeout: -1,
	}, "")
	if err != nil {
		return fmt.Errorf("starting container %q: %w", spec.Name, err)
	}
	return op.WaitContext(ctx)
}

func (r *Runtime) createInstance(ctx context.Context, name string, config map[string]string, devices map[string]map[string]string) error {
	op, err := r.client.CreateInstance(lxdapi.InstancesPost{
		Name: name,
		Type: lxdapi.InstanceTypeContainer,
		Source: lxdapi.InstanceSource{
			Type:     "image",
			Server:   r.imageServer,
			Protocol: "simplestreams",
			Alias:    r.imageAlias,
		},
		InstancePut: lxdapi.InstancePut{
			Config:  config,
			Devices: devices,
		},
		Start: true,
	})
	if err != nil {
		return fmt.Errorf("creating container %q: %w", name, err)
	}
	return op.WaitContext(ctx)
}

// Status implements iaascontainerrunner.ContainerRuntime.
func (r *Runtime) Status(ctx context.Context, name string) (iaascontainerrunner.ContainerStatus, error) {
	state, _, err := r.client.GetInstanceState(name)
	if err != nil {
		if lxdapi.StatusErrorCheck(err, http.StatusNotFound) {
			return iaascontainerrunner.ContainerStatus{State: "stopped", Message: "container does not exist"}, nil
		}
		return iaascontainerrunner.ContainerStatus{}, fmt.Errorf("getting state for container %q: %w", name, err)
	}
	switch state.StatusCode {
	case lxdapi.Running:
		return iaascontainerrunner.ContainerStatus{State: "running", Message: state.Status}, nil
	case lxdapi.Stopped:
		return iaascontainerrunner.ContainerStatus{State: "stopped", Message: state.Status}, nil
	default:
		return iaascontainerrunner.ContainerStatus{State: "unknown", Message: state.Status}, nil
	}
}

// Stop implements iaascontainerrunner.ContainerRuntime.
func (r *Runtime) Stop(ctx context.Context, name string) error {
	inst, _, err := r.client.GetInstance(name)
	if err != nil {
		if lxdapi.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("getting container %q: %w", name, err)
	}

	if inst.StatusCode != lxdapi.Stopped {
		op, err := r.client.UpdateInstanceState(name, lxdapi.InstanceStatePut{
			Action:  "stop",
			Timeout: 30,
			Force:   true,
		}, "")
		if err != nil {
			return fmt.Errorf("stopping container %q: %w", name, err)
		}
		if err := op.WaitContext(ctx); err != nil {
			return fmt.Errorf("stopping container %q: %w", name, err)
		}
	}

	op, err := r.client.DeleteInstance(name)
	if err != nil {
		if lxdapi.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("deleting container %q: %w", name, err)
	}
	return op.WaitContext(ctx)
}

// TailLogs implements iaascontainerrunner.LogTailer by polling LXD's
// console log for the container. This is best-effort: peel's own boot
// messages and the entrypoint's stdout/stderr are written to the
// container's console, but individual log lines carry no timestamp of
// their own, so timestamps reflect when this worker observed the line
// rather than when it was written.
func (r *Runtime) TailLogs(ctx context.Context, name string, sink iaascontainerrunner.LogSink) error {
	var offset int64
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		rc, err := r.client.GetInstanceConsoleLog(name, &lxdclient.InstanceConsoleLogArgs{})
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || int64(len(data)) <= offset {
			continue
		}

		newData := data[offset:]
		offset = int64(len(data))
		for line := range strings.SplitSeq(strings.TrimRight(string(newData), "\n"), "\n") {
			if line == "" {
				continue
			}
			sink.Log(name, time.Now(), line)
		}
	}
}

// managedConfigKeys are the LXD instance configuration keys this package
// manages. Comparisons against a live instance's configuration are
// restricted to these keys, since LXD populates many other ("volatile.*"
// etc.) keys we don't own.
var managedConfigKeys = []string{
	"user.oci.image",
	"user.oci.username",
	"user.oci.password",
	"user.oci.entrypoint",
	"user.oci.cmd",
	"user.oci.env",
	"security.devlxd",
	"security.privileged",
}

// loopbackDir returns the host path of the peel loopback directory for
// this unit, at <dataDir>/peel/lo. It is shared by all containers in the
// same pod and mounted inside each at /peel/lo.
//
// Returns "" when r.dataDir is empty, suppressing the /peel/lo device.
func (r *Runtime) loopbackDir() string {
	if r.dataDir == "" {
		return ""
	}
	return filepath.Join(r.dataDir, "peel", "lo")
}

// ensureLoopbackDir creates the loopback directory on the host if it does
// not yet exist. It is a no-op when dir is empty.
func ensureLoopbackDir(dir string) error {
	if dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}

// renderConfig computes the desired LXD instance configuration and devices
// for spec. When privileged is true the container runs with
// security.privileged=true (container UID 0 = host UID 0) and no per-device
// idmapped mounts; this is required when the source directories are on ZFS
// inside a nested LXD container where mount_setattr idmapping does not work.
// When privileged is false, shift=true is used on all writable disk devices
// instead.
func renderConfig(spec iaascontainerrunner.ContainerSpec, privileged bool, loopbackDir string) (map[string]string, map[string]map[string]string, error) {
	entrypoint, err := json.Marshal([]string{pebbleEntrypoint})
	if err != nil {
		return nil, nil, err
	}
	cmd, err := json.Marshal(pebbleArgs)
	if err != nil {
		return nil, nil, err
	}

	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	// Sort for deterministic comparisons against the live instance config.
	sort.Strings(env)
	envJSON, err := json.Marshal(env)
	if err != nil {
		return nil, nil, err
	}

	image := spec.Image.RegistryPath

	privilegedVal := "false"
	if privileged {
		privilegedVal = "true"
	}

	config := map[string]string{
		"user.oci.image":      image,
		"user.oci.entrypoint": string(entrypoint),
		"user.oci.cmd":        string(cmd),
		"user.oci.env":        string(envJSON),
		// Prevent the container from reading its own LXD instance
		// configuration (which includes OCI registry credentials).
		"security.devlxd": "false",
		// See renderConfig godoc for privileged mode rationale.
		"security.privileged": privilegedVal,
	}
	if spec.Image.Username != "" {
		config["user.oci.username"] = spec.Image.Username
	}
	if spec.Image.Password != "" {
		config["user.oci.password"] = spec.Image.Password
	}

	charmContainer := map[string]string{
		"type":   "disk",
		"source": spec.SocketDir,
		"path":   "/charm/container",
	}
	if !privileged {
		// shift remaps container UID 0 → host UID 0 for this mount so
		// that pebble can write to the socket directory (owned by host
		// root). Not needed when security.privileged=true.
		charmContainer["shift"] = "true"
	}
	devices := map[string]map[string]string{
		"charm-container": charmContainer,
	}

	if spec.PebbleBinaryPath != "" {
		devices["pebble-bin"] = map[string]string{
			"type":     "disk",
			"source":   spec.PebbleBinaryPath,
			"path":     pebbleEntrypoint,
			"readonly": "true",
			// No shift needed: the binary is read-only and has execute
			// permission for all (0755), so it is accessible without
			// UID remapping in either mode.
		}
	}
	if loopbackDir != "" {
		loDevice := map[string]string{
			"type":   "disk",
			"source": loopbackDir,
			"path":   "/peel/lo",
		}
		if !privileged {
			loDevice["shift"] = "true"
		}
		devices["peel-lo"] = loDevice
	}
	for i, m := range spec.Mounts {
		storageDevice := map[string]string{
			"type":   "disk",
			"source": m.HostPath,
			"path":   m.Location,
		}
		if !privileged {
			storageDevice["shift"] = "true"
		}
		devices[fmt.Sprintf("storage-%d", i)] = storageDevice
	}

	return config, devices, nil
}

// configMatches reports whether actual already has the values we manage in
// desired.
func configMatches(actual, desired map[string]string) bool {
	for _, key := range managedConfigKeys {
		if actual[key] != desired[key] {
			return false
		}
	}
	return true
}

// isManagedDeviceName reports whether name is one of the device names this
// package creates.
func isManagedDeviceName(name string) bool {
	switch name {
	case "charm-container", "pebble-bin", "peel-lo":
		return true
	default:
		return strings.HasPrefix(name, "storage-")
	}
}

// devicesMatch reports whether actual already has the devices we manage in
// desired, and no longer has any managed device that desired no longer
// wants (e.g. a charm storage mount that has since been detached).
func devicesMatch(actual, desired map[string]map[string]string) bool {
	for name, dev := range desired {
		actualDev, ok := actual[name]
		if !ok {
			return false
		}
		for k, v := range dev {
			if actualDev[k] != v {
				return false
			}
		}
	}
	for name := range actual {
		if _, ok := desired[name]; !ok && isManagedDeviceName(name) {
			return false
		}
	}
	return true
}
