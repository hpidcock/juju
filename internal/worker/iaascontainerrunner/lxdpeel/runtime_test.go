// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package lxdpeel

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	lxdclient "github.com/canonical/lxd/client"
	lxdapi "github.com/canonical/lxd/shared/api"
	"github.com/gorilla/websocket"
	"github.com/juju/tc"

	"github.com/juju/juju/internal/worker/iaascontainerrunner"
)

type runtimeSuite struct{}

func TestRuntimeSuite(t *testing.T) {
	tc.Run(t, &runtimeSuite{})
}

func (s *runtimeSuite) TestEnsureRunningCreatesNewContainer(c *tc.C) {
	// Pin to non-privileged so the test is independent of the machine's
	// filesystem type and whether it is running inside a LXD container.
	origOnZFS := isOnZFS
	origNested := isNestedLXDContainer
	defer func() {
		isOnZFS = origOnZFS
		isNestedLXDContainer = origNested
	}()
	isOnZFS = func(string) bool { return false }
	isNestedLXDContainer = func() bool { return false }

	fake := newFakeServer()
	baseDir := c.MkDir()
	r := NewWithClient(fake, baseDir)

	socketDir := filepath.Join(baseDir, "charm", "containers", "workload")
	loopbackDir := filepath.Join(baseDir, "peel", "lo")

	spec := iaascontainerrunner.ContainerSpec{
		Name:             "juju-unit-mysql-0-workload",
		Image:            iaascontainerrunner.ImageDetails{RegistryPath: "docker.io/library/nginx:1.27"},
		PebbleBinaryPath: "/snap/pebble/current/bin/pebble",
		SocketDir:        socketDir,
		Pod:              "unit-mysql-0",
		Env:              map[string]string{"JUJU_CONTAINER_NAME": "workload"},
	}

	err := r.EnsureRunning(c.Context(), spec)
	c.Assert(err, tc.ErrorIsNil)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	inst, ok := fake.instances[spec.Name]
	c.Assert(ok, tc.IsTrue)
	c.Check(inst.Config["user.oci.image"], tc.Equals, "docker.io/library/nginx:1.27")
	c.Check(inst.Config["security.devlxd"], tc.Equals, "false")
	c.Check(inst.Config["security.privileged"], tc.Equals, "false")
	c.Check(inst.Devices["pebble-bin"]["source"], tc.Equals, "/snap/pebble/current/bin/pebble")
	c.Check(inst.Devices["pebble-bin"]["path"], tc.Equals, "/charm/bin/pebble")
	c.Check(inst.Devices["pebble-bin"]["shift"], tc.Equals, "") // no shift on read-only binary
	c.Check(inst.Devices["peel-lo"]["source"], tc.Equals, loopbackDir)
	c.Check(inst.Devices["peel-lo"]["path"], tc.Equals, "/peel/lo")
	c.Check(inst.Devices["peel-lo"]["shift"], tc.Equals, "true")
	c.Check(inst.Devices["charm-container"]["source"], tc.Equals, spec.SocketDir)
	c.Check(inst.Devices["charm-container"]["shift"], tc.Equals, "true")
	c.Check(fake.createCalls, tc.Equals, 1)
}

// TestEnsureRunningCreatesPrivilegedContainerInNestedZFS verifies that when
// the agent is running inside a nested LXD container on ZFS (where
// mount_setattr idmapped mounts don't work), the container is created with
// security.privileged=true and no shift on disk devices.
func (s *runtimeSuite) TestEnsureRunningCreatesPrivilegedContainerInNestedZFS(c *tc.C) {
	origOnZFS := isOnZFS
	origNested := isNestedLXDContainer
	defer func() {
		isOnZFS = origOnZFS
		isNestedLXDContainer = origNested
	}()
	isOnZFS = func(string) bool { return true }
	isNestedLXDContainer = func() bool { return true }

	fake := newFakeServer()
	baseDir := c.MkDir()
	r := NewWithClient(fake, baseDir)

	socketDir := filepath.Join(baseDir, "charm", "containers", "workload")

	spec := iaascontainerrunner.ContainerSpec{
		Name:             "juju-unit-mysql-0-workload",
		Image:            iaascontainerrunner.ImageDetails{RegistryPath: "docker.io/library/nginx:1.27"},
		PebbleBinaryPath: "/snap/pebble/current/bin/pebble",
		SocketDir:        socketDir,
		Pod:              "unit-mysql-0",
		Env:              map[string]string{"JUJU_CONTAINER_NAME": "workload"},
	}

	err := r.EnsureRunning(c.Context(), spec)
	c.Assert(err, tc.ErrorIsNil)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	inst, ok := fake.instances[spec.Name]
	c.Assert(ok, tc.IsTrue)
	c.Check(inst.Config["security.privileged"], tc.Equals, "true")
	// No shift on writable devices in privileged mode.
	c.Check(inst.Devices["charm-container"]["shift"], tc.Equals, "")
	c.Check(inst.Devices["peel-lo"]["shift"], tc.Equals, "")
	c.Check(fake.createCalls, tc.Equals, 1)
}

func (s *runtimeSuite) TestEnsureRunningStartsStoppedContainer(c *tc.C) {
	fake := newFakeServer()
	r := NewWithClient(fake, "")

	spec := iaascontainerrunner.ContainerSpec{
		Name:  "juju-unit-mysql-0-workload",
		Image: iaascontainerrunner.ImageDetails{RegistryPath: "docker.io/library/nginx:1.27"},
	}
	config, devices, err := renderConfig(spec, false, "")
	c.Assert(err, tc.ErrorIsNil)
	fake.instances[spec.Name] = &lxdapi.Instance{
		Name:       spec.Name,
		StatusCode: lxdapi.Stopped,
	}
	fake.instances[spec.Name].Config = config
	fake.instances[spec.Name].Devices = devices

	// Pin to non-privileged to match the renderConfig call above.
	origOnZFS := isOnZFS
	origNested := isNestedLXDContainer
	defer func() { isOnZFS = origOnZFS; isNestedLXDContainer = origNested }()
	isOnZFS = func(string) bool { return false }
	isNestedLXDContainer = func() bool { return false }

	err = r.EnsureRunning(c.Context(), spec)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(fake.createCalls, tc.Equals, 0)
	c.Check(fake.startCalls, tc.Equals, 1)
	c.Check(fake.instances[spec.Name].StatusCode, tc.Equals, lxdapi.Running)
}

func (s *runtimeSuite) TestEnsureRunningNoopWhenAlreadyRunning(c *tc.C) {
	fake := newFakeServer()
	r := NewWithClient(fake, "")

	spec := iaascontainerrunner.ContainerSpec{
		Name:  "juju-unit-mysql-0-workload",
		Image: iaascontainerrunner.ImageDetails{RegistryPath: "docker.io/library/nginx:1.27"},
	}
	config, devices, err := renderConfig(spec, false, "")
	c.Assert(err, tc.ErrorIsNil)
	fake.instances[spec.Name] = &lxdapi.Instance{
		Name:       spec.Name,
		StatusCode: lxdapi.Running,
	}
	fake.instances[spec.Name].Config = config
	fake.instances[spec.Name].Devices = devices

	origOnZFS := isOnZFS
	origNested := isNestedLXDContainer
	defer func() { isOnZFS = origOnZFS; isNestedLXDContainer = origNested }()
	isOnZFS = func(string) bool { return false }
	isNestedLXDContainer = func() bool { return false }

	err = r.EnsureRunning(c.Context(), spec)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(fake.createCalls, tc.Equals, 0)
	c.Check(fake.startCalls, tc.Equals, 0)
	c.Check(fake.stopCalls, tc.Equals, 0)
}

func (s *runtimeSuite) TestEnsureRunningReplacesOnImageChange(c *tc.C) {
	fake := newFakeServer()
	r := NewWithClient(fake, "")

	spec := iaascontainerrunner.ContainerSpec{
		Name:  "juju-unit-mysql-0-workload",
		Image: iaascontainerrunner.ImageDetails{RegistryPath: "docker.io/library/nginx:1.27"},
	}
	oldSpec := spec
	oldSpec.Image = iaascontainerrunner.ImageDetails{RegistryPath: "docker.io/library/nginx:1.26"}
	config, devices, err := renderConfig(oldSpec, false, "")
	c.Assert(err, tc.ErrorIsNil)
	fake.instances[spec.Name] = &lxdapi.Instance{
		Name:       spec.Name,
		StatusCode: lxdapi.Running,
	}
	fake.instances[spec.Name].Config = config
	fake.instances[spec.Name].Devices = devices

	origOnZFS := isOnZFS
	origNested := isNestedLXDContainer
	defer func() { isOnZFS = origOnZFS; isNestedLXDContainer = origNested }()
	isOnZFS = func(string) bool { return false }
	isNestedLXDContainer = func() bool { return false }

	err = r.EnsureRunning(c.Context(), spec)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(fake.stopCalls, tc.Equals, 1)
	c.Check(fake.deleteCalls, tc.Equals, 1)
	c.Check(fake.createCalls, tc.Equals, 1)
	c.Check(fake.instances[spec.Name].Config["user.oci.image"], tc.Equals, "docker.io/library/nginx:1.27")
}

func (s *runtimeSuite) TestEnsureRunningReplacesOnPrivilegedModeChange(c *tc.C) {
	// Verify that an existing non-privileged container is replaced when
	// the environment now requires privileged mode (configMatches detects
	// the security.privileged change).
	fake := newFakeServer()
	r := NewWithClient(fake, "")

	spec := iaascontainerrunner.ContainerSpec{
		Name:  "juju-unit-mysql-0-workload",
		Image: iaascontainerrunner.ImageDetails{RegistryPath: "docker.io/library/nginx:1.27"},
	}
	// Pre-populate with a non-privileged container.
	config, devices, err := renderConfig(spec, false, "")
	c.Assert(err, tc.ErrorIsNil)
	fake.instances[spec.Name] = &lxdapi.Instance{
		Name:       spec.Name,
		StatusCode: lxdapi.Running,
	}
	fake.instances[spec.Name].Config = config
	fake.instances[spec.Name].Devices = devices

	// Now the environment detects nested ZFS: privileged mode required.
	origOnZFS := isOnZFS
	origNested := isNestedLXDContainer
	defer func() { isOnZFS = origOnZFS; isNestedLXDContainer = origNested }()
	isOnZFS = func(string) bool { return true }
	isNestedLXDContainer = func() bool { return true }

	err = r.EnsureRunning(c.Context(), spec)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(fake.stopCalls, tc.Equals, 1)
	c.Check(fake.deleteCalls, tc.Equals, 1)
	c.Check(fake.createCalls, tc.Equals, 1)
	c.Check(fake.instances[spec.Name].Config["security.privileged"], tc.Equals, "true")
}

func (s *runtimeSuite) TestStopDeletesRunningContainer(c *tc.C) {
	fake := newFakeServer()
	r := NewWithClient(fake, "")

	fake.instances["foo"] = &lxdapi.Instance{Name: "foo", StatusCode: lxdapi.Running}

	err := r.Stop(c.Context(), "foo")
	c.Assert(err, tc.ErrorIsNil)
	c.Check(fake.stopCalls, tc.Equals, 1)
	c.Check(fake.deleteCalls, tc.Equals, 1)
	_, ok := fake.instances["foo"]
	c.Check(ok, tc.IsFalse)
}

func (s *runtimeSuite) TestStopIsNoopWhenMissing(c *tc.C) {
	fake := newFakeServer()
	r := NewWithClient(fake, "")

	err := r.Stop(c.Context(), "does-not-exist")
	c.Assert(err, tc.ErrorIsNil)
	c.Check(fake.stopCalls, tc.Equals, 0)
	c.Check(fake.deleteCalls, tc.Equals, 0)
}

func (s *runtimeSuite) TestStatusReportsRunning(c *tc.C) {
	fake := newFakeServer()
	r := NewWithClient(fake, "")
	fake.instances["foo"] = &lxdapi.Instance{Name: "foo", StatusCode: lxdapi.Running, Status: "Running"}

	status, err := r.Status(c.Context(), "foo")
	c.Assert(err, tc.ErrorIsNil)
	c.Check(status.State, tc.Equals, "running")
}

func (s *runtimeSuite) TestStatusReportsStoppedWhenMissing(c *tc.C) {
	fake := newFakeServer()
	r := NewWithClient(fake, "")

	status, err := r.Status(c.Context(), "does-not-exist")
	c.Assert(err, tc.ErrorIsNil)
	c.Check(status.State, tc.Equals, "stopped")
}

func (s *runtimeSuite) TestConfigMatchesIgnoresUnmanagedKeys(c *tc.C) {
	desired := map[string]string{"user.oci.image": "img"}
	actual := map[string]string{"user.oci.image": "img", "volatile.uuid": "abc"}
	c.Check(configMatches(actual, desired), tc.IsTrue)
}

func (s *runtimeSuite) TestConfigMatchesDetectsChangedManagedKey(c *tc.C) {
	desired := map[string]string{"user.oci.image": "img"}
	actual := map[string]string{"user.oci.image": "other"}
	c.Check(configMatches(actual, desired), tc.IsFalse)
}

func (s *runtimeSuite) TestConfigMatchesDetectsPrivilegedChange(c *tc.C) {
	// Changing security.privileged must be detected so the container is
	// replaced when the environment changes.
	desired := map[string]string{"security.privileged": "true"}
	actual := map[string]string{"security.privileged": "false"}
	c.Check(configMatches(actual, desired), tc.IsFalse)
}

func (s *runtimeSuite) TestDevicesMatchDetectsRemovedManagedDevice(c *tc.C) {
	desired := map[string]map[string]string{}
	actual := map[string]map[string]string{
		"storage-0": {"type": "disk", "source": "/x", "path": "/y"},
	}
	c.Check(devicesMatch(actual, desired), tc.IsFalse)
}

// fakeServer is a fake instanceServer used for testing.
type fakeServer struct {
	mu          sync.Mutex
	instances   map[string]*lxdapi.Instance
	createCalls int
	startCalls  int
	stopCalls   int
	deleteCalls int
}

func newFakeServer() *fakeServer {
	return &fakeServer{instances: make(map[string]*lxdapi.Instance)}
}

func (f *fakeServer) GetInstance(name string) (*lxdapi.Instance, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inst, ok := f.instances[name]
	if !ok {
		return nil, "", lxdapi.StatusErrorf(http.StatusNotFound, "not found")
	}
	return inst, "etag", nil
}

func (f *fakeServer) CreateInstance(instance lxdapi.InstancesPost) (lxdclient.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	inst := &lxdapi.Instance{
		Name:       instance.Name,
		StatusCode: lxdapi.Running,
	}
	inst.Config = instance.InstancePut.Config
	inst.Devices = instance.InstancePut.Devices
	f.instances[instance.Name] = inst
	return &fakeOperation{}, nil
}

func (f *fakeServer) UpdateInstanceState(name string, state lxdapi.InstanceStatePut, _ string) (lxdclient.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inst, ok := f.instances[name]
	if !ok {
		return nil, lxdapi.StatusErrorf(http.StatusNotFound, "not found")
	}
	switch state.Action {
	case "start":
		f.startCalls++
		inst.StatusCode = lxdapi.Running
	case "stop":
		f.stopCalls++
		inst.StatusCode = lxdapi.Stopped
	}
	return &fakeOperation{}, nil
}

func (f *fakeServer) DeleteInstance(name string) (lxdclient.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.instances[name]; !ok {
		return nil, lxdapi.StatusErrorf(http.StatusNotFound, "not found")
	}
	f.deleteCalls++
	delete(f.instances, name)
	return &fakeOperation{}, nil
}

func (f *fakeServer) GetInstanceState(name string) (*lxdapi.InstanceState, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inst, ok := f.instances[name]
	if !ok {
		return nil, "", lxdapi.StatusErrorf(http.StatusNotFound, "not found")
	}
	return &lxdapi.InstanceState{Status: inst.Status, StatusCode: inst.StatusCode}, "etag", nil
}

func (f *fakeServer) GetInstanceConsoleLog(_ string, _ *lxdclient.InstanceConsoleLogArgs) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

// fakeOperation is a no-op lxdclient.Operation.
type fakeOperation struct{}

func (f *fakeOperation) AddHandler(func(lxdapi.Operation)) (*lxdclient.EventTarget, error) {
	return nil, nil
}
func (f *fakeOperation) Cancel() error         { return nil }
func (f *fakeOperation) Get() lxdapi.Operation { return lxdapi.Operation{} }
func (f *fakeOperation) GetWebsocket(string) (*websocket.Conn, error) {
	return nil, nil
}
func (f *fakeOperation) RemoveHandler(*lxdclient.EventTarget) error { return nil }
func (f *fakeOperation) Refresh() error                             { return nil }
func (f *fakeOperation) Wait() error                                { return nil }
func (f *fakeOperation) WaitContext(context.Context) error          { return nil }
