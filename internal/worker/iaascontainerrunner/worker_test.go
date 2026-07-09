// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/juju/tc"
	"github.com/juju/worker/v5/dependency"

	loggertesting "github.com/juju/juju/internal/logger/testing"
)

type workerSuite struct{}

func TestWorkerSuite(t *testing.T) {
	tc.Run(t, &workerSuite{})
}

func (s *workerSuite) TestValidateNilLogger(c *tc.C) {
	_, err := New(Config{
		DataDir:        "/tmp/test",
		ContainerNames: []string{"mycontainer"},
		Runtime:        &fakeRuntime{},
	})
	c.Assert(err, tc.ErrorMatches, "invalid config: nil Logger not valid")
}

func (s *workerSuite) TestValidateEmptyDataDir(c *tc.C) {
	_, err := New(Config{
		Logger:         loggertesting.WrapCheckLog(c),
		ContainerNames: []string{"mycontainer"},
		Runtime:        &fakeRuntime{},
	})
	c.Assert(err, tc.ErrorMatches, "invalid config: empty DataDir not valid")
}

func (s *workerSuite) TestValidateEmptyContainerNames(c *tc.C) {
	_, err := New(Config{
		Logger:  loggertesting.WrapCheckLog(c),
		DataDir: "/tmp/test",
		Runtime: &fakeRuntime{},
	})
	c.Assert(err, tc.ErrorMatches, "invalid config: empty ContainerNames not valid")
}

func (s *workerSuite) TestValidateNilRuntime(c *tc.C) {
	_, err := New(Config{
		Logger:         loggertesting.WrapCheckLog(c),
		DataDir:        "/tmp/test",
		ContainerNames: []string{"mycontainer"},
	})
	c.Assert(err, tc.ErrorMatches, "invalid config: nil Runtime not valid")
}

func (s *workerSuite) TestEnsureRunningStartsContainer(c *tc.C) {
	dataDir := c.MkDir()
	socketRoot := c.MkDir()
	runtime := newFakeRuntime()

	w, err := New(Config{
		Logger:              loggertesting.WrapCheckLog(c),
		DataDir:             dataDir,
		ContainerNames:      []string{"mycontainer"},
		Runtime:             runtime,
		PebbleBinaryPath:    "/snap/pebble/current/bin/pebble",
		ContainerSocketRoot: socketRoot,
	})
	c.Assert(err, tc.ErrorIsNil)

	w.Kill()
	err = w.Wait()
	c.Assert(err, tc.ErrorIsNil)

	id := w.containerID("mycontainer")
	spec := runtime.specFor(id)
	c.Assert(spec, tc.NotNil)
	c.Check(spec.PebbleBinaryPath, tc.Equals, "/snap/pebble/current/bin/pebble")
	c.Check(spec.Image.RegistryPath, tc.Equals, defaultImage)
	c.Check(runtime.ensureCalls[id], tc.Equals, 1)
}

func (s *workerSuite) TestStopContainerOnShutdown(c *tc.C) {
	dataDir := c.MkDir()
	socketRoot := c.MkDir()
	runtime := newFakeRuntime()

	w, err := New(Config{
		Logger:              loggertesting.WrapCheckLog(c),
		DataDir:             dataDir,
		ContainerNames:      []string{"mycontainer"},
		Runtime:             runtime,
		ContainerSocketRoot: socketRoot,
	})
	c.Assert(err, tc.ErrorIsNil)

	w.Kill()
	err = w.Wait()
	c.Assert(err, tc.ErrorIsNil)

	id := w.containerID("mycontainer")
	c.Check(runtime.stopCalls[id], tc.Equals, 1)
}

func (s *workerSuite) TestContainerID(c *tc.C) {
	w := &Worker{
		config: Config{
			DataDir: "/var/lib/juju/agents/unit-mysql-0",
		},
	}
	c.Assert(w.containerID("workload"), tc.Equals, "juju-unit-mysql-0-workload")
}

func (s *workerSuite) TestContainerIDTruncatesLongNames(c *tc.C) {
	w := &Worker{
		config: Config{
			DataDir: "/var/lib/juju/agents/unit-a-very-long-application-name-indeed-0",
		},
	}
	id := w.containerID("a-very-long-container-name-too")
	c.Check(len(id) <= 63, tc.IsTrue)
}

func (s *workerSuite) TestMonitorContainersReportsRunning(c *tc.C) {
	runtime := newFakeRuntime()
	reporter := &mockStatusReporter{}

	w := &Worker{
		config: Config{
			Logger:         loggertesting.WrapCheckLog(c),
			DataDir:        "/var/lib/juju/agents/unit-mysql-0",
			ContainerNames: []string{"workload"},
			Runtime:        runtime,
			StatusReporter: reporter,
		},
	}
	id := w.containerID("workload")
	runtime.statuses[id] = ContainerStatus{State: "running", Message: "container running"}

	w.monitorContainers(c.Context())
	c.Assert(reporter.statuses, tc.HasLen, 1)
	c.Assert(reporter.statuses[0].State, tc.Equals, "running")
}

func (s *workerSuite) TestMonitorContainersRestartsStopped(c *tc.C) {
	runtime := newFakeRuntime()
	reporter := &mockStatusReporter{}

	w := &Worker{
		config: Config{
			Logger:         loggertesting.WrapCheckLog(c),
			DataDir:        "/var/lib/juju/agents/unit-mysql-0",
			ContainerNames: []string{"workload"},
			Runtime:        runtime,
			StatusReporter: reporter,
		},
	}
	id := w.containerID("workload")
	runtime.statuses[id] = ContainerStatus{State: "stopped", Message: "container does not exist"}

	w.monitorContainers(c.Context())
	c.Assert(runtime.ensureCalls[id], tc.Equals, 1)
	c.Assert(reporter.statuses, tc.HasLen, 1)
	c.Assert(reporter.statuses[0].Message, tc.Equals, "container restarted")
}

func (s *workerSuite) TestResolveMounts(c *tc.C) {
	resolver := &mockStorageResolver{
		paths: map[string]string{
			"data": "/var/lib/juju/storage/data/0",
		},
	}
	w := &Worker{
		config: Config{
			Logger: loggertesting.WrapCheckLog(c),
			CharmMeta: map[string]ContainerMeta{
				"workload": {
					Mounts: []Mount{{StorageName: "data", Location: "/data"}},
				},
			},
			StorageResolver: resolver,
		},
	}

	mounts, err := w.resolveMounts(c.Context(), "workload")
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(mounts, tc.DeepEquals, []ResolvedMount{{HostPath: "/var/lib/juju/storage/data/0", Location: "/data"}})
}

func (s *workerSuite) TestResolveMountsSkipsMissingStorage(c *tc.C) {
	resolver := &mockStorageResolver{err: fmt.Errorf("not attached")}
	w := &Worker{
		config: Config{
			Logger: loggertesting.WrapCheckLog(c),
			CharmMeta: map[string]ContainerMeta{
				"workload": {
					Mounts: []Mount{{StorageName: "data", Location: "/data"}},
				},
			},
			StorageResolver: resolver,
		},
	}

	mounts, err := w.resolveMounts(c.Context(), "workload")
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(mounts, tc.HasLen, 0)
}

func (s *workerSuite) TestBuildContainerSpecIncludesResolvedMounts(c *tc.C) {
	resolver := &mockStorageResolver{
		paths: map[string]string{
			"data": "/var/lib/juju/storage/data/0",
		},
	}
	w := &Worker{
		config: Config{
			Logger:              loggertesting.WrapCheckLog(c),
			DataDir:             "/var/lib/juju/agents/unit-mysql-0",
			ContainerSocketRoot: "/",
			CharmMeta: map[string]ContainerMeta{
				"workload": {
					Mounts: []Mount{{StorageName: "data", Location: "/data"}},
				},
			},
			StorageResolver: resolver,
			ImageDetails: map[string]ImageDetails{
				"workload": {RegistryPath: "docker.io/library/nginx:1.27"},
			},
		},
	}

	spec, err := w.buildContainerSpec(c.Context(), "workload")
	c.Assert(err, tc.ErrorIsNil)
	c.Check(spec.Image.RegistryPath, tc.Equals, "docker.io/library/nginx:1.27")
	c.Check(spec.Mounts, tc.DeepEquals, []ResolvedMount{{HostPath: "/var/lib/juju/storage/data/0", Location: "/data"}})
	c.Check(spec.Pod, tc.Equals, "unit-mysql-0")
	c.Check(spec.SocketDir, tc.Equals, "/charm/containers/workload")
	c.Check(spec.Env["JUJU_CONTAINER_NAME"], tc.Equals, "workload")
}

func (s *workerSuite) TestManifoldEmptyContainerNames(c *tc.C) {
	m := Manifold(ManifoldConfig{
		AgentName:      "agent",
		ContainerNames: nil,
		Logger:         loggertesting.WrapCheckLog(c),
	})
	// Start should return ErrMissing.
	_, err := m.Start(c.Context(), nil)
	c.Assert(err, tc.Equals, dependency.ErrMissing)
}

// fakeRuntime is a test double for ContainerRuntime.
type fakeRuntime struct {
	mu          sync.Mutex
	specs       map[string]ContainerSpec
	statuses    map[string]ContainerStatus
	ensureCalls map[string]int
	stopCalls   map[string]int
	ensureErr   error
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		specs:       make(map[string]ContainerSpec),
		statuses:    make(map[string]ContainerStatus),
		ensureCalls: make(map[string]int),
		stopCalls:   make(map[string]int),
	}
}

func (f *fakeRuntime) EnsureRunning(_ context.Context, spec ContainerSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ensureErr != nil {
		return f.ensureErr
	}
	f.specs[spec.Name] = spec
	f.ensureCalls[spec.Name]++
	f.statuses[spec.Name] = ContainerStatus{State: "running", Message: "container running"}
	return nil
}

func (f *fakeRuntime) Status(_ context.Context, name string) (ContainerStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status, ok := f.statuses[name]
	if !ok {
		return ContainerStatus{State: "stopped", Message: "container does not exist"}, nil
	}
	return status, nil
}

func (f *fakeRuntime) Stop(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls[name]++
	delete(f.statuses, name)
	return nil
}

func (f *fakeRuntime) specFor(name string) *ContainerSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	spec, ok := f.specs[name]
	if !ok {
		return nil
	}
	return &spec
}

type mockStatusReporter struct {
	statuses []ContainerStatus
}

type mockStorageResolver struct {
	paths map[string]string
	err   error
}

func (m *mockStorageResolver) GetStorageMountPath(_ context.Context, storageName string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.paths[storageName], nil
}

func (m *mockStatusReporter) ReportContainerStatus(_ context.Context, _ string, status ContainerStatus) error {
	m.statuses = append(m.statuses, status)
	return nil
}
