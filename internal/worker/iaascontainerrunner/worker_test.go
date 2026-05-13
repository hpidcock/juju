// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		CommandRunner:  &mockCommandRunner{},
	})
	c.Assert(err, tc.ErrorMatches, "invalid config: nil Logger not valid")
}

func (s *workerSuite) TestValidateEmptyDataDir(c *tc.C) {
	_, err := New(Config{
		Logger:         loggertesting.WrapCheckLog(c),
		ContainerNames: []string{"mycontainer"},
		CommandRunner:  &mockCommandRunner{},
	})
	c.Assert(err, tc.ErrorMatches, "invalid config: empty DataDir not valid")
}

func (s *workerSuite) TestValidateEmptyContainerNames(c *tc.C) {
	_, err := New(Config{
		Logger:        loggertesting.WrapCheckLog(c),
		DataDir:       "/tmp/test",
		CommandRunner: &mockCommandRunner{},
	})
	c.Assert(err, tc.ErrorMatches, "invalid config: empty ContainerNames not valid")
}

func (s *workerSuite) TestValidateNilCommandRunner(c *tc.C) {
	_, err := New(Config{
		Logger:         loggertesting.WrapCheckLog(c),
		DataDir:        "/tmp/test",
		ContainerNames: []string{"mycontainer"},
	})
	c.Assert(err, tc.ErrorMatches, "invalid config: nil CommandRunner not valid")
}

func (s *workerSuite) TestEnsureRunningStartsContainer(c *tc.C) {
	dataDir := c.MkDir()

	// Create a fake pebble binary.
	snapDir := c.MkDir()
	pebbleSrc := filepath.Join(snapDir, "bin", "pebble")
	c.Assert(os.MkdirAll(filepath.Dir(pebbleSrc), 0755), tc.ErrorIsNil)
	c.Assert(os.WriteFile(pebbleSrc, []byte("#!/bin/sh\n"), 0755), tc.ErrorIsNil)

	runner := &mockCommandRunner{}
	// nerdctl version succeeds
	runner.addResponse("nerdctl version", nil, nil)
	// nerdctl inspect --format ... fails (not running)
	runner.addResponse("nerdctl inspect --format", nil, fmt.Errorf("not found"))
	// nerdctl inspect fails (not created)
	runner.addResponse("nerdctl inspect juju", nil, fmt.Errorf("not found"))
	// nerdctl run succeeds
	runner.addResponse("nerdctl run", nil, nil)

	// Pre-create pebble binary to avoid snap lookup.
	binDir := filepath.Join(dataDir, "charm", "bin")
	c.Assert(os.MkdirAll(binDir, 0755), tc.ErrorIsNil)
	c.Assert(os.WriteFile(filepath.Join(binDir, "pebble"), []byte("fake"), 0755), tc.ErrorIsNil)

	w, err := New(Config{
		Logger:         loggertesting.WrapCheckLog(c),
		DataDir:        dataDir,
		ContainerNames: []string{"mycontainer"},
		CommandRunner:  runner,
	})
	c.Assert(err, tc.ErrorIsNil)

	// Give the loop time to run, then kill.
	w.Kill()
	err = w.Wait()
	c.Assert(err, tc.ErrorIsNil)

	// Check that nerdctl run was called.
	c.Assert(runner.hasCommand("nerdctl run"), tc.IsTrue)
}

func (s *workerSuite) TestEnsureRunningSkipsAlreadyRunning(c *tc.C) {
	dataDir := c.MkDir()

	runner := &mockCommandRunner{}
	// nerdctl version succeeds
	runner.addResponse("nerdctl version", nil, nil)
	// nerdctl inspect --format ... returns true (already running)
	runner.addResponse("nerdctl inspect --format", []byte("true"), nil)

	// Pre-create pebble binary.
	binDir := filepath.Join(dataDir, "charm", "bin")
	c.Assert(os.MkdirAll(binDir, 0755), tc.ErrorIsNil)
	c.Assert(os.WriteFile(filepath.Join(binDir, "pebble"), []byte("fake"), 0755), tc.ErrorIsNil)

	w, err := New(Config{
		Logger:         loggertesting.WrapCheckLog(c),
		DataDir:        dataDir,
		ContainerNames: []string{"mycontainer"},
		CommandRunner:  runner,
	})
	c.Assert(err, tc.ErrorIsNil)

	w.Kill()
	err = w.Wait()
	c.Assert(err, tc.ErrorIsNil)

	// nerdctl run should NOT have been called.
	c.Assert(runner.hasCommand("nerdctl run"), tc.IsFalse)
}

func (s *workerSuite) TestStopContainerOnShutdown(c *tc.C) {
	dataDir := c.MkDir()

	runner := &mockCommandRunner{}
	// nerdctl version succeeds
	runner.addResponse("nerdctl version", nil, nil)
	// Container already running
	runner.addResponse("nerdctl inspect --format", []byte("true"), nil)
	// Stop commands
	runner.addResponse("nerdctl inspect juju", nil, nil)
	runner.addResponse("nerdctl stop", nil, nil)
	runner.addResponse("nerdctl rm", nil, nil)

	// Pre-create pebble binary.
	binDir := filepath.Join(dataDir, "charm", "bin")
	c.Assert(os.MkdirAll(binDir, 0755), tc.ErrorIsNil)
	c.Assert(os.WriteFile(filepath.Join(binDir, "pebble"), []byte("fake"), 0755), tc.ErrorIsNil)

	w, err := New(Config{
		Logger:         loggertesting.WrapCheckLog(c),
		DataDir:        dataDir,
		ContainerNames: []string{"mycontainer"},
		CommandRunner:  runner,
	})
	c.Assert(err, tc.ErrorIsNil)

	w.Kill()
	err = w.Wait()
	c.Assert(err, tc.ErrorIsNil)

	// nerdctl stop should have been called during shutdown.
	c.Assert(runner.hasCommand("nerdctl stop"), tc.IsTrue)
}

func (s *workerSuite) TestContainerID(c *tc.C) {
	w := &Worker{
		config: Config{
			DataDir: "/var/lib/juju/agents/unit-mysql-0",
		},
	}
	c.Assert(w.containerID("workload"), tc.Equals, "juju-unit-mysql-0-workload")
}

func (s *workerSuite) TestFileHash(c *tc.C) {
	path := filepath.Join(c.MkDir(), "f")
	c.Assert(os.WriteFile(path, []byte("hello"), 0644), tc.ErrorIsNil)
	hash, err := fileHash(path)
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(hash, tc.Equals, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
}

func (s *workerSuite) TestEnsureRunningReplacesOnPebbleUpgrade(c *tc.C) {
	runner := &mockCommandRunner{}
	runner.addResponse("nerdctl inspect --format", []byte("true"), nil)
	runner.addResponse("nerdctl inspect juju-unit-mysql-0-workload", nil, nil)
	runner.addResponse("nerdctl stop", nil, nil)
	runner.addResponse("nerdctl rm", nil, nil)
	runner.addResponse("nerdctl run", nil, nil)

	w := &Worker{
		config: Config{
			Logger:        loggertesting.WrapCheckLog(c),
			DataDir:       "/var/lib/juju/agents/unit-mysql-0",
			CommandRunner: runner,
		},
		pebbleUpgraded: true,
	}

	err := w.ensureRunning(c.Context(), "workload")
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(runner.hasCommand("nerdctl stop"), tc.IsTrue)
	c.Assert(runner.hasCommand("nerdctl rm"), tc.IsTrue)
	c.Assert(runner.hasCommand("nerdctl run"), tc.IsTrue)
}

func (s *workerSuite) TestMonitorContainersReportsRunning(c *tc.C) {
	runner := &mockCommandRunner{}
	runner.addResponse("nerdctl inspect --format", []byte("true"), nil)
	reporter := &mockStatusReporter{}

	w := &Worker{
		config: Config{
			Logger:         loggertesting.WrapCheckLog(c),
			DataDir:        "/var/lib/juju/agents/unit-mysql-0",
			ContainerNames: []string{"workload"},
			CommandRunner:  runner,
			StatusReporter: reporter,
		},
	}

	w.monitorContainers(c.Context())
	c.Assert(reporter.statuses, tc.HasLen, 1)
	c.Assert(reporter.statuses[0].State, tc.Equals, "running")
}

func (s *workerSuite) TestMonitorContainersRestartsStopped(c *tc.C) {
	runner := &mockCommandRunner{}
	runner.addResponse("nerdctl inspect --format", []byte("false"), nil)
	runner.addResponse("nerdctl start", nil, nil)
	reporter := &mockStatusReporter{}

	w := &Worker{
		config: Config{
			Logger:         loggertesting.WrapCheckLog(c),
			DataDir:        "/var/lib/juju/agents/unit-mysql-0",
			ContainerNames: []string{"workload"},
			CommandRunner:  runner,
			StatusReporter: reporter,
		},
	}

	w.monitorContainers(c.Context())
	c.Assert(runner.hasCommand("nerdctl start"), tc.IsTrue)
	c.Assert(reporter.statuses, tc.HasLen, 1)
	c.Assert(reporter.statuses[0].Message, tc.Equals, "container restarted")
}

func (s *workerSuite) TestStorageMountArgs(c *tc.C) {
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

	args, err := w.storageMountArgs(c.Context(), "workload")
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(args, tc.DeepEquals, []string{"-v", "/var/lib/juju/storage/data/0:/data"})
}

func (s *workerSuite) TestStorageMountArgsSkipsMissingStorage(c *tc.C) {
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

	args, err := w.storageMountArgs(c.Context(), "workload")
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(args, tc.HasLen, 0)
}

func (s *workerSuite) TestRunContainerIncludesStorageMountArgs(c *tc.C) {
	runner := &mockCommandRunner{}
	runner.addResponse("nerdctl run", nil, nil)
	resolver := &mockStorageResolver{
		paths: map[string]string{
			"data": "/var/lib/juju/storage/data/0",
		},
	}
	w := &Worker{
		config: Config{
			Logger:        loggertesting.WrapCheckLog(c),
			DataDir:       "/var/lib/juju/agents/unit-mysql-0",
			CommandRunner: runner,
			CharmMeta: map[string]ContainerMeta{
				"workload": {
					Mounts: []Mount{{StorageName: "data", Location: "/data"}},
				},
			},
			StorageResolver: resolver,
		},
	}

	err := w.runContainer(c.Context(), "workload")
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(runner.hasCommand("nerdctl run"), tc.IsTrue)
	c.Assert(runner.hasCommandContaining("/var/lib/juju/storage/data/0:/data"), tc.IsTrue)
}

func (s *workerSuite) TestParseLogLineWithTimestamp(c *tc.C) {
	ts, message := parseLogLine("2024-01-01T00:00:00Z workload started")
	c.Assert(ts, tc.Equals, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	c.Assert(message, tc.Equals, "workload started")
}

func (s *workerSuite) TestParseLogLineWithoutTimestamp(c *tc.C) {
	ts, message := parseLogLine("plain log line")
	c.Assert(ts.IsZero(), tc.IsTrue)
	c.Assert(message, tc.Equals, "plain log line")
}

func (s *workerSuite) TestForwardLogLines(c *tc.C) {
	sink := &mockLogSink{}
	w := &Worker{
		config: Config{
			LogSink: sink,
		},
	}
	w.forwardLogLines("workload", strings.NewReader("2024-01-01T00:00:00Z hello\nno timestamp\n"))
	c.Assert(sink.records, tc.HasLen, 2)
	c.Assert(sink.records[0].containerName, tc.Equals, "workload")
	c.Assert(sink.records[0].message, tc.Equals, "hello")
	c.Assert(sink.records[1].message, tc.Equals, "no timestamp")
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

// mockCommandRunner records commands and returns pre-configured responses.
type mockCommandRunner struct {
	commands  []string
	responses []mockResponse
}

type mockStatusReporter struct {
	statuses []ContainerStatus
}

type mockStorageResolver struct {
	paths map[string]string
	err   error
}

type mockLogSink struct {
	records []mockLogRecord
}

type mockLogRecord struct {
	containerName string
	timestamp     time.Time
	message       string
}

func (m *mockLogSink) Log(containerName string, timestamp time.Time, message string) {
	m.records = append(m.records, mockLogRecord{
		containerName: containerName,
		timestamp:     timestamp,
		message:       message,
	})
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

type mockResponse struct {
	prefix string
	output []byte
	err    error
}

func (m *mockCommandRunner) addResponse(prefix string, output []byte, err error) {
	m.responses = append(m.responses, mockResponse{prefix: prefix, output: output, err: err})
}

func (m *mockCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	m.commands = append(m.commands, cmd)

	for i, r := range m.responses {
		if strings.HasPrefix(cmd, r.prefix) {
			// Remove used response.
			m.responses = append(m.responses[:i], m.responses[i+1:]...)
			return r.output, r.err
		}
	}
	return nil, nil
}

func (m *mockCommandRunner) RunStdin(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
	return m.Run(context.Background(), name, args...)
}

func (m *mockCommandRunner) hasCommand(prefix string) bool {
	for _, cmd := range m.commands {
		if strings.HasPrefix(cmd, prefix) {
			return true
		}
	}
	return false
}

func (m *mockCommandRunner) hasCommandContaining(substr string) bool {
	for _, cmd := range m.commands {
		if strings.Contains(cmd, substr) {
			return true
		}
	}
	return false
}
