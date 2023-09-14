// Copyright 2022 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package database

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"go.uber.org/mock/gomock"
	gc "gopkg.in/check.v1"
	"gopkg.in/yaml.v3"

	"github.com/juju/juju/agent"
	"github.com/juju/juju/controller"
	coredatabase "github.com/juju/juju/core/database"
	corenetwork "github.com/juju/juju/core/network"
	"github.com/juju/juju/database/app"
	"github.com/juju/juju/database/dqlite"
	dqlitetesting "github.com/juju/juju/database/testing"
	"github.com/juju/juju/network"
	jujutesting "github.com/juju/juju/testing"
)

type nodeManagerSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&nodeManagerSuite{})

func (s *nodeManagerSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)

	if !dqlite.Enabled {
		c.Skip("This requires a dqlite server to be running")
	}
}

func (s *nodeManagerSuite) TestEnsureDataDirSuccess(c *gc.C) {
	subDir := strconv.Itoa(rand.Intn(10))

	cfg := fakeAgentConfig{dataDir: "/tmp/" + subDir}
	m := NewNodeManager(cfg, stubLogger{}, coredatabase.NoopSlowQueryLogger{})

	expected := fmt.Sprintf("/tmp/%s/%s", subDir, dqliteDataDir)
	s.AddCleanup(func(*gc.C) { _ = os.RemoveAll(cfg.DataDir()) })

	// Call twice to check both the creation and extant scenarios.
	dir, err := m.EnsureDataDir()
	c.Assert(err, jc.ErrorIsNil)
	c.Check(dir, gc.Equals, expected)

	_, err = os.Stat(expected)
	c.Assert(err, jc.ErrorIsNil)

	dir, err = m.EnsureDataDir()
	c.Assert(err, jc.ErrorIsNil)
	c.Check(dir, gc.Equals, expected)

	_, err = os.Stat(expected)
	c.Assert(err, jc.ErrorIsNil)
}

func (s *nodeManagerSuite) TestIsExistingNode(c *gc.C) {
	subDir := strconv.Itoa(rand.Intn(10))

	cfg := fakeAgentConfig{dataDir: "/tmp/" + subDir}
	s.AddCleanup(func(*gc.C) { _ = os.RemoveAll(cfg.DataDir()) })

	m := NewNodeManager(cfg, stubLogger{}, coredatabase.NoopSlowQueryLogger{})

	// Empty directory indicates we've never started.
	extant, err := m.IsExistingNode()
	c.Assert(err, jc.ErrorIsNil)
	c.Check(extant, jc.IsFalse)

	// Non-empty indicates we've come up before.
	dataDir, err := m.EnsureDataDir()
	c.Assert(err, jc.ErrorIsNil)

	someFile := path.Join(dataDir, "a-file.txt")
	err = os.WriteFile(someFile, nil, 06000)
	c.Assert(err, jc.ErrorIsNil)

	extant, err = m.IsExistingNode()
	c.Assert(err, jc.ErrorIsNil)
	c.Check(extant, jc.IsTrue)
}

func (s *nodeManagerSuite) TestIsBootstrappedNode(c *gc.C) {
	subDir := strconv.Itoa(rand.Intn(10))

	cfg := fakeAgentConfig{dataDir: "/tmp/" + subDir}
	s.AddCleanup(func(*gc.C) { _ = os.RemoveAll(cfg.DataDir()) })

	m := NewNodeManager(cfg, stubLogger{}, coredatabase.NoopSlowQueryLogger{})
	ctx := context.Background()

	// Empty directory indicates we are not the bootstrapped node.
	asBootstrapped, err := m.IsLoopbackBound(ctx)
	c.Assert(err, jc.ErrorIsNil)
	c.Check(asBootstrapped, jc.IsFalse)

	dataDir, err := m.EnsureDataDir()
	c.Assert(err, jc.ErrorIsNil)

	clusterFile := path.Join(dataDir, dqliteClusterFileName)

	// Multiple nodes indicates the cluster has mutated since bootstrap.
	data := `
- Address: 10.246.27.114:17666
  ID: 3297041220608546238
  Role: 0
- Address: 10.246.27.115:17666
  ID: 123456789
  Role: 0
`[1:]

	err = os.WriteFile(clusterFile, []byte(data), 0600)
	c.Assert(err, jc.ErrorIsNil)

	asBootstrapped, err = m.IsLoopbackBound(ctx)
	c.Assert(err, jc.ErrorIsNil)
	c.Check(asBootstrapped, jc.IsFalse)

	// Non-loopback address indicates node was reconfigured since bootstrap.
	data = `
- Address: 10.246.27.114:17666
  ID: 3297041220608546238
  Role: 0
`[1:]

	err = os.WriteFile(clusterFile, []byte(data), 0600)
	c.Assert(err, jc.ErrorIsNil)

	asBootstrapped, err = m.IsLoopbackBound(ctx)
	c.Assert(err, jc.ErrorIsNil)
	c.Check(asBootstrapped, jc.IsFalse)

	// Loopback IP address indicates the node is as we bootstrapped it.
	data = `
- Address: 127.0.0.1:17666
  ID: 3297041220608546238
  Role: 0
`[1:]

	err = os.WriteFile(clusterFile, []byte(data), 0600)
	c.Assert(err, jc.ErrorIsNil)

	asBootstrapped, err = m.IsLoopbackBound(ctx)
	c.Assert(err, jc.ErrorIsNil)
	c.Check(asBootstrapped, jc.IsTrue)
}

func (s *nodeManagerSuite) TestSetClusterServersSuccess(c *gc.C) {
	subDir := strconv.Itoa(rand.Intn(10))

	cfg := fakeAgentConfig{dataDir: "/tmp/" + subDir}
	s.AddCleanup(func(*gc.C) { _ = os.RemoveAll(cfg.DataDir()) })

	m := NewNodeManager(cfg, stubLogger{}, coredatabase.NoopSlowQueryLogger{})
	ctx := context.Background()

	dataDir, err := m.EnsureDataDir()
	c.Assert(err, jc.ErrorIsNil)

	clusterFile := path.Join(dataDir, dqliteClusterFileName)

	// Write a cluster.yaml file into the Dqlite data directory.
	data := []byte(`
- Address: 127.0.0.1:17666
  ID: 3297041220608546238
  Role: 0
`[1:])

	err = os.WriteFile(clusterFile, data, 0600)
	c.Assert(err, jc.ErrorIsNil)

	servers := []dqlite.NodeInfo{
		{
			ID:      3297041220608546238,
			Address: "10.6.6.6:17666",
			Role:    0,
		},
	}

	err = m.SetClusterServers(ctx, servers)
	c.Assert(err, jc.ErrorIsNil)

	data, err = os.ReadFile(clusterFile)
	c.Assert(err, jc.ErrorIsNil)

	// cluster.yaml should reflect the new server list.
	var result []dqlite.NodeInfo
	err = yaml.Unmarshal(data, &result)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(result, jc.DeepEquals, servers)
}

func (s *nodeManagerSuite) TestSetGetNodeInfoSuccess(c *gc.C) {
	subDir := strconv.Itoa(rand.Intn(10))

	cfg := fakeAgentConfig{dataDir: "/tmp/" + subDir}
	s.AddCleanup(func(*gc.C) { _ = os.RemoveAll(cfg.DataDir()) })

	m := NewNodeManager(cfg, stubLogger{}, coredatabase.NoopSlowQueryLogger{})
	dataDir, err := m.EnsureDataDir()
	c.Assert(err, jc.ErrorIsNil)

	infoFile := path.Join(dataDir, "info.yaml")

	// Write an info.yaml file into the Dqlite data directory.
	// We'll update it with a different address.
	data := []byte(`
Address: 127.0.0.1:17666
ID: 3297041220608546238
Role: 0
`[1:])

	err = os.WriteFile(infoFile, data, 0600)
	c.Assert(err, jc.ErrorIsNil)

	server := dqlite.NodeInfo{
		ID:      3297041220608546238,
		Address: "10.6.6.6:17666",
		Role:    0,
	}

	err = m.SetNodeInfo(server)
	c.Assert(err, jc.ErrorIsNil)

	// info.yaml should reflect the new node info.
	result, err := m.NodeInfo()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(result, jc.DeepEquals, server)
}

func (s *nodeManagerSuite) TestSetClusterToLocalNodeSuccess(c *gc.C) {
	subDir := strconv.Itoa(rand.Intn(10))

	cfg := fakeAgentConfig{dataDir: "/tmp/" + subDir}
	s.AddCleanup(func(*gc.C) { _ = os.RemoveAll(cfg.DataDir()) })

	m := NewNodeManager(cfg, stubLogger{}, coredatabase.NoopSlowQueryLogger{})
	ctx := context.Background()

	_, err := m.EnsureDataDir()
	c.Assert(err, jc.ErrorIsNil)

	servers := []dqlite.NodeInfo{
		{
			ID:      3297041220608546238,
			Address: "10.6.6.6:17666",
			Role:    0,
		}, {
			ID:      123456789,
			Address: "10.6.6.7:17666",
			Role:    0,
		},
	}

	err = m.SetClusterServers(ctx, servers)
	c.Assert(err, jc.ErrorIsNil)

	err = m.SetNodeInfo(servers[0])
	c.Assert(err, jc.ErrorIsNil)

	err = m.SetClusterToLocalNode(ctx)
	c.Assert(err, jc.ErrorIsNil)

	newServers, err := m.ClusterServers(ctx)
	c.Assert(err, jc.ErrorIsNil)
	c.Check(newServers, gc.DeepEquals, []dqlite.NodeInfo{servers[0]})
}

func (s *nodeManagerSuite) TestWithAddressOptionSuccess(c *gc.C) {
	m := NewNodeManager(nil, stubLogger{}, coredatabase.NoopSlowQueryLogger{})
	m.port = dqlitetesting.FindTCPPort(c)

	dqliteApp, err := app.New(c.MkDir(), m.WithAddressOption("127.0.0.1"))
	c.Assert(err, jc.ErrorIsNil)

	err = dqliteApp.Close()
	c.Assert(err, jc.ErrorIsNil)
}

func (s *nodeManagerSuite) TestWithTLSOptionSuccess(c *gc.C) {
	cfg := fakeAgentConfig{}
	m := NewNodeManager(cfg, stubLogger{}, coredatabase.NoopSlowQueryLogger{})

	withTLS, err := m.WithTLSOption()
	c.Assert(err, jc.ErrorIsNil)

	dqliteApp, err := app.New(c.MkDir(), withTLS)
	c.Assert(err, jc.ErrorIsNil)

	err = dqliteApp.Close()
	c.Assert(err, jc.ErrorIsNil)
}

func (s *nodeManagerSuite) TestWithClusterOptionSuccess(c *gc.C) {
	cfg := fakeAgentConfig{}
	m := NewNodeManager(cfg, stubLogger{}, coredatabase.NoopSlowQueryLogger{})

	dqliteApp, err := app.New(c.MkDir(), m.WithClusterOption([]string{"10.6.6.6"}))
	c.Assert(err, jc.ErrorIsNil)

	err = dqliteApp.Close()
	c.Assert(err, jc.ErrorIsNil)
}

func (s *nodeManagerSuite) TestWithPreferredCloudLocalAddressOptionNoAddrFallback(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	// Having no interfaces will trigger the loopback address fallback.
	src := NewMockConfigSource(ctrl)
	src.EXPECT().Interfaces().Return(nil, nil)

	m := NewNodeManager(nil, stubLogger{}, coredatabase.NoopSlowQueryLogger{})
	m.port = dqlitetesting.FindTCPPort(c)

	opt, err := m.WithPreferredCloudLocalAddressOption(src)
	c.Assert(err, jc.ErrorIsNil)

	dqliteApp, err := app.New(c.MkDir(), opt)
	c.Assert(err, jc.ErrorIsNil)

	c.Check(strings.Split(dqliteApp.Address(), ":")[0], gc.Equals, "127.0.0.1")

	err = dqliteApp.Close()
	c.Assert(err, jc.ErrorIsNil)
}

func (s *nodeManagerSuite) TestWithPreferredCloudLocalAddressOptionSingleAddrSuccess(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	localCloudIP := "192.168.10.254"

	// Loopback is ignored.
	loopback := NewMockConfigSourceNIC(ctrl)
	loopback.EXPECT().Type().Return(corenetwork.LoopbackDevice)
	loopback.EXPECT().Name().Return("lo")

	// Default LXD bridge is ignored.
	lxdbr0 := NewMockConfigSourceNIC(ctrl)
	lxdbr0.EXPECT().Type().Return(corenetwork.BridgeDevice)
	lxdbr0.EXPECT().Name().Return(network.DefaultLXDBridge)

	// A unique local-cloud address is used.
	addr := NewMockConfigSourceAddr(ctrl)
	addr.EXPECT().IP().Return(net.ParseIP(localCloudIP))

	eth0 := NewMockConfigSourceNIC(ctrl)
	eth0.EXPECT().Type().Return(corenetwork.EthernetDevice)
	eth0.EXPECT().Name().Return("eth0")
	eth0.EXPECT().Addresses().Return([]corenetwork.ConfigSourceAddr{addr}, nil)

	src := NewMockConfigSource(ctrl)
	src.EXPECT().Interfaces().Return([]corenetwork.ConfigSourceNIC{loopback, lxdbr0, eth0}, nil)

	m := NewNodeManager(nil, stubLogger{}, coredatabase.NoopSlowQueryLogger{})
	m.port = dqlitetesting.FindTCPPort(c)

	opt, err := m.WithPreferredCloudLocalAddressOption(src)
	c.Assert(err, jc.ErrorIsNil)

	dqliteApp, err := app.New(c.MkDir(), opt)

	// Now it is very unlikely that the machine we are running on just happens
	// to have the address we've chosen above, but we can verify the correct
	// behaviour either way.
	if err != nil {
		c.Check(err.Error(), jc.Contains, localCloudIP)
	} else {
		c.Check(strings.Split(dqliteApp.Address(), ":")[0], gc.Equals, localCloudIP)
		err = dqliteApp.Close()
		c.Assert(err, jc.ErrorIsNil)
	}
}

type fakeAgentConfig struct {
	agent.Config

	dataDir  string
	apiAddrs []string
}

// DataDir implements agent.Config.
func (cfg fakeAgentConfig) DataDir() string {
	return cfg.dataDir
}

// CACert implements agent.Config.
func (cfg fakeAgentConfig) CACert() string {
	return jujutesting.CACert
}

// StateServingInfo implements agent.AgentConfig.
func (cfg fakeAgentConfig) StateServingInfo() (controller.StateServingInfo, bool) {
	return controller.StateServingInfo{
		CAPrivateKey: jujutesting.CAKey,
		Cert:         jujutesting.ServerCert,
		PrivateKey:   jujutesting.ServerKey,
	}, true
}

// APIAddresses implements agent.Config.
func (cfg fakeAgentConfig) APIAddresses() ([]string, error) {
	return cfg.apiAddrs, nil
}

// DqlitePort implements agent.Config.
func (cfg fakeAgentConfig) DqlitePort() (int, bool) {
	return 0, false
}

type slowQuerySuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&slowQuerySuite{})

func (s *slowQuerySuite) TestSlowQueryParsing(c *gc.C) {
	tests := []struct {
		name              string
		msg               string
		args              []any
		threshold         time.Duration
		expectedQueryType queryType
		expectedDuration  float64
		expectedStmt      string
	}{
		{
			name:              "empty",
			msg:               "",
			expectedQueryType: normalQuery,
		},
		{
			name:              "normal query",
			msg:               "hello world",
			expectedQueryType: normalQuery,
		},
		{
			name: "wrong args",
			msg:  "%.3fs request query: %q",
			args: []any{
				time.Second.Seconds(),
			},
			threshold:         time.Millisecond,
			expectedQueryType: normalQuery,
		},
		{
			name:              "no args",
			msg:               "%.3fs request query: %q",
			args:              []any{},
			threshold:         time.Millisecond,
			expectedQueryType: normalQuery,
		},
		{
			name:              "too many args",
			msg:               "%.3fs request query: %q",
			args:              []any{1, 2, 3, 4},
			threshold:         time.Millisecond,
			expectedQueryType: normalQuery,
		},
		{
			name: "request slow query",
			msg:  "%.3fs request query: %q",
			args: []any{
				time.Second.Seconds(),
				"SELECT * FROM foo",
			},
			threshold:         time.Millisecond,
			expectedQueryType: slowQuery,
			expectedDuration:  time.Second.Seconds(),
			expectedStmt:      "SELECT * FROM foo",
		},
		{
			name: "request slow exec",
			msg:  "%.3fs request exec: %q",
			args: []any{
				time.Second.Seconds(),
				"INSERT INTO foo (bar) VALUES (666)",
			},
			threshold:         time.Millisecond,
			expectedQueryType: slowQuery,
			expectedDuration:  time.Second.Seconds(),
			expectedStmt:      "INSERT INTO foo (bar) VALUES (666)",
		},
		{
			name: "request slow exec",
			msg:  "%.3fs request exec: %q",
			args: []any{
				time.Second.Seconds(),
				"INSERT INTO foo (bar) VALUES (666)",
			},
			threshold:         time.Millisecond,
			expectedDuration:  time.Second.Seconds(),
			expectedQueryType: slowQuery,
			expectedStmt:      "INSERT INTO foo (bar) VALUES (666)",
		},
		{
			name: "request slow exec - ignored",
			msg:  "%.3fs request exec: %q",
			args: []any{
				time.Second.Seconds(),
				"INSERT INTO foo (bar) VALUES (666)",
			},
			threshold:         time.Second * 2,
			expectedQueryType: ignoreSlowQuery,
			expectedDuration:  time.Second.Seconds(),
			expectedStmt:      "INSERT INTO foo (bar) VALUES (666)",
		},
		{
			name: "request slow exec - ignored",
			msg:  "%.3fs request exec: %q",
			args: []any{
				time.Second.Seconds(),
				"INSERT INTO foo (bar) VALUES (666)",
			},
			threshold:         time.Second * 2,
			expectedQueryType: ignoreSlowQuery,
			expectedDuration:  time.Second.Seconds(),
			expectedStmt:      "INSERT INTO foo (bar) VALUES (666)",
		},
	}

	for _, test := range tests {
		c.Logf("test %q", test.name)
		queryType, duration, stmt := parseSlowQuery(test.msg, test.args, test.threshold)
		c.Assert(queryType, jc.DeepEquals, test.expectedQueryType)
		c.Assert(duration, gc.Equals, test.expectedDuration)
		c.Assert(stmt, gc.Equals, test.expectedStmt)
	}
}
