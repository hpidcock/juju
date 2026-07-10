// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package lxdpeel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	lxdapi "github.com/canonical/lxd/shared/api"

	"github.com/juju/juju/internal/worker/iaascontainerrunner"
)

var _ iaascontainerrunner.PortProxyRunner = (*Runtime)(nil)

// listenKey is the full identity of a single listening socket reported by
// peel: it carries the address family, transport protocol, bind address and
// port number. Using the actual address lets us mirror proxy devices exactly
// (e.g. a container's 127.0.0.1:8080 becomes host 127.0.0.1:8080→container
// 127.0.0.1:8080, not a wildcard proxy).
type listenKey struct {
	stack string // "v4" or "v6"
	proto string // "tcp" or "udp"
	addr  string // bind address as reported by peel (e.g. "0.0.0.0", "::1")
	port  uint16
}

// loEvent matches the JSON emitted by peel's /watch endpoint.  The op field
// is "add", "remove" or "sync"; the remaining fields are populated for add
// and remove events.
type loEvent struct {
	Op    string `json:"op"`
	Stack string `json:"stack"` // "v4" or "v6"
	Proto string `json:"proto"` // "tcp" or "udp"
	Addr  string `json:"addr"`  // bind address
	Port  uint16 `json:"port"`
}

// containerProxy manages the LXD proxy devices we own for a single container.
// All methods are called from the container's watcher goroutine only — no
// locking is required.
type containerProxy struct {
	name    string
	client  instanceServer
	proxied map[listenKey]bool
}

func newContainerProxy(name string, client instanceServer) *containerProxy {
	return &containerProxy{name: name, client: client, proxied: make(map[listenKey]bool)}
}

func (cp *containerProxy) ensure(ctx context.Context, lk listenKey) {
	if cp.proxied[lk] {
		return
	}
	if err := ensureProxy(ctx, cp.client, cp.name, lk); err != nil {
		return
	}
	cp.proxied[lk] = true
}

func (cp *containerProxy) remove(ctx context.Context, lk listenKey) {
	if !cp.proxied[lk] {
		return
	}
	if err := removeProxy(ctx, cp.client, cp.name, lk); err != nil {
		return
	}
	delete(cp.proxied, lk)
}

func (cp *containerProxy) reconcile(ctx context.Context, snapshot map[listenKey]bool) {
	for lk := range cp.proxied {
		if !snapshot[lk] {
			cp.remove(ctx, lk)
		}
	}
	for lk := range snapshot {
		cp.ensure(ctx, lk)
	}
}

// removeAll tears down every proxy device we created. Called with a
// background context so cleanup is not gated on the worker's lifetime.
func (cp *containerProxy) removeAll() {
	ctx := context.Background()
	for lk := range cp.proxied {
		_ = removeProxy(ctx, cp.client, cp.name, lk)
		delete(cp.proxied, lk)
	}
}

// RunPortProxy implements iaascontainerrunner.PortProxyRunner.
//
// It scans the unit's peel loopback-socket directory for container sockets,
// subscribes to each container's /watch HTTP stream to learn every port the
// container is listening on, and manages a matching LXD proxy device for each
// listen — including loopback listeners. The proxy mirrors the bind address
// exactly: a container listening on 127.0.0.1:8080 gets a proxy device of
// listen=tcp:127.0.0.1:8080, connect=tcp:127.0.0.1:8080. It blocks until ctx
// is cancelled.
func (r *Runtime) RunPortProxy(ctx context.Context) error {
	dir := r.loopbackDir()
	if dir == "" {
		<-ctx.Done()
		return nil
	}

	// watchers maps socket-file name → cancel function for that container's
	// watcher goroutine.
	watchers := make(map[string]context.CancelFunc)

	scan := func() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		seen := make(map[string]bool, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			seen[name] = true
			if _, ok := watchers[name]; ok {
				continue // already watching
			}
			sockPath := filepath.Join(dir, name)
			cp := newContainerProxy(name, r.client)
			wctx, cancel := context.WithCancel(ctx)
			watchers[name] = cancel
			go func(wctx context.Context, cp *containerProxy, sockPath string) {
				defer cp.removeAll()
				watchContainerSock(wctx, cp, sockPath)
			}(wctx, cp, sockPath)
		}

		for name, cancel := range watchers {
			if !seen[name] {
				cancel()
				delete(watchers, name)
			}
		}
	}

	scan()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			for _, cancel := range watchers {
				cancel()
			}
			return nil
		case <-ticker.C:
			scan()
		}
	}
}

// watchContainerSock subscribes to a single container's /watch stream until
// ctx is cancelled, reconnecting after each failure.
func watchContainerSock(ctx context.Context, cp *containerProxy, sockPath string) {
	for ctx.Err() == nil {
		if err := watchContainerSockOnce(ctx, cp, sockPath); err != nil && ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// watchContainerSockOnce makes a single connection to sockPath, issues GET
// /watch, and processes events until the stream ends or ctx is cancelled.
// On a fresh connection, peel sends the current snapshot as a run of "add"
// events followed by a "sync" marker; watchContainerSockOnce uses the sync
// to reconcile against any proxy state left over from a prior connection.
func watchContainerSockOnce(ctx context.Context, cp *containerProxy, sockPath string) error {
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}
	defer hc.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://peel/watch", nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watch: %s", resp.Status)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 64*1024)

	// snapshot accumulates the pre-sync "add" events so that after the
	// "sync" marker we can reconcile against any stale proxy devices from
	// a previous connection.
	snapshot := make(map[listenKey]bool)
	synced := false

	for sc.Scan() {
		var ev loEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		lk := listenKey{stack: ev.Stack, proto: ev.Proto, addr: ev.Addr, port: ev.Port}
		switch ev.Op {
		case "add":
			if !synced {
				snapshot[lk] = true
			} else {
				cp.ensure(ctx, lk)
			}
		case "remove":
			if synced {
				cp.remove(ctx, lk)
			} else {
				delete(snapshot, lk)
			}
		case "sync":
			synced = true
			cp.reconcile(ctx, snapshot)
		}
	}
	return sc.Err()
}

// ensureProxy adds a host-to-container LXD proxy device for the given
// container and listen key, if it does not already exist.
func ensureProxy(ctx context.Context, client instanceServer, containerName string, lk listenKey) error {
	inst, etag, err := client.GetInstance(containerName)
	if err != nil {
		if lxdapi.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("getting container %q: %w", containerName, err)
	}

	devName := proxyDeviceName(lk)
	if _, ok := inst.Devices[devName]; ok {
		return nil // already exists
	}

	addrSpec := lxdAddrSpec(lk.proto, lk.addr, lk.port)
	devices := copyDevices(inst.Devices)
	devices[devName] = map[string]string{
		"type":    "proxy",
		"listen":  addrSpec,
		"connect": addrSpec,
		"bind":    "host",
	}

	updated := lxdapi.InstancePut{
		Architecture: inst.Architecture,
		Config:       inst.Config,
		Devices:      devices,
		Ephemeral:    inst.Ephemeral,
		Profiles:     inst.Profiles,
		Stateful:     inst.Stateful,
		Description:  inst.Description,
	}
	op, err := client.UpdateInstance(containerName, updated, etag)
	if err != nil {
		return fmt.Errorf("adding proxy device to %q: %w", containerName, err)
	}
	return op.WaitContext(ctx)
}

// removeProxy removes the LXD proxy device for the given container and listen
// key, if it exists.
func removeProxy(ctx context.Context, client instanceServer, containerName string, lk listenKey) error {
	inst, etag, err := client.GetInstance(containerName)
	if err != nil {
		if lxdapi.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("getting container %q: %w", containerName, err)
	}

	devName := proxyDeviceName(lk)
	if _, ok := inst.Devices[devName]; !ok {
		return nil // already gone
	}

	devices := copyDevices(inst.Devices)
	delete(devices, devName)

	updated := lxdapi.InstancePut{
		Architecture: inst.Architecture,
		Config:       inst.Config,
		Devices:      devices,
		Ephemeral:    inst.Ephemeral,
		Profiles:     inst.Profiles,
		Stateful:     inst.Stateful,
		Description:  inst.Description,
	}
	op, err := client.UpdateInstance(containerName, updated, etag)
	if err != nil {
		return fmt.Errorf("removing proxy device from %q: %w", containerName, err)
	}
	return op.WaitContext(ctx)
}

// proxyDeviceName returns a deterministic LXD device name for a proxy device.
// The address is sanitised so that dots and colons become hyphens; a leading
// or trailing hyphen (from e.g. "::") is stripped and replaced with "any".
func proxyDeviceName(lk listenKey) string {
	addrSan := addrSanitise(lk.addr)
	return fmt.Sprintf("port-proxy-%s-%s-%s-%d", lk.stack, lk.proto, addrSan, lk.port)
}

func addrSanitise(addr string) string {
	out := make([]byte, len(addr))
	for i := range addr {
		switch addr[i] {
		case '.', ':':
			out[i] = '-'
		default:
			out[i] = addr[i]
		}
	}
	// Trim leading/trailing hyphens that arise from addresses like "::" → "--".
	s := string(out)
	for len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == '-' {
		s = s[:len(s)-1]
	}
	if s == "" {
		s = "any"
	}
	return s
}

// lxdAddrSpec formats a protocol+address+port string for an LXD proxy device.
// IPv6 addresses are wrapped in square brackets as required by LXD.
func lxdAddrSpec(proto, addr string, port uint16) string {
	ip := net.ParseIP(addr)
	if ip != nil && ip.To4() == nil {
		// IPv6 address: LXD requires bracket notation.
		return fmt.Sprintf("%s:[%s]:%d", proto, addr, port)
	}
	return fmt.Sprintf("%s:%s:%d", proto, addr, port)
}

// copyDevices returns a shallow copy of an LXD device map.
func copyDevices(src map[string]map[string]string) map[string]map[string]string {
	dst := make(map[string]map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
