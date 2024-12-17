// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package addons

import (
	"path"
	"runtime"

	"github.com/juju/clock"
	"github.com/juju/errors"
	"github.com/juju/loggo"
	"github.com/juju/worker/v3"
	"github.com/juju/worker/v3/catacomb"
	"github.com/juju/worker/v3/dependency"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/juju/juju/cmd/jujud/agent/engine"
	"github.com/juju/juju/core/machinelock"
	"github.com/juju/juju/core/presence"
	"github.com/juju/juju/worker/introspection"
)

var logger = loggo.GetLogger("juju.cmd.jujud.agent.addons")

// IntrospectionSocketName is the name of the socket file inside
// the agent's directory used for introspection calls.
const IntrospectionSocketName = "introspection.socket"

// IntrospectionConfig defines the various components that the introspection
// worker reports on or needs to start up.
type IntrospectionConfig struct {
	AgentDir           string
	Engine             *dependency.Engine
	StatePoolReporter  introspection.Reporter
	PubSubReporter     introspection.Reporter
	MachineLock        machinelock.Lock
	PrometheusGatherer prometheus.Gatherer
	PresenceRecorder   presence.Recorder
	Clock              clock.Clock
	LocalHub           introspection.SimpleHub
	CentralHub         introspection.StructuredHub
	LeaseFSM           introspection.Leases

	WorkerFunc func(config introspection.Config) (worker.Worker, error)
}

// StartIntrospection creates the introspection worker. It cannot and should
// not be in the engine itself as it reports on the engine, and other aspects
// of the runtime.
func StartIntrospection(cfg IntrospectionConfig) (worker.Worker, error) {
	if runtime.GOOS != "linux" {
		logger.Debugf("introspection worker not supported on %q", runtime.GOOS)
		return nil, nil
	}
	socketName := path.Join(cfg.AgentDir, IntrospectionSocketName)
	w, err := cfg.WorkerFunc(introspection.Config{
		SocketName:         socketName,
		DepEngine:          cfg.Engine,
		StatePool:          cfg.StatePoolReporter,
		PubSub:             cfg.PubSubReporter,
		MachineLock:        cfg.MachineLock,
		PrometheusGatherer: cfg.PrometheusGatherer,
		Presence:           cfg.PresenceRecorder,
		Clock:              cfg.Clock,
		LocalHub:           cfg.LocalHub,
		CentralHub:         cfg.CentralHub,
		Leases:             cfg.LeaseFSM,
	})
	if err != nil {
		return nil, errors.Trace(err)
	}
	return w, nil
}

// NewPrometheusRegistry returns a new prometheus.Registry with
// the Go and process metric collectors registered. This registry
// is exposed by the introspection abstract domain socket on all
// Linux agents.
func NewPrometheusRegistry() (*prometheus.Registry, error) {
	r := prometheus.NewRegistry()
	if err := r.Register(prometheus.NewGoCollector()); err != nil {
		return nil, errors.Trace(err)
	}
	if err := r.Register(prometheus.NewProcessCollector(
		prometheus.ProcessCollectorOpts{})); err != nil {
		return nil, errors.Trace(err)
	}
	return r, nil
}

// RegisterEngineMetrics registers the metrics sink on a prometheus registerer,
// ensuring that we cleanup when the worker has stopped.
func RegisterEngineMetrics(registry prometheus.Registerer, metrics prometheus.Collector, worker worker.Worker, sink engine.MetricSink) error {
	if err := registry.Register(metrics); err != nil {
		return errors.Annotatef(err, "failed to register engine metrics")
	}

	go func() {
		_ = worker.Wait()
		_ = sink.Unregister()
		_ = registry.Unregister(metrics)
	}()
	return nil
}

// IntrospectedEngine binds any number of introspection workers to die after the engine worker.
func IntrospectedEngine(engine *dependency.Engine, workers ...worker.Worker) (worker.Worker, error) {
	w := &introspectedEngineWorker{
		engine: engine,
	}
	init := []worker.Worker{}
	for _, worker := range workers {
		if worker == nil {
			continue
		}
		init = append(init, worker)
	}
	err := catacomb.Invoke(catacomb.Plan{
		Site: &w.catacomb,
		Work: engine.Wait,
		Init: init,
	})
	if err != nil {
		return nil, err
	}
	return w, nil
}

type introspectedEngineWorker struct {
	engine   *dependency.Engine
	catacomb catacomb.Catacomb
}

func (w *introspectedEngineWorker) Kill() {
	w.engine.Kill()
}

func (w *introspectedEngineWorker) Wait() error {
	err := w.engine.Wait()
	w.catacomb.Kill(nil)
	_ = w.catacomb.Wait()
	return err
}

func (w *introspectedEngineWorker) Report() map[string]interface{} {
	return w.engine.Report()
}
