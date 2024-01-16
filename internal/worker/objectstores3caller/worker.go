// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package objectstores3caller

import (
	context "context"
	"sync"
	"time"

	"github.com/juju/clock"
	"github.com/juju/errors"
	"github.com/juju/retry"
	"github.com/juju/worker/v4"
	"github.com/juju/worker/v4/catacomb"
	"github.com/juju/worker/v4/dependency"

	"github.com/juju/juju/controller"
	"github.com/juju/juju/core/objectstore"
	coretrace "github.com/juju/juju/core/trace"
	"github.com/juju/juju/core/watcher"
	"github.com/juju/juju/core/watcher/eventsource"
	"github.com/juju/juju/internal/s3client"
)

const (
	// default retry strategy for when the forbidden error is returned.
	defaultRetryAttempts    = 10
	defaultRetryDelay       = time.Second * 1
	defaultRetryMaxDelay    = time.Second * 20
	defaultRetryMaxDuration = time.Minute
)

// ControllerService is the interface that the worker uses to get the
// controller configuration.
type ControllerService interface {
	// ControllerConfig returns the current controller configuration.
	ControllerConfig(context.Context) (controller.Config, error)
	// Watch returns a watcher that returns keys for any changes to controller
	// config.
	Watch() (watcher.StringsWatcher, error)
}

type workerConfig struct {
	ControllerService ControllerService
	HTTPClient        s3client.HTTPClient
	NewClient         NewClientFunc
	Tracer            coretrace.Tracer
	Logger            s3client.Logger
	Clock             clock.Clock
}

// Validate returns an error if the workerConfig is not valid.
func (cfg workerConfig) Validate() error {
	if cfg.ControllerService == nil {
		return errors.NotValidf("nil ControllerService")
	}
	if cfg.HTTPClient == nil {
		return errors.NotValidf("nil HTTPClient")
	}
	if cfg.NewClient == nil {
		return errors.NotValidf("nil NewClient")
	}
	if cfg.Clock == nil {
		return errors.NotValidf("nil Clock")
	}
	return nil
}

type s3Worker struct {
	catacomb catacomb.Catacomb
	config   workerConfig

	mutex   sync.Mutex
	session objectstore.Session
}

func newS3Worker(config workerConfig) (worker.Worker, error) {
	if err := config.Validate(); err != nil {
		return nil, errors.Trace(err)
	}

	w := &s3Worker{
		config: config,
	}

	if err := catacomb.Invoke(catacomb.Plan{
		Site: &w.catacomb,
		Work: w.loop,
	}); err != nil {
		return nil, errors.Trace(err)
	}

	return w, nil
}

// Session calls the given function with a session.
// The func maybe called multiple times if the underlying session has
// invalid credentials. Therefore session might not be the same across
// calls. The function should be idempotent.
func (w *s3Worker) Session(ctx context.Context, fn func(context.Context, objectstore.Session) error) error {
	ctx, trace := coretrace.Start(ctx, coretrace.NameFromFunc())
	defer trace.End()

	return retry.Call(retry.CallArgs{
		Func: func() error {
			w.mutex.Lock()
			defer w.mutex.Unlock()
			return fn(ctx, w.session)
		},
		IsFatalError: func(err error) bool {
			// If the forbidden error is returned, then it's not fatal, retry
			// the operation.
			return !errors.Is(err, errors.Forbidden)
		},
		Attempts:    defaultRetryAttempts,
		Delay:       defaultRetryDelay,
		MaxDuration: defaultRetryMaxDuration,
		BackoffFunc: retry.ExpBackoff(defaultRetryDelay, defaultRetryMaxDelay, 1.5, true),
		Clock:       w.config.Clock,
		Stop:        ctx.Done(),
	})
}

// Kill is part of the worker.Worker interface.
func (w *s3Worker) Kill() {
	w.catacomb.Kill(nil)
}

// Wait is part of the worker.Worker interface.
func (w *s3Worker) Wait() error {
	return w.catacomb.Wait()
}

func (w *s3Worker) loop() (err error) {
	watcher, err := w.config.ControllerService.Watch()
	if err != nil {
		return errors.Trace(err)
	}

	ctx, cancel := w.scopedContext()
	defer cancel()

	if err := w.addWatcher(ctx, watcher); err != nil {
		return errors.Trace(err)
	}

	for {
		select {
		case <-w.catacomb.Dying():
			return w.catacomb.ErrDying()
		case keys := <-watcher.Changes():
			// If any of the keys we care about have changed, then we need to
			// update the session.
			if !containsObjectStoreKey(keys) {
				continue
			}

			// Attempt to get the controller config. If we can't get it, then
			// defer the update until the next change or until
			controllerConfig, err := w.config.ControllerService.ControllerConfig(ctx)
			if err != nil {
				return errors.Trace(err)
			}

			// We're no longer using S3, so we need to stop this worker.
			if controllerConfig.ObjectStoreType() != objectstore.S3Backend {
				return dependency.ErrUninstall
			}

			client, err := w.config.NewClient(
				controllerConfig.ObjectStoreS3Endpoint(),
				w.config.HTTPClient,
				s3client.StaticCredentials{
					Key:     controllerConfig.ObjectStoreS3StaticKey(),
					Secret:  controllerConfig.ObjectStoreS3StaticSecret(),
					Session: controllerConfig.ObjectStoreS3StaticSession(),
				},
				w.config.Logger,
			)
			if err != nil {
				return errors.Trace(err)
			}

			w.mutex.Lock()
			w.session = client
			w.mutex.Unlock()
		}
	}
}

func (w *s3Worker) addWatcher(ctx context.Context, watcher eventsource.Watcher[[]string]) error {
	if err := w.catacomb.Add(watcher); err != nil {
		return errors.Trace(err)
	}

	// Consume the initial events from the watchers. The notify watcher will
	// dispatch an initial event when it is created, so we need to consume
	// that event before we can start watching.
	if _, err := eventsource.ConsumeInitialEvent[[]string](ctx, watcher); err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (w *s3Worker) scopedContext() (context.Context, context.CancelFunc) {
	return context.WithCancel(w.catacomb.Context(context.Background()))
}

var objectStoreKeys = map[string]struct{}{
	controller.ObjectStoreS3Endpoint:      {},
	controller.ObjectStoreS3StaticKey:     {},
	controller.ObjectStoreS3StaticSecret:  {},
	controller.ObjectStoreS3StaticSession: {},
}

// containsObjectStoreKey returns true if the key is interesting to the worker.
func containsObjectStoreKey(keys []string) bool {
	for _, key := range keys {
		if _, ok := objectStoreKeys[key]; ok {
			return true
		}
	}
	return false
}
