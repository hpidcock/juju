// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package caasapplicationprovisioner

import (
	"fmt"

	"github.com/juju/errors"
	"github.com/juju/loggo"
	"github.com/juju/names/v4"

	"github.com/juju/juju/apiserver/common"
	charmscommon "github.com/juju/juju/apiserver/common/charms"
	apiservererrors "github.com/juju/juju/apiserver/errors"
	"github.com/juju/juju/apiserver/facade"
	"github.com/juju/juju/apiserver/params"
	"github.com/juju/juju/caas"
	"github.com/juju/juju/caas/kubernetes/provider"
	"github.com/juju/juju/cloudconfig/podcfg"
	"github.com/juju/juju/core/network"
	"github.com/juju/juju/core/status"
	"github.com/juju/juju/environs/config"
	"github.com/juju/juju/environs/tags"
	"github.com/juju/juju/state"
	"github.com/juju/juju/state/stateenvirons"
	"github.com/juju/juju/state/watcher"
	"github.com/juju/juju/storage"
	"github.com/juju/juju/storage/poolmanager"
	"github.com/juju/juju/version"
)

var logger = loggo.GetLogger("juju.apiserver.caasapplicationprovisioner")

type API struct {
	*common.PasswordChanger
	*common.LifeGetter
	*charmscommon.CharmsAPI

	auth      facade.Authorizer
	resources facade.Resources

	state              CAASApplicationProvisionerState
	storagePoolManager poolmanager.PoolManager
	registry           storage.ProviderRegistry
}

// NewStateCAASApplicationProvisionerAPI provides the signature required for facade registration.
func NewStateCAASApplicationProvisionerAPI(ctx facade.Context) (*API, error) {
	authorizer := ctx.Auth()
	resources := ctx.Resources()

	model, err := ctx.State().Model()
	if err != nil {
		return nil, errors.Trace(err)
	}
	broker, err := stateenvirons.GetNewCAASBrokerFunc(caas.New)(model)
	if err != nil {
		return nil, errors.Annotate(err, "getting caas client")
	}
	registry := stateenvirons.NewStorageProviderRegistry(broker)
	pm := poolmanager.New(state.NewStateSettings(ctx.State()), registry)

	return NewCAASApplicationProvisionerAPI(ctx.State(), resources, authorizer, pm, registry)
}

// NewCAASApplicationProvisionerAPI returns a new CAAS operator provisioner API facade.
func NewCAASApplicationProvisionerAPI(
	st *state.State,
	resources facade.Resources,
	authorizer facade.Authorizer,
	storagePoolManager poolmanager.PoolManager,
	registry storage.ProviderRegistry,
) (*API, error) {
	if !authorizer.AuthController() {
		return nil, apiservererrors.ErrPerm
	}

	commonCharmsAPI, err := charmscommon.NewCharmsAPI(st, authorizer)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &API{
		PasswordChanger:    common.NewPasswordChanger(st, common.AuthFuncForTagKind(names.ApplicationTagKind)),
		LifeGetter:         common.NewLifeGetter(st, common.AuthFuncForTagKind(names.ApplicationTagKind)),
		CharmsAPI:          commonCharmsAPI,
		auth:               authorizer,
		resources:          resources,
		state:              stateShim{st},
		storagePoolManager: storagePoolManager,
		registry:           registry,
	}, nil
}

// WatchApplications starts a StringsWatcher to watch CAAS applications
// deployed to this model.
func (a *API) WatchApplications() (params.StringsWatchResult, error) {
	watch := a.state.WatchApplications()
	// Consume the initial event and forward it to the result.
	if changes, ok := <-watch.Changes(); ok {
		return params.StringsWatchResult{
			StringsWatcherId: a.resources.Register(watch),
			Changes:          changes,
		}, nil
	}
	return params.StringsWatchResult{}, watcher.EnsureErr(watch)
}

// ProvisioningInfo returns the info needed to provision a caas application.
func (a *API) ProvisioningInfo(args params.Entities) (params.CAASApplicationProvisioningInfoResults, error) {
	var result params.CAASApplicationProvisioningInfoResults
	cfg, err := a.state.ControllerConfig()
	if err != nil {
		return result, err
	}

	model, err := a.state.Model()
	if err != nil {
		return result, errors.Trace(err)
	}
	modelConfig, err := model.ModelConfig()
	if err != nil {
		return result, errors.Trace(err)
	}

	vers, ok := modelConfig.AgentVersion()
	if !ok {
		return result, errors.NewNotValid(nil,
			fmt.Sprintf("agent version is missing in model config %q", modelConfig.Name()),
		)
	}

	resourceTags := tags.ResourceTags(
		names.NewModelTag(model.UUID()),
		names.NewControllerTag(cfg.ControllerUUID()),
		modelConfig,
	)

	imagePath := podcfg.GetJujuK8sOCIImagePath(cfg, vers.ToPatch(), version.OfficialBuild)

	apiHostPorts, err := a.state.APIHostPortsForAgents()
	if err != nil {
		return result, errors.Annotatef(err, "getting api addresses")
	}

	addrs := []string(nil)
	for _, hostPorts := range apiHostPorts {
		ordered := hostPorts.HostPorts().PrioritizedForScope(network.ScopeMatchCloudLocal)
		for _, addr := range ordered {
			if addr != "" {
				addrs = append(addrs, addr)
			}
		}
	}

	caCert, _ := cfg.CACert()

	oneProvisioningInfo := func(storageRequired bool) params.CAASApplicationProvisioningInfo {
		var charmStorageParams *params.KubernetesFilesystemParams
		storageClassName, _ := modelConfig.AllAttrs()[provider.WorkloadStorageKey].(string)
		if storageRequired {
			if storageClassName == "" {
				return params.CAASApplicationProvisioningInfo{
					Error: apiservererrors.ServerError(errors.New("no workload storage defined")),
				}
			}
			charmStorageParams, err = CharmStorageParams(cfg.ControllerUUID(), storageClassName, modelConfig, "", a.storagePoolManager, a.registry)
			if err != nil {
				return params.CAASApplicationProvisioningInfo{
					Error: apiservererrors.ServerError(errors.Annotatef(err, "getting workload storage parameters")),
				}
			}
			charmStorageParams.Tags = resourceTags
		}
		return params.CAASApplicationProvisioningInfo{
			ImagePath:    imagePath,
			Version:      vers,
			APIAddresses: addrs,
			CACert:       caCert,
			CharmStorage: charmStorageParams,
			Tags:         resourceTags,
		}
	}
	result.Results = make([]params.CAASApplicationProvisioningInfo, len(args.Entities))
	for i, entity := range args.Entities {
		appName, err := names.ParseApplicationTag(entity.Tag)
		if err != nil {
			result.Results[i].Error = apiservererrors.ServerError(err)
			continue
		}
		app, err := a.state.Application(appName.Id())
		if err != nil {
			result.Results[i].Error = apiservererrors.ServerError(err)
			continue
		}
		ch, _, err := app.Charm()
		if err != nil {
			result.Results[i].Error = apiservererrors.ServerError(err)
			continue
		}
		needStorage := provider.RequireOperatorStorage(ch.Meta().MinJujuVersion)
		logger.Debugf("application %s has min-juju-version=%v, so charm storage is %v",
			appName.String(), ch.Meta().MinJujuVersion, needStorage)
		result.Results[i] = oneProvisioningInfo(needStorage)
	}
	return result, nil
}

// SetOperatorStatus sets the status of each given entity.
func (a *API) SetOperatorStatus(args params.SetStatus) (params.ErrorResults, error) {
	results := params.ErrorResults{
		Results: make([]params.ErrorResult, len(args.Entities)),
	}
	for i, arg := range args.Entities {
		tag, err := names.ParseApplicationTag(arg.Tag)
		if err != nil {
			results.Results[i].Error = apiservererrors.ServerError(err)
			continue
		}
		info := status.StatusInfo{
			Status:  status.Status(arg.Status),
			Message: arg.Info,
			Data:    arg.Data,
		}
		results.Results[i].Error = apiservererrors.ServerError(a.setStatus(tag, info))
	}
	return results, nil
}

func (a *API) setStatus(tag names.ApplicationTag, info status.StatusInfo) error {
	app, err := a.state.Application(tag.Id())
	if err != nil {
		return errors.Trace(err)
	}
	return app.SetOperatorStatus(info)
}

// CharmStorageParams returns filesystem parameters needed
// to provision storage used for a charm operator or workload.
func CharmStorageParams(
	controllerUUID string,
	storageClassName string,
	modelCfg *config.Config,
	poolName string,
	poolManager poolmanager.PoolManager,
	registry storage.ProviderRegistry,
) (*params.KubernetesFilesystemParams, error) {
	// The defaults here are for operator storage.
	// Workload storage will override these elsewhere.
	var size uint64 = 1024
	tags := tags.ResourceTags(
		names.NewModelTag(modelCfg.UUID()),
		names.NewControllerTag(controllerUUID),
		modelCfg,
	)

	result := &params.KubernetesFilesystemParams{
		StorageName: "charm",
		Size:        size,
		Provider:    string(provider.K8s_ProviderType),
		Tags:        tags,
		Attributes:  make(map[string]interface{}),
	}

	// The storage key value from the model config might correspond
	// to a storage pool, unless there's been a specific storage pool
	// requested.
	// First, blank out the fallback pool name used in previous
	// versions of Juju.
	if poolName == string(provider.K8s_ProviderType) {
		poolName = ""
	}
	maybePoolName := poolName
	if maybePoolName == "" {
		maybePoolName = storageClassName
	}

	providerType, attrs, err := poolStorageProvider(poolManager, registry, maybePoolName)
	if err != nil && (!errors.IsNotFound(err) || poolName != "") {
		return nil, errors.Trace(err)
	}
	if err == nil {
		result.Provider = string(providerType)
		if len(attrs) > 0 {
			result.Attributes = attrs
		}
	}
	if _, ok := result.Attributes[provider.StorageClass]; !ok && result.Provider == string(provider.K8s_ProviderType) {
		result.Attributes[provider.StorageClass] = storageClassName
	}
	return result, nil
}

func poolStorageProvider(poolManager poolmanager.PoolManager, registry storage.ProviderRegistry, poolName string) (storage.ProviderType, map[string]interface{}, error) {
	pool, err := poolManager.Get(poolName)
	if errors.IsNotFound(err) {
		// If there's no pool called poolName, maybe a provider type
		// has been specified directly.
		providerType := storage.ProviderType(poolName)
		provider, err1 := registry.StorageProvider(providerType)
		if err1 != nil {
			// The name can't be resolved as a storage provider type,
			// so return the original "pool not found" error.
			return "", nil, errors.Trace(err)
		}
		if !provider.Supports(storage.StorageKindFilesystem) {
			return "", nil, errors.NotValidf("storage provider %q", providerType)
		}
		return providerType, nil, nil
	} else if err != nil {
		return "", nil, errors.Trace(err)
	}
	providerType := pool.Provider()
	return providerType, pool.Attrs(), nil
}

// ApplicationCharmURLs finds the CharmURL for an application.
func (a *API) ApplicationCharmURLs(args params.Entities) (params.StringResults, error) {
	res := params.StringResults{
		Results: make([]params.StringResult, len(args.Entities)),
	}
	for i, entity := range args.Entities {
		appTag, err := names.ParseApplicationTag(entity.Tag)
		if err != nil {
			res.Results[i].Error = apiservererrors.ServerError(err)
			continue
		}
		app, err := a.state.Application(appTag.Id())
		if err != nil {
			res.Results[i].Error = apiservererrors.ServerError(err)
			continue
		}
		ch, _, err := app.Charm()
		if err != nil {
			res.Results[i].Error = apiservererrors.ServerError(err)
			continue
		}
		res.Results[i].Result = ch.URL().String()
	}
	return res, nil
}
