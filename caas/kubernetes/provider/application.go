// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package provider

import (
	"github.com/juju/juju/caas"
	"github.com/juju/juju/caas/kubernetes/provider/application"
)

func (k *kubernetesClient) Application(name string, deploymentType caas.DeploymentType) caas.Application {
	return application.NewApplication(name,
		k.namespace,
		k.modelUUID,
		deploymentType,
		k.client(),
		k.newWatcher,
		k.clock)
}
