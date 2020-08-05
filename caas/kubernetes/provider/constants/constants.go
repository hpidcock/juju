// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package k8sconstants

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/juju/juju/agent"
)

const (
	// JujuRunServerSocketPort is the port used by juju run callbacks.
	JujuRunServerSocketPort = 30666

	// TemplateFileNameAgentConf is the template agent.conf file name.
	TemplateFileNameAgentConf = "template-" + agent.AgentConfigFilename

	CAASProviderType = "kubernetes"
)

func DefaultPropagationPolicy() *metav1.DeletionPropagation {
	v := metav1.DeletePropagationForeground
	return &v
}
