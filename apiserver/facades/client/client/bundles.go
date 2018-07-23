// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package client

import (
	"gopkg.in/juju/names.v2"

	"github.com/juju/juju/apiserver/facades/client/bundle"
	"github.com/juju/juju/apiserver/params"
)

// GetBundleChanges returns the list of changes required to deploy the given
// bundle data. The changes are sorted by requirements, so that they can be
// applied in order.
// This call is deprecated, clients should use the GetChanges endpoint on the
// Bundle facade.
func (c *Client) GetBundleChanges(args params.BundleChangesParams) (params.BundleChangesResults, error) {
	st := c.api.state()

	bundleAPI, err := bundle.NewBundleAPI(bundle.NewStateShim(st), c.api.auth, names.NewModelTag(st.ModelUUID()))
	if err != nil {
		return params.BundleChangesResults{}, err
	}
	return bundleAPI.GetChanges(args)
}
