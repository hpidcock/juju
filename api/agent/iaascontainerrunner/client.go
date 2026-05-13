// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"strings"

	"github.com/juju/errors"
	"github.com/juju/names/v6"

	"github.com/juju/juju/api/agent/uniter"
	"github.com/juju/juju/api/base"
	"github.com/juju/juju/core/resource"
	domainresource "github.com/juju/juju/domain/deployment/charm/resource"
	"github.com/juju/juju/rpc/params"
)

// Client provides access to the APIs needed by the iaascontainerrunner worker.
// It wraps the existing ResourcesHookContext facade used by the uniter.
type Client struct {
	resources *uniter.ResourcesFacadeClient
	unitTag   names.UnitTag
}

// NewClient creates a new iaascontainerrunner API client using the uniter's
// ResourcesHookContext facade.
func NewClient(caller base.APICaller, unitTag names.UnitTag) (*Client, error) {
	resources, err := uniter.NewResourcesFacadeClient(caller, unitTag)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &Client{
		resources: resources,
		unitTag:   unitTag,
	}, nil
}

// ResourceInfo contains the OCI image details for a charm resource.
type ResourceInfo struct {
	RegistryPath string
	Username     string
	Password     string
}

// GetContainerResourceInfo returns OCI image details for the named resource.
// Returns nil if the resource is not found or is not an OCI image.
func (c *Client) GetContainerResourceInfo(ctx context.Context, resourceName string) (*ResourceInfo, error) {
	candidates := []string{resourceName, resourceName + "-image", resourceName + "_image"}
	for _, candidate := range candidates {
		res, _, err := c.resources.GetResource(ctx, candidate)
		if err != nil {
			if isResourceNotFound(err) {
				continue
			}
			return nil, errors.Trace(err)
		}
		info, err := resourceInfoFromResource(res)
		if err != nil {
			return nil, err
		}
		if info != nil {
			return info, nil
		}
	}

	// No matching OCI resource found for this container.
	return nil, nil
}

func isResourceNotFound(err error) bool {
	if params.IsCodeNotFound(err) || errors.IsNotFound(err) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "resource not found")
}

// resourceInfoFromResource extracts OCI image details from a resource.Resource.
func resourceInfoFromResource(res resource.Resource) (*ResourceInfo, error) {
	if res.Type != domainresource.TypeContainerImage {
		return nil, nil
	}
	// The OCI image registry path is embedded in the resource metadata
	// from the charm store. For OCI image resources, the Path field in
	// Meta holds the registry path.
	return &ResourceInfo{
		RegistryPath: res.Path,
	}, nil
}
