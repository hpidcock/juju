// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package iaascontainerrunner

import (
	"context"
	"io"
	"strings"

	"github.com/juju/errors"
	"github.com/juju/names/v6"

	"github.com/juju/juju/api/agent/uniter"
	"github.com/juju/juju/api/base"
	"github.com/juju/juju/core/resource"
	domainresource "github.com/juju/juju/domain/deployment/charm/resource"
	"github.com/juju/juju/internal/docker"
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
// It tries the resource name directly, then common suffixed variants used by
// charm authors to name OCI image resources.
// Returns errors.NotFound if no matching OCI image resource can be resolved.
func (c *Client) GetContainerResourceInfo(ctx context.Context, resourceName string) (*ResourceInfo, error) {
	candidates := []string{resourceName, resourceName + "-image", resourceName + "_image"}
	for _, candidate := range candidates {
		res, body, err := c.resources.GetResource(ctx, candidate)
		if err != nil {
			if isResourceNotFound(err) {
				continue
			}
			return nil, errors.Trace(err)
		}
		info, err := resourceInfoFromBody(res, body)
		// Always close after reading, regardless of outcome.
		body.Close()
		if err != nil {
			return nil, err
		}
		if info != nil {
			return info, nil
		}
	}

	// No matching OCI resource found for this container.
	return nil, errors.NotFoundf("OCI image resource for container %q", resourceName)
}

func isResourceNotFound(err error) bool {
	if params.IsCodeNotFound(err) || errors.IsNotFound(err) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "resource not found")
}

// resourceInfoFromBody extracts OCI image details from a resource response.
// For container image resources the HTTP response body contains a JSON-encoded
// docker.DockerImageDetails value produced by the container image metadata
// service; all other resource types return nil.
func resourceInfoFromBody(res resource.Resource, body io.Reader) (*ResourceInfo, error) {
	if res.Type != domainresource.TypeContainerImage {
		return nil, nil
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, errors.Annotate(err, "reading container image resource body")
	}
	details, err := docker.UnmarshalDockerResource(data)
	if err != nil {
		return nil, errors.Annotate(err, "parsing container image resource")
	}
	return &ResourceInfo{
		RegistryPath: details.RegistryPath,
		Username:     details.Username,
		Password:     details.Password,
	}, nil
}
