// Copyright 2012, 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sync

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/juju/errors"
	"github.com/juju/http/v2"
	"github.com/juju/loggo"
	"github.com/juju/utils/v3"
	"github.com/juju/version/v2"

	"github.com/juju/juju/core/arch"
	"github.com/juju/juju/environs/simplestreams"
	"github.com/juju/juju/environs/storage"
	envtools "github.com/juju/juju/environs/tools"
	"github.com/juju/juju/juju/keys"
	coretools "github.com/juju/juju/tools"
	jujuversion "github.com/juju/juju/version"
)

var logger = loggo.GetLogger("juju.environs.sync")

// SyncContext describes the context for tool synchronization.
type SyncContext struct {
	// TargetToolsFinder is a ToolsFinder provided to find existing
	// tools in the target destination.
	TargetToolsFinder ToolsFinder

	// TargetToolsUploader is a ToolsUploader provided to upload
	// tools to the target destination.
	TargetToolsUploader ToolsUploader

	// AllVersions controls the copy of all versions, not only the latest.
	// TODO: remove here because it's only used for tests!
	AllVersions bool

	// DryRun controls that nothing is copied. Instead it's logged
	// what would be coppied.
	DryRun bool

	// Stream specifies the simplestreams stream to use (defaults to "Released").
	Stream string

	// Source, if non-empty, specifies a directory in the local file system
	// to use as a source.
	Source string

	// ChosenVersion is the requested version to upload.
	ChosenVersion version.Number
}

// ToolsFinder provides an interface for finding tools of a specified version.
type ToolsFinder interface {
	// FindTools returns a list of tools with the specified major version in the specified stream.
	FindTools(major int, stream string) (coretools.List, error)
}

// ToolsUploader provides an interface for uploading tools and associated
// metadata.
type ToolsUploader interface {
	// UploadTools uploads the tools with the specified version and tarball contents.
	UploadTools(toolsDir, stream string, tools *coretools.Tools, data []byte) error
}

// SyncTools copies the Juju tools tarball from the official bucket
// or a specified source directory into the user's environment.
func SyncTools(syncContext *SyncContext) error {
	sourceDataSource, err := selectSourceDatasource(syncContext)
	if err != nil {
		return errors.Trace(err)
	}

	logger.Infof("listing available agent binaries")
	if syncContext.ChosenVersion.Major == 0 && syncContext.ChosenVersion.Minor == 0 {
		syncContext.ChosenVersion.Major = jujuversion.Current.Major
		syncContext.ChosenVersion.Minor = -1
		if !syncContext.AllVersions {
			syncContext.ChosenVersion.Minor = jujuversion.Current.Minor
		}
	}

	toolsDir := syncContext.Stream
	// If no stream has been specified, assume "released" for non-devel versions of Juju.
	if syncContext.Stream == "" {
		// We now store the tools in a directory named after their stream, but the
		// legacy behaviour is to store all tools in a single "releases" directory.
		toolsDir = envtools.ReleasedStream
		// Always use the primary stream here - the user can specify
		// to override that decision.
		syncContext.Stream = envtools.PreferredStreams(&jujuversion.Current, false, "")[0]
	}
	// TODO (stickupkid): We should lift this simplestreams constructor out of
	// this function.
	ss := simplestreams.NewSimpleStreams(simplestreams.DefaultDataSourceFactory())
	// For backwards compatibility with cloud storage, if there are no tools in the specified stream,
	// double check the release stream.
	// TODO - remove this when we no longer need to support cloud storage upgrades.
	streams := []string{syncContext.Stream, envtools.ReleasedStream}
	sourceTools, err := envtools.FindToolsForCloud(
		ss,
		[]simplestreams.DataSource{sourceDataSource}, simplestreams.CloudSpec{},
		streams, syncContext.ChosenVersion.Major, syncContext.ChosenVersion.Minor, coretools.Filter{})
	if err != nil {
		return errors.Trace(err)
	}

	logger.Infof("found %d agent binaries", len(sourceTools))
	for _, tool := range sourceTools {
		logger.Debugf("found source agent binary: %v", tool)
	}

	logger.Infof("listing target agent binaries storage")

	result, err := sourceTools.Match(coretools.Filter{Number: syncContext.ChosenVersion})
	logger.Tracef("syncContext.ChosenVersion %s, result %s", syncContext.ChosenVersion, result)
	if err != nil {
		return errors.Wrap(err, errors.NotFoundf("%q", syncContext.ChosenVersion))
	}
	_, chosenList := result.Newest()
	logger.Tracef("syncContext.ChosenVersion %s, chosenList %s", syncContext.ChosenVersion, chosenList)
	if syncContext.TargetToolsFinder != nil {
		targetTools, err := syncContext.TargetToolsFinder.FindTools(
			syncContext.ChosenVersion.Major, syncContext.Stream,
		)
		switch err {
		case nil, coretools.ErrNoMatches, envtools.ErrNoTools:
		default:
			return errors.Trace(err)
		}
		for _, tool := range targetTools {
			logger.Debugf("found target agent binary: %v", tool)
		}
		if targetTools.Exclude(chosenList).Len() != targetTools.Len() {
			// already in target.
			return nil
		}
	}

	if syncContext.DryRun {
		for _, tools := range chosenList {
			logger.Infof("copying %s from %s", tools.Version, tools.URL)
		}
		return nil
	}

	err = copyTools(toolsDir, syncContext.Stream, chosenList, syncContext.TargetToolsUploader)
	if err != nil {
		return err
	}
	logger.Infof("copied %d agent binaries", len(chosenList))
	return nil
}

// selectSourceDatasource returns a storage reader based on the source setting.
func selectSourceDatasource(syncContext *SyncContext) (simplestreams.DataSource, error) {
	source := syncContext.Source
	if source == "" {
		source = envtools.DefaultBaseURL
	}
	sourceURL, err := envtools.ToolsURL(source)
	if err != nil {
		return nil, err
	}
	logger.Infof("source for sync of agent binaries: %v", sourceURL)
	config := simplestreams.Config{
		Description:          "sync agent binaries source",
		BaseURL:              sourceURL,
		PublicSigningKey:     keys.JujuPublicKey,
		HostnameVerification: true,
		Priority:             simplestreams.CUSTOM_CLOUD_DATA,
	}
	if err := config.Validate(); err != nil {
		return nil, errors.Annotate(err, "simplestreams config validation failed")
	}
	return simplestreams.NewDataSource(config), nil
}

// copyTools copies a set of tools from the source to the target.
func copyTools(toolsDir, stream string, tools []*coretools.Tools, u ToolsUploader) error {
	for _, tool := range tools {
		logger.Infof("copying %s from %s", tool.Version, tool.URL)
		if err := copyOneToolsPackage(toolsDir, stream, tool, u); err != nil {
			return err
		}
	}
	return nil
}

// copyOneToolsPackage copies one tool from the source to the target.
func copyOneToolsPackage(toolsDir, stream string, tools *coretools.Tools, u ToolsUploader) error {
	toolsName := envtools.StorageName(tools.Version, toolsDir)
	logger.Infof("downloading %q %v (%v)", stream, toolsName, tools.URL)
	client := http.NewClient()
	resp, err := client.Get(context.TODO(), tools.URL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// Verify SHA-256 hash.
	var buf bytes.Buffer
	sha256, size, err := utils.ReadSHA256(io.TeeReader(resp.Body, &buf))
	if err != nil {
		return err
	}
	if tools.SHA256 == "" {
		logger.Errorf("no SHA-256 hash for %v", tools.SHA256) // TODO(dfc) can you spot the bug ?
	} else if sha256 != tools.SHA256 {
		return errors.Errorf("SHA-256 hash mismatch (%v/%v)", sha256, tools.SHA256)
	}
	sizeInKB := (size + 512) / 1024
	logger.Infof("uploading %v (%dkB) to model", toolsName, sizeInKB)
	return u.UploadTools(toolsDir, stream, tools, buf.Bytes())
}

// BuiltAgent contains metadata for a tools tarball resulting from
// a call to BundleTools.
type BuiltAgent struct {
	Version     version.Binary
	Dir         string
	StorageName string
	Sha256Hash  string
	Size        int64
}

// BuildAgentTarballFunc is a function which can build an agent tarball.
type BuildAgentTarballFunc func(devSrcDir string, stream string, arch arch.Arch) (*BuiltAgent, error)

// BuildAgentTarball bundles an agent tarball and places it in a temp directory in
// the expected agent path.
var BuildAgentTarball BuildAgentTarballFunc = buildAgentTarball

// buildAgentTarball bundles an agent tarball and places it in a temp directory in
// the expected agent path.
func buildAgentTarball(devSrcDir string, stream string, arch arch.Arch) (_ *BuiltAgent, err error) {
	logger.Debugf("Making agent binary tarball")
	// We create the entire archive before asking the environment to
	// start uploading so that we can be sure we have archived
	// correctly.
	f, err := os.CreateTemp("", "juju-tgz")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()

	toolsVersion, sha256Hash, err := envtools.BundleTools(devSrcDir, arch, f)
	if err != nil {
		return nil, err
	}
	// Built agent version needs to match the client used to bootstrap.
	builtVersion := toolsVersion
	clientVersion := jujuversion.Current
	if builtVersion.Number.Compare(clientVersion) != 0 {
		return nil, errors.Errorf(
			"agent binary %v not compatible with bootstrap client %v",
			toolsVersion.Number, jujuversion.Current,
		)
	}
	fileInfo, err := f.Stat()
	if err != nil {
		return nil, errors.Errorf("cannot stat newly made agent binary archive: %v", err)
	}
	size := fileInfo.Size()
	agentBinary := "agent binary"
	logger.Infof("using %s %v (%dkB)", agentBinary, toolsVersion, (size+512)/1024)

	baseToolsDir, err := os.MkdirTemp("", "juju-tools")
	if err != nil {
		return nil, err
	}

	// If we exit with an error, clean up the built tools directory.
	defer func() {
		if err != nil {
			os.RemoveAll(baseToolsDir)
		}
	}()

	err = os.MkdirAll(filepath.Join(baseToolsDir, storage.BaseToolsPath, stream), 0755)
	if err != nil {
		return nil, err
	}
	storageName := envtools.StorageName(toolsVersion, stream)
	err = utils.CopyFile(filepath.Join(baseToolsDir, storageName), f.Name())
	if err != nil {
		return nil, err
	}
	return &BuiltAgent{
		Version:     toolsVersion,
		Dir:         baseToolsDir,
		StorageName: storageName,
		Size:        size,
		Sha256Hash:  sha256Hash,
	}, nil
}

// StorageToolsFinder is an implementation of ToolsFinder
// that searches for tools in the specified storage.
type StorageToolsFinder struct {
	Storage storage.StorageReader
}

func (f StorageToolsFinder) FindTools(major int, stream string) (coretools.List, error) {
	return envtools.ReadList(f.Storage, stream, major, -1)
}

// StorageToolsUploader is an implementation of ToolsUploader that
// writes tools to the provided storage and then writes merged
// metadata, optionally with mirrors.
type StorageToolsUploader struct {
	Fetcher       envtools.SimplestreamsFetcher
	Storage       storage.Storage
	WriteMetadata bool
	WriteMirrors  envtools.ShouldWriteMirrors
}

func (u StorageToolsUploader) UploadTools(toolsDir, stream string, tools *coretools.Tools, data []byte) error {
	toolsName := envtools.StorageName(tools.Version, toolsDir)
	if err := u.Storage.Put(toolsName, bytes.NewReader(data), int64(len(data))); err != nil {
		return err
	}
	if !u.WriteMetadata {
		return nil
	}
	err := envtools.MergeAndWriteMetadata(u.Fetcher, u.Storage, toolsDir, stream, coretools.List{tools}, u.WriteMirrors)
	if err != nil {
		logger.Errorf("error writing agent metadata: %v", err)
		return err
	}
	return nil
}
