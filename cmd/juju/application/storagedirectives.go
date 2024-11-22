// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package application

import (
	"fmt"
	"io"

	"github.com/juju/cmd/v3"
	"github.com/juju/errors"
	"github.com/juju/gnuflag"
	"github.com/juju/names/v5"

	"github.com/juju/juju/api/client/application"
	jujucmd "github.com/juju/juju/cmd"
	"github.com/juju/juju/cmd/juju/block"
	"github.com/juju/juju/cmd/modelcmd"
	"github.com/juju/juju/storage"
)

var usageGetStorageDirectivesSummary = `
Displays machine storage-directives for an application.`[1:]

var usageGetStorageDirectivesDetails = `
Shows machine storage-directives that have been set for an application with ` + "`juju set-\nstorage-directives`" + `.
By default, the model is the current model.
Application storage-directives are combined with model storage-directives, set with ` +
	"`juju \nset-model-storage-directives`" + `, for commands (such as 'deploy') that provision
machines for applications. Where model and application storage-directives overlap, the
application storage-directives take precedence.
StorageDirectives for a specific model can be viewed with ` + "`juju model-\nstorage-directives`" + `.`

const usageGetStorageDirectivesExamples = `
    juju storage-directives mysql
    juju storage-directives -m mymodel apache2
`

var usageSetStorageDirectivesSummary = `
Sets machine storage-directives for an application.`[1:]

// setStorageDirectivesDoc is multi-line since we need to use ` to denote
// commands for ease in markdown.
var usageSetStorageDirectivesDetails = `
Sets storage-directives for an application, which are used for all new machines 
provisioned for that application.

	juju set-storage-directives <storage-directive>...

<storage-directive> describes to the charm how to refer to the storage, 
and where to provision it from. <storage-directive> takes the following form:
	
    <storage-name>[=<storage-constraint>]

<storage-name> is defined in the charm's metadata.yaml file.   

<storage-constraint> is a description of how Juju should provision storage 
instances for the unit. They are made up of up to three parts: <storage-pool>,
<count>, and <size>. They can be provided in any order, but we recommend the
following:

    <storage-pool>,<count>,<size>

Each parameter is optional, so long as at least one is present. So the following
storage constraints are also valid:

   <storage-pool>,<size>
   <count>,<size>
   <size>

<storage-pool> is the storage pool to provision storage instances from. Must 
be a name from 'juju storage-pools'.  The default pool is available via 
executing 'juju model-config storage-default-block-source'.

<count> is the number of storage instances to provision from <storage-pool> of
<size>. Must be a positive integer. The default count is "1". May be restricted
by the charm, which can specify a maximum number of storage instances per unit.

<size> is the number of bytes to provision per storage instance. Must be a 
positive number, followed by a size suffix.  Valid suffixes include M, G, T,
and P.  Defaults to "1024M", or the which can specify a minimum size required 
by the charm.
`

const usageSetStorageDirectivesExamples = `
    juju set-storage-directives mysql mem=8G cores=4
    juju set-storage-directives -m mymodel apache2 mem=8G arch=amd64
`

// NewApplicationGetStorageDirectivesCommand returns a command which gets application storage-directives.
func NewApplicationGetStorageDirectivesCommand() modelcmd.ModelCommand {
	return modelcmd.Wrap(&applicationGetStorageDirectivesCommand{})
}

type applicationStorageDirectivesAPI interface {
	Close() error
	GetStorageDirectives(...string) ([]storage.Constraints, error)
	SetStorageDirectives(string, storage.Constraints) error
}

type applicationStorageDirectivesCommand struct {
	modelcmd.ModelCommandBase
	ApplicationName string
	out             cmd.Output
	api             applicationStorageDirectivesAPI
}

func (c *applicationStorageDirectivesCommand) getAPI() (applicationStorageDirectivesAPI, error) {
	if c.api != nil {
		return c.api, nil
	}
	root, err := c.NewAPIRoot()
	if err != nil {
		return nil, errors.Trace(err)
	}
	return application.NewClient(root), nil
}

type applicationGetStorageDirectivesCommand struct {
	applicationStorageDirectivesCommand
}

func (c *applicationGetStorageDirectivesCommand) Info() *cmd.Info {
	return jujucmd.Info(&cmd.Info{
		Name:     "storage-directives",
		Args:     "<application>",
		Purpose:  usageGetStorageDirectivesSummary,
		Doc:      usageGetStorageDirectivesDetails,
		Examples: usageGetStorageDirectivesExamples,
		SeeAlso: []string{
			"set-storage-directives",
			"model-storage-directives",
			"set-model-storage-directives",
		},
	})
}

func formatStorageDirectives(writer io.Writer, value interface{}) error {
	fmt.Fprintln(writer, value.(storage).String())
	return nil
}

func (c *applicationGetStorageDirectivesCommand) SetFlags(f *gnuflag.FlagSet) {
	c.ModelCommandBase.SetFlags(f)
	c.out.AddFlags(f, "storage-directives", map[string]cmd.Formatter{
		"storage-directives": formatStorageDirectives,
		"yaml":               cmd.FormatYaml,
		"json":               cmd.FormatJson,
	})
}

func (c *applicationGetStorageDirectivesCommand) Init(args []string) error {
	if len(args) == 0 {
		return errors.Errorf("no application name specified")
	}
	if !names.IsValidApplication(args[0]) {
		return errors.Errorf("invalid application name %q", args[0])
	}

	c.ApplicationName, args = args[0], args[1:]
	return cmd.CheckEmpty(args)
}

func (c *applicationGetStorageDirectivesCommand) Run(ctx *cmd.Context) error {
	apiclient, err := c.getAPI()
	if err != nil {
		return err
	}
	defer apiclient.Close()

	cons, err := apiclient.GetStorageDirectives(c.ApplicationName)
	if err != nil {
		return err
	}
	return c.out.Write(ctx, cons[0])
}

type applicationSetStorageDirectivesCommand struct {
	applicationStorageDirectivesCommand
	StorageDirectives storage.Constraints
}

// NewApplicationSetStorageDirectivesCommand returns a command which sets application storage-directives.
func NewApplicationSetStorageDirectivesCommand() modelcmd.ModelCommand {
	return modelcmd.Wrap(&applicationSetStorageDirectivesCommand{})
}

func (c *applicationSetStorageDirectivesCommand) Info() *cmd.Info {
	return jujucmd.Info(&cmd.Info{
		Name:     "set-storage-directives",
		Args:     "<application> <storage>=<value> ...",
		Purpose:  usageSetStorageDirectivesSummary,
		Doc:      usageSetStorageDirectivesDetails,
		Examples: usageSetStorageDirectivesExamples,
		SeeAlso: []string{
			"storage-directives",
			"model-storage-directives",
			"set-model-storage-directives",
		},
	})
}

func (c *applicationSetStorageDirectivesCommand) Init(args []string) (err error) {
	if len(args) == 0 {
		return errors.Errorf("no application name specified")
	}
	if !names.IsValidApplication(args[0]) {
		return errors.Errorf("invalid application name %q", args[0])
	}

	c.ApplicationName, args = args[0], args[1:]

	c.StorageDirectives, err = storage.ParseConstraints(args...)
	return err
}

func (c *applicationSetStorageDirectivesCommand) Run(_ *cmd.Context) (err error) {
	apiclient, err := c.getAPI()
	if err != nil {
		return err
	}
	defer apiclient.Close()

	err = apiclient.SetStorageDirectives(c.ApplicationName, c.StorageDirectives)
	return block.ProcessBlockedError(err, block.BlockChange)
}
