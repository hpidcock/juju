(manage-universal-charms)=
# Manage universal charms

Universal charms are Kubernetes-style charms with a `containers:` section that
can also run on IAAS models. On IAAS, Juju runs each workload container with
`nerdctl` and exposes the container's Pebble socket to the unit agent.

See also: {ref}`Manage charms or bundles <manage-charms>`, {ref}`Manage charm resources <manage-charm-resources>`, {ref}`Manage storage <manage-storage>`.

```{note}
Universal charms keep the IAAS hook execution model. Hooks run on the unit
agent host, and charms communicate with workload containers through Pebble over
the socket created under the unit data directory.
```

## Deploy a universal charm to an IAAS model

To deploy a universal charm to an IAAS model, use the same deploy command as for
other charms:

```text
juju deploy my-universal-charm
```

Juju detects the charm's `containers:` metadata, starts the workload containers
on the unit machine, and then runs the charm's Pebble hooks when the sockets are
ready.

See more: {ref}`juju deploy <command-juju-deploy>`

## Require container support in a charm

To require an IAAS model that supports workload containers, add the `containerd`
feature to the charm's `assumes` expression:

```text
assumes:
  - containerd
```

For IAAS models, Juju advertises this feature at deploy time. On the target
machine, the unit worker installs and uses `nerdctl` to run OCI workload
containers. If `nerdctl` cannot be installed or started, the unit reports a clear
runtime error.

## View universal charm status

To view a universal charm's unit status, use `juju status`:

```text
juju status my-universal-charm
```

On IAAS, Juju monitors the underlying containers and restarts containers that
exist but are not running. Container failures are surfaced through unit logs and
worker status reporting.

See more: {ref}`juju status <command-juju-status>`

## Inspect a universal charm's workload

To inspect Pebble services for a unit, run Pebble from the unit context:

```text
juju exec --unit my-universal-charm/0 -- pebble services
```

On IAAS, the Pebble client connects to the workload socket that Juju bind-mounts
from the unit's data directory into the container. On Kubernetes, the same
operation uses the existing sidecar container path.

See more: {ref}`juju exec <command-juju-exec>`

## Use storage with universal charms

To attach filesystem storage to a universal charm, use regular Juju storage
syntax:

```text
juju deploy my-universal-charm --storage data=10G
```

If the charm maps the storage into a workload container, Juju resolves the
attached host path and bind-mounts it into the container at the location declared
in charm metadata. Initial support is for filesystem-style mounts.

See more: {ref}`juju deploy <command-juju-deploy>`

## View universal charm logs

To view unit and workload logs, use `juju debug-log`:

```text
juju debug-log --include unit-my-universal-charm-0
```

On IAAS, Juju tails container logs and forwards them to the Juju logging
pipeline so workload output can be inspected alongside unit-agent logs.

See more: {ref}`juju debug-log <command-juju-debug-log>`

## Troubleshoot a universal charm

To troubleshoot a universal charm on IAAS, inspect these layers in order:

1. Use `juju status` to check whether the unit is blocked, waiting, or active.
2. Use `juju debug-log` to inspect unit-agent and workload-container logs.
3. Use `juju exec --unit <unit> -- pebble services` to check Pebble connectivity.
4. If container startup fails, inspect the unit machine for `nerdctl` and
   container state.

```{warning}
Avoid modifying Juju-managed containers directly with `nerdctl` except during
manual troubleshooting. Juju reconciles container state and may restart or
replace containers when the unit worker restarts.
```
