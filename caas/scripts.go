// Copyright 2019 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package caas

var (
	// JujudStartUpSh is the exec script for CAAS controller.
	JujudStartUpSh = `
export JUJU_DATA_DIR=%[1]s
export JUJU_TOOLS_DIR=$JUJU_DATA_DIR/%[2]s

mkdir -p $JUJU_TOOLS_DIR
cp /opt/jujud $JUJU_TOOLS_DIR/jujud
%[3]s
`[1:]

	InitSh = `
set -eux
mkdir -p /shared/bin
mkdir -p /shared/etc
mkdir -p /shared/etc/ssl/certs
cp $(which busybox) /shared/bin
cp /opt/jujud /shared/bin
cp /etc/os-release /shared/etc/os-release
cp /etc/ssl/certs/ca-certificates.crt /shared/etc/ssl/certs/ca-certificates.crt
/shared/bin/busybox --list-full | while read line; do
	if [ "/shared/bin/busybox" != "/shared/$line" ]; then
		mkdir -p $(dirname "/shared/$line")
		ln -s "/shared/bin/busybox" "/shared/$line"
	fi
done
`[1:]

	HackStartUpSh = `
set -eux
UNIT_INDEX=$(hostname | grep -o -E '[0-9]+$')
export JUJU_DATA_DIR=%[1]s
export JUJU_TOOLS_DIR=$JUJU_DATA_DIR/%[2]s/unit-%[3]s-$UNIT_INDEX

mkdir -p /etc
cp -r /shared/etc/* /etc/
mkdir -p /tmp
mkdir -p /var/log/juju
mkdir -p /bin
ln -s /shared/bin/busybox /bin/sh

mkdir -p $JUJU_TOOLS_DIR
cd $JUJU_DATA_DIR
cp /shared/bin/jujud $JUJU_TOOLS_DIR/jujud
$JUJU_TOOLS_DIR/jujud unit --unit-name="%[3]s/$UNIT_INDEX" --use-application --debug
`[1:]
)
