// Copyright 2012-2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package openstack_test

import (
	"flag"
	"os"
	"testing"

	gc "gopkg.in/check.v1"
	"gopkg.in/goose.v2/identity"
)

var live *bool

func TestMain(m *testing.M) {
	live = flag.Bool("live", false, "Include live OpenStack tests")
	flag.Parse()
	os.Exit(m.Run())
}

func Test(t *testing.T) {
	if *live {
		cred, err := identity.CompleteCredentialsFromEnv()
		if err != nil {
			t.Fatalf("Error setting up test suite: %s", err.Error())
		}
		registerLiveTests(cred)
	}
	registerLocalTests()
	gc.TestingT(t)
}
