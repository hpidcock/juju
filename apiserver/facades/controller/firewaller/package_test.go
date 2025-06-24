// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package firewaller_test

import (
	"os"
	stdtesting "testing"

	"github.com/juju/juju/internal/testing"
)

//go:generate go tool mockgen -typed -package firewaller_test -destination package_mock_test.go github.com/juju/juju/apiserver/facades/controller/firewaller State,ControllerConfigAPI
//go:generate go tool mockgen -typed -package firewaller_test -destination service_mock_test.go github.com/juju/juju/apiserver/facades/controller/firewaller ControllerConfigService,ModelConfigService,NetworkService,ApplicationService,MachineService,ModelInfoService

func TestMain(m *stdtesting.M) {
	os.Exit(func() int {
		defer testing.MgoTestMain()()
		return m.Run()
	}())
}
