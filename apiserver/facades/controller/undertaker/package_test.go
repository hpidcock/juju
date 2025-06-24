// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package undertaker

//go:generate go tool mockgen -typed -package undertaker -destination mock_service.go github.com/juju/juju/apiserver/facades/controller/undertaker SecretBackendService,ModelConfigService,ModelInfoService,ModelProviderService
