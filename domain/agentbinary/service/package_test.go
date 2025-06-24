// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package service

//go:generate go tool mockgen -typed -package service -destination store_mock_test.go github.com/juju/juju/domain/agentbinary/service State,AgentBinaryState,ProviderForAgentBinaryFinder
//go:generate go tool mockgen -typed -package service -destination objectstore_mock_test.go github.com/juju/juju/core/objectstore ModelObjectStoreGetter,ObjectStore
