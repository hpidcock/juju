// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/domain/keyupdater/service (interfaces: ControllerKeyProvider,State,WatchableState)
//
// Generated by this command:
//
//	mockgen -typed -package service -destination service_mock_test.go github.com/juju/juju/domain/keyupdater/service ControllerKeyProvider,State,WatchableState
//

// Package service is a generated GoMock package.
package service

import (
	context "context"
	reflect "reflect"

	machine "github.com/juju/juju/core/machine"
	gomock "go.uber.org/mock/gomock"
)

// MockControllerKeyProvider is a mock of ControllerKeyProvider interface.
type MockControllerKeyProvider struct {
	ctrl     *gomock.Controller
	recorder *MockControllerKeyProviderMockRecorder
}

// MockControllerKeyProviderMockRecorder is the mock recorder for MockControllerKeyProvider.
type MockControllerKeyProviderMockRecorder struct {
	mock *MockControllerKeyProvider
}

// NewMockControllerKeyProvider creates a new mock instance.
func NewMockControllerKeyProvider(ctrl *gomock.Controller) *MockControllerKeyProvider {
	mock := &MockControllerKeyProvider{ctrl: ctrl}
	mock.recorder = &MockControllerKeyProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockControllerKeyProvider) EXPECT() *MockControllerKeyProviderMockRecorder {
	return m.recorder
}

// ControllerKeys mocks base method.
func (m *MockControllerKeyProvider) ControllerKeys(arg0 context.Context) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ControllerKeys", arg0)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ControllerKeys indicates an expected call of ControllerKeys.
func (mr *MockControllerKeyProviderMockRecorder) ControllerKeys(arg0 any) *MockControllerKeyProviderControllerKeysCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ControllerKeys", reflect.TypeOf((*MockControllerKeyProvider)(nil).ControllerKeys), arg0)
	return &MockControllerKeyProviderControllerKeysCall{Call: call}
}

// MockControllerKeyProviderControllerKeysCall wrap *gomock.Call
type MockControllerKeyProviderControllerKeysCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockControllerKeyProviderControllerKeysCall) Return(arg0 []string, arg1 error) *MockControllerKeyProviderControllerKeysCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockControllerKeyProviderControllerKeysCall) Do(f func(context.Context) ([]string, error)) *MockControllerKeyProviderControllerKeysCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockControllerKeyProviderControllerKeysCall) DoAndReturn(f func(context.Context) ([]string, error)) *MockControllerKeyProviderControllerKeysCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// MockState is a mock of State interface.
type MockState struct {
	ctrl     *gomock.Controller
	recorder *MockStateMockRecorder
}

// MockStateMockRecorder is the mock recorder for MockState.
type MockStateMockRecorder struct {
	mock *MockState
}

// NewMockState creates a new mock instance.
func NewMockState(ctrl *gomock.Controller) *MockState {
	mock := &MockState{ctrl: ctrl}
	mock.recorder = &MockStateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockState) EXPECT() *MockStateMockRecorder {
	return m.recorder
}

// AuthorisedKeysForMachine mocks base method.
func (m *MockState) AuthorisedKeysForMachine(arg0 context.Context, arg1 machine.ID) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorisedKeysForMachine", arg0, arg1)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthorisedKeysForMachine indicates an expected call of AuthorisedKeysForMachine.
func (mr *MockStateMockRecorder) AuthorisedKeysForMachine(arg0, arg1 any) *MockStateAuthorisedKeysForMachineCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorisedKeysForMachine", reflect.TypeOf((*MockState)(nil).AuthorisedKeysForMachine), arg0, arg1)
	return &MockStateAuthorisedKeysForMachineCall{Call: call}
}

// MockStateAuthorisedKeysForMachineCall wrap *gomock.Call
type MockStateAuthorisedKeysForMachineCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockStateAuthorisedKeysForMachineCall) Return(arg0 []string, arg1 error) *MockStateAuthorisedKeysForMachineCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockStateAuthorisedKeysForMachineCall) Do(f func(context.Context, machine.ID) ([]string, error)) *MockStateAuthorisedKeysForMachineCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockStateAuthorisedKeysForMachineCall) DoAndReturn(f func(context.Context, machine.ID) ([]string, error)) *MockStateAuthorisedKeysForMachineCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// MockWatchableState is a mock of WatchableState interface.
type MockWatchableState struct {
	ctrl     *gomock.Controller
	recorder *MockWatchableStateMockRecorder
}

// MockWatchableStateMockRecorder is the mock recorder for MockWatchableState.
type MockWatchableStateMockRecorder struct {
	mock *MockWatchableState
}

// NewMockWatchableState creates a new mock instance.
func NewMockWatchableState(ctrl *gomock.Controller) *MockWatchableState {
	mock := &MockWatchableState{ctrl: ctrl}
	mock.recorder = &MockWatchableStateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWatchableState) EXPECT() *MockWatchableStateMockRecorder {
	return m.recorder
}

// AllPublicKeysQuery mocks base method.
func (m *MockWatchableState) AllPublicKeysQuery() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AllPublicKeysQuery")
	ret0, _ := ret[0].(string)
	return ret0
}

// AllPublicKeysQuery indicates an expected call of AllPublicKeysQuery.
func (mr *MockWatchableStateMockRecorder) AllPublicKeysQuery() *MockWatchableStateAllPublicKeysQueryCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AllPublicKeysQuery", reflect.TypeOf((*MockWatchableState)(nil).AllPublicKeysQuery))
	return &MockWatchableStateAllPublicKeysQueryCall{Call: call}
}

// MockWatchableStateAllPublicKeysQueryCall wrap *gomock.Call
type MockWatchableStateAllPublicKeysQueryCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockWatchableStateAllPublicKeysQueryCall) Return(arg0 string) *MockWatchableStateAllPublicKeysQueryCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockWatchableStateAllPublicKeysQueryCall) Do(f func() string) *MockWatchableStateAllPublicKeysQueryCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockWatchableStateAllPublicKeysQueryCall) DoAndReturn(f func() string) *MockWatchableStateAllPublicKeysQueryCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AuthorisedKeysForMachine mocks base method.
func (m *MockWatchableState) AuthorisedKeysForMachine(arg0 context.Context, arg1 machine.ID) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorisedKeysForMachine", arg0, arg1)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthorisedKeysForMachine indicates an expected call of AuthorisedKeysForMachine.
func (mr *MockWatchableStateMockRecorder) AuthorisedKeysForMachine(arg0, arg1 any) *MockWatchableStateAuthorisedKeysForMachineCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorisedKeysForMachine", reflect.TypeOf((*MockWatchableState)(nil).AuthorisedKeysForMachine), arg0, arg1)
	return &MockWatchableStateAuthorisedKeysForMachineCall{Call: call}
}

// MockWatchableStateAuthorisedKeysForMachineCall wrap *gomock.Call
type MockWatchableStateAuthorisedKeysForMachineCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockWatchableStateAuthorisedKeysForMachineCall) Return(arg0 []string, arg1 error) *MockWatchableStateAuthorisedKeysForMachineCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockWatchableStateAuthorisedKeysForMachineCall) Do(f func(context.Context, machine.ID) ([]string, error)) *MockWatchableStateAuthorisedKeysForMachineCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockWatchableStateAuthorisedKeysForMachineCall) DoAndReturn(f func(context.Context, machine.ID) ([]string, error)) *MockWatchableStateAuthorisedKeysForMachineCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
