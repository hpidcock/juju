// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/internal/docker/registry/internal (interfaces: Registry)
//
// Generated by this command:
//
//	mockgen -typed -package mocks -destination mocks/registry_mock.go github.com/juju/juju/internal/docker/registry/internal Registry
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"
	time "time"

	docker "github.com/juju/juju/internal/docker"
	tools "github.com/juju/juju/internal/tools"
	gomock "go.uber.org/mock/gomock"
)

// MockRegistry is a mock of Registry interface.
type MockRegistry struct {
	ctrl     *gomock.Controller
	recorder *MockRegistryMockRecorder
}

// MockRegistryMockRecorder is the mock recorder for MockRegistry.
type MockRegistryMockRecorder struct {
	mock *MockRegistry
}

// NewMockRegistry creates a new mock instance.
func NewMockRegistry(ctrl *gomock.Controller) *MockRegistry {
	mock := &MockRegistry{ctrl: ctrl}
	mock.recorder = &MockRegistryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRegistry) EXPECT() *MockRegistryMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockRegistry) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockRegistryMockRecorder) Close() *MockRegistryCloseCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRegistry)(nil).Close))
	return &MockRegistryCloseCall{Call: call}
}

// MockRegistryCloseCall wrap *gomock.Call
type MockRegistryCloseCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRegistryCloseCall) Return(arg0 error) *MockRegistryCloseCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRegistryCloseCall) Do(f func() error) *MockRegistryCloseCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRegistryCloseCall) DoAndReturn(f func() error) *MockRegistryCloseCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetArchitectures mocks base method.
func (m *MockRegistry) GetArchitectures(arg0, arg1 string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetArchitectures", arg0, arg1)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetArchitectures indicates an expected call of GetArchitectures.
func (mr *MockRegistryMockRecorder) GetArchitectures(arg0, arg1 any) *MockRegistryGetArchitecturesCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetArchitectures", reflect.TypeOf((*MockRegistry)(nil).GetArchitectures), arg0, arg1)
	return &MockRegistryGetArchitecturesCall{Call: call}
}

// MockRegistryGetArchitecturesCall wrap *gomock.Call
type MockRegistryGetArchitecturesCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRegistryGetArchitecturesCall) Return(arg0 []string, arg1 error) *MockRegistryGetArchitecturesCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRegistryGetArchitecturesCall) Do(f func(string, string) ([]string, error)) *MockRegistryGetArchitecturesCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRegistryGetArchitecturesCall) DoAndReturn(f func(string, string) ([]string, error)) *MockRegistryGetArchitecturesCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ImageRepoDetails mocks base method.
func (m *MockRegistry) ImageRepoDetails() docker.ImageRepoDetails {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageRepoDetails")
	ret0, _ := ret[0].(docker.ImageRepoDetails)
	return ret0
}

// ImageRepoDetails indicates an expected call of ImageRepoDetails.
func (mr *MockRegistryMockRecorder) ImageRepoDetails() *MockRegistryImageRepoDetailsCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageRepoDetails", reflect.TypeOf((*MockRegistry)(nil).ImageRepoDetails))
	return &MockRegistryImageRepoDetailsCall{Call: call}
}

// MockRegistryImageRepoDetailsCall wrap *gomock.Call
type MockRegistryImageRepoDetailsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRegistryImageRepoDetailsCall) Return(arg0 docker.ImageRepoDetails) *MockRegistryImageRepoDetailsCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRegistryImageRepoDetailsCall) Do(f func() docker.ImageRepoDetails) *MockRegistryImageRepoDetailsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRegistryImageRepoDetailsCall) DoAndReturn(f func() docker.ImageRepoDetails) *MockRegistryImageRepoDetailsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Ping mocks base method.
func (m *MockRegistry) Ping() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Ping")
	ret0, _ := ret[0].(error)
	return ret0
}

// Ping indicates an expected call of Ping.
func (mr *MockRegistryMockRecorder) Ping() *MockRegistryPingCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Ping", reflect.TypeOf((*MockRegistry)(nil).Ping))
	return &MockRegistryPingCall{Call: call}
}

// MockRegistryPingCall wrap *gomock.Call
type MockRegistryPingCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRegistryPingCall) Return(arg0 error) *MockRegistryPingCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRegistryPingCall) Do(f func() error) *MockRegistryPingCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRegistryPingCall) DoAndReturn(f func() error) *MockRegistryPingCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// RefreshAuth mocks base method.
func (m *MockRegistry) RefreshAuth() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RefreshAuth")
	ret0, _ := ret[0].(error)
	return ret0
}

// RefreshAuth indicates an expected call of RefreshAuth.
func (mr *MockRegistryMockRecorder) RefreshAuth() *MockRegistryRefreshAuthCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RefreshAuth", reflect.TypeOf((*MockRegistry)(nil).RefreshAuth))
	return &MockRegistryRefreshAuthCall{Call: call}
}

// MockRegistryRefreshAuthCall wrap *gomock.Call
type MockRegistryRefreshAuthCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRegistryRefreshAuthCall) Return(arg0 error) *MockRegistryRefreshAuthCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRegistryRefreshAuthCall) Do(f func() error) *MockRegistryRefreshAuthCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRegistryRefreshAuthCall) DoAndReturn(f func() error) *MockRegistryRefreshAuthCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ShouldRefreshAuth mocks base method.
func (m *MockRegistry) ShouldRefreshAuth() (bool, time.Duration) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ShouldRefreshAuth")
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(time.Duration)
	return ret0, ret1
}

// ShouldRefreshAuth indicates an expected call of ShouldRefreshAuth.
func (mr *MockRegistryMockRecorder) ShouldRefreshAuth() *MockRegistryShouldRefreshAuthCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ShouldRefreshAuth", reflect.TypeOf((*MockRegistry)(nil).ShouldRefreshAuth))
	return &MockRegistryShouldRefreshAuthCall{Call: call}
}

// MockRegistryShouldRefreshAuthCall wrap *gomock.Call
type MockRegistryShouldRefreshAuthCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRegistryShouldRefreshAuthCall) Return(arg0 bool, arg1 time.Duration) *MockRegistryShouldRefreshAuthCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRegistryShouldRefreshAuthCall) Do(f func() (bool, time.Duration)) *MockRegistryShouldRefreshAuthCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRegistryShouldRefreshAuthCall) DoAndReturn(f func() (bool, time.Duration)) *MockRegistryShouldRefreshAuthCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// String mocks base method.
func (m *MockRegistry) String() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "String")
	ret0, _ := ret[0].(string)
	return ret0
}

// String indicates an expected call of String.
func (mr *MockRegistryMockRecorder) String() *MockRegistryStringCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "String", reflect.TypeOf((*MockRegistry)(nil).String))
	return &MockRegistryStringCall{Call: call}
}

// MockRegistryStringCall wrap *gomock.Call
type MockRegistryStringCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRegistryStringCall) Return(arg0 string) *MockRegistryStringCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRegistryStringCall) Do(f func() string) *MockRegistryStringCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRegistryStringCall) DoAndReturn(f func() string) *MockRegistryStringCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Tags mocks base method.
func (m *MockRegistry) Tags(arg0 string) (tools.Versions, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Tags", arg0)
	ret0, _ := ret[0].(tools.Versions)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Tags indicates an expected call of Tags.
func (mr *MockRegistryMockRecorder) Tags(arg0 any) *MockRegistryTagsCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Tags", reflect.TypeOf((*MockRegistry)(nil).Tags), arg0)
	return &MockRegistryTagsCall{Call: call}
}

// MockRegistryTagsCall wrap *gomock.Call
type MockRegistryTagsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRegistryTagsCall) Return(arg0 tools.Versions, arg1 error) *MockRegistryTagsCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRegistryTagsCall) Do(f func(string) (tools.Versions, error)) *MockRegistryTagsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRegistryTagsCall) DoAndReturn(f func(string) (tools.Versions, error)) *MockRegistryTagsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
