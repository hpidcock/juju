// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/environs (interfaces: BootstrapEnviron)
//
// Generated by this command:
//
//	mockgen -typed -package mocks -destination mocks/environs.go github.com/juju/juju/environs BootstrapEnviron
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	constraints "github.com/juju/juju/core/constraints"
	environs "github.com/juju/juju/environs"
	config "github.com/juju/juju/environs/config"
	envcontext "github.com/juju/juju/environs/envcontext"
	storage "github.com/juju/juju/internal/storage"
	gomock "go.uber.org/mock/gomock"
)

// MockBootstrapEnviron is a mock of BootstrapEnviron interface.
type MockBootstrapEnviron struct {
	ctrl     *gomock.Controller
	recorder *MockBootstrapEnvironMockRecorder
}

// MockBootstrapEnvironMockRecorder is the mock recorder for MockBootstrapEnviron.
type MockBootstrapEnvironMockRecorder struct {
	mock *MockBootstrapEnviron
}

// NewMockBootstrapEnviron creates a new mock instance.
func NewMockBootstrapEnviron(ctrl *gomock.Controller) *MockBootstrapEnviron {
	mock := &MockBootstrapEnviron{ctrl: ctrl}
	mock.recorder = &MockBootstrapEnvironMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBootstrapEnviron) EXPECT() *MockBootstrapEnvironMockRecorder {
	return m.recorder
}

// Bootstrap mocks base method.
func (m *MockBootstrapEnviron) Bootstrap(arg0 environs.BootstrapContext, arg1 envcontext.ProviderCallContext, arg2 environs.BootstrapParams) (*environs.BootstrapResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Bootstrap", arg0, arg1, arg2)
	ret0, _ := ret[0].(*environs.BootstrapResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Bootstrap indicates an expected call of Bootstrap.
func (mr *MockBootstrapEnvironMockRecorder) Bootstrap(arg0, arg1, arg2 any) *MockBootstrapEnvironBootstrapCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Bootstrap", reflect.TypeOf((*MockBootstrapEnviron)(nil).Bootstrap), arg0, arg1, arg2)
	return &MockBootstrapEnvironBootstrapCall{Call: call}
}

// MockBootstrapEnvironBootstrapCall wrap *gomock.Call
type MockBootstrapEnvironBootstrapCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironBootstrapCall) Return(arg0 *environs.BootstrapResult, arg1 error) *MockBootstrapEnvironBootstrapCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironBootstrapCall) Do(f func(environs.BootstrapContext, envcontext.ProviderCallContext, environs.BootstrapParams) (*environs.BootstrapResult, error)) *MockBootstrapEnvironBootstrapCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironBootstrapCall) DoAndReturn(f func(environs.BootstrapContext, envcontext.ProviderCallContext, environs.BootstrapParams) (*environs.BootstrapResult, error)) *MockBootstrapEnvironBootstrapCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Config mocks base method.
func (m *MockBootstrapEnviron) Config() *config.Config {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Config")
	ret0, _ := ret[0].(*config.Config)
	return ret0
}

// Config indicates an expected call of Config.
func (mr *MockBootstrapEnvironMockRecorder) Config() *MockBootstrapEnvironConfigCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Config", reflect.TypeOf((*MockBootstrapEnviron)(nil).Config))
	return &MockBootstrapEnvironConfigCall{Call: call}
}

// MockBootstrapEnvironConfigCall wrap *gomock.Call
type MockBootstrapEnvironConfigCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironConfigCall) Return(arg0 *config.Config) *MockBootstrapEnvironConfigCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironConfigCall) Do(f func() *config.Config) *MockBootstrapEnvironConfigCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironConfigCall) DoAndReturn(f func() *config.Config) *MockBootstrapEnvironConfigCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ConstraintsValidator mocks base method.
func (m *MockBootstrapEnviron) ConstraintsValidator(arg0 envcontext.ProviderCallContext) (constraints.Validator, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConstraintsValidator", arg0)
	ret0, _ := ret[0].(constraints.Validator)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConstraintsValidator indicates an expected call of ConstraintsValidator.
func (mr *MockBootstrapEnvironMockRecorder) ConstraintsValidator(arg0 any) *MockBootstrapEnvironConstraintsValidatorCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConstraintsValidator", reflect.TypeOf((*MockBootstrapEnviron)(nil).ConstraintsValidator), arg0)
	return &MockBootstrapEnvironConstraintsValidatorCall{Call: call}
}

// MockBootstrapEnvironConstraintsValidatorCall wrap *gomock.Call
type MockBootstrapEnvironConstraintsValidatorCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironConstraintsValidatorCall) Return(arg0 constraints.Validator, arg1 error) *MockBootstrapEnvironConstraintsValidatorCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironConstraintsValidatorCall) Do(f func(envcontext.ProviderCallContext) (constraints.Validator, error)) *MockBootstrapEnvironConstraintsValidatorCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironConstraintsValidatorCall) DoAndReturn(f func(envcontext.ProviderCallContext) (constraints.Validator, error)) *MockBootstrapEnvironConstraintsValidatorCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Create mocks base method.
func (m *MockBootstrapEnviron) Create(arg0 envcontext.ProviderCallContext, arg1 environs.CreateParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockBootstrapEnvironMockRecorder) Create(arg0, arg1 any) *MockBootstrapEnvironCreateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockBootstrapEnviron)(nil).Create), arg0, arg1)
	return &MockBootstrapEnvironCreateCall{Call: call}
}

// MockBootstrapEnvironCreateCall wrap *gomock.Call
type MockBootstrapEnvironCreateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironCreateCall) Return(arg0 error) *MockBootstrapEnvironCreateCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironCreateCall) Do(f func(envcontext.ProviderCallContext, environs.CreateParams) error) *MockBootstrapEnvironCreateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironCreateCall) DoAndReturn(f func(envcontext.ProviderCallContext, environs.CreateParams) error) *MockBootstrapEnvironCreateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Destroy mocks base method.
func (m *MockBootstrapEnviron) Destroy(arg0 envcontext.ProviderCallContext) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Destroy", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Destroy indicates an expected call of Destroy.
func (mr *MockBootstrapEnvironMockRecorder) Destroy(arg0 any) *MockBootstrapEnvironDestroyCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Destroy", reflect.TypeOf((*MockBootstrapEnviron)(nil).Destroy), arg0)
	return &MockBootstrapEnvironDestroyCall{Call: call}
}

// MockBootstrapEnvironDestroyCall wrap *gomock.Call
type MockBootstrapEnvironDestroyCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironDestroyCall) Return(arg0 error) *MockBootstrapEnvironDestroyCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironDestroyCall) Do(f func(envcontext.ProviderCallContext) error) *MockBootstrapEnvironDestroyCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironDestroyCall) DoAndReturn(f func(envcontext.ProviderCallContext) error) *MockBootstrapEnvironDestroyCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// DestroyController mocks base method.
func (m *MockBootstrapEnviron) DestroyController(arg0 envcontext.ProviderCallContext, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DestroyController", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DestroyController indicates an expected call of DestroyController.
func (mr *MockBootstrapEnvironMockRecorder) DestroyController(arg0, arg1 any) *MockBootstrapEnvironDestroyControllerCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DestroyController", reflect.TypeOf((*MockBootstrapEnviron)(nil).DestroyController), arg0, arg1)
	return &MockBootstrapEnvironDestroyControllerCall{Call: call}
}

// MockBootstrapEnvironDestroyControllerCall wrap *gomock.Call
type MockBootstrapEnvironDestroyControllerCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironDestroyControllerCall) Return(arg0 error) *MockBootstrapEnvironDestroyControllerCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironDestroyControllerCall) Do(f func(envcontext.ProviderCallContext, string) error) *MockBootstrapEnvironDestroyControllerCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironDestroyControllerCall) DoAndReturn(f func(envcontext.ProviderCallContext, string) error) *MockBootstrapEnvironDestroyControllerCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// PrepareForBootstrap mocks base method.
func (m *MockBootstrapEnviron) PrepareForBootstrap(arg0 environs.BootstrapContext, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrepareForBootstrap", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// PrepareForBootstrap indicates an expected call of PrepareForBootstrap.
func (mr *MockBootstrapEnvironMockRecorder) PrepareForBootstrap(arg0, arg1 any) *MockBootstrapEnvironPrepareForBootstrapCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrepareForBootstrap", reflect.TypeOf((*MockBootstrapEnviron)(nil).PrepareForBootstrap), arg0, arg1)
	return &MockBootstrapEnvironPrepareForBootstrapCall{Call: call}
}

// MockBootstrapEnvironPrepareForBootstrapCall wrap *gomock.Call
type MockBootstrapEnvironPrepareForBootstrapCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironPrepareForBootstrapCall) Return(arg0 error) *MockBootstrapEnvironPrepareForBootstrapCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironPrepareForBootstrapCall) Do(f func(environs.BootstrapContext, string) error) *MockBootstrapEnvironPrepareForBootstrapCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironPrepareForBootstrapCall) DoAndReturn(f func(environs.BootstrapContext, string) error) *MockBootstrapEnvironPrepareForBootstrapCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SetConfig mocks base method.
func (m *MockBootstrapEnviron) SetConfig(arg0 context.Context, arg1 *config.Config) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetConfig", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetConfig indicates an expected call of SetConfig.
func (mr *MockBootstrapEnvironMockRecorder) SetConfig(arg0, arg1 any) *MockBootstrapEnvironSetConfigCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetConfig", reflect.TypeOf((*MockBootstrapEnviron)(nil).SetConfig), arg0, arg1)
	return &MockBootstrapEnvironSetConfigCall{Call: call}
}

// MockBootstrapEnvironSetConfigCall wrap *gomock.Call
type MockBootstrapEnvironSetConfigCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironSetConfigCall) Return(arg0 error) *MockBootstrapEnvironSetConfigCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironSetConfigCall) Do(f func(context.Context, *config.Config) error) *MockBootstrapEnvironSetConfigCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironSetConfigCall) DoAndReturn(f func(context.Context, *config.Config) error) *MockBootstrapEnvironSetConfigCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// StorageProvider mocks base method.
func (m *MockBootstrapEnviron) StorageProvider(arg0 storage.ProviderType) (storage.Provider, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageProvider", arg0)
	ret0, _ := ret[0].(storage.Provider)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StorageProvider indicates an expected call of StorageProvider.
func (mr *MockBootstrapEnvironMockRecorder) StorageProvider(arg0 any) *MockBootstrapEnvironStorageProviderCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageProvider", reflect.TypeOf((*MockBootstrapEnviron)(nil).StorageProvider), arg0)
	return &MockBootstrapEnvironStorageProviderCall{Call: call}
}

// MockBootstrapEnvironStorageProviderCall wrap *gomock.Call
type MockBootstrapEnvironStorageProviderCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironStorageProviderCall) Return(arg0 storage.Provider, arg1 error) *MockBootstrapEnvironStorageProviderCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironStorageProviderCall) Do(f func(storage.ProviderType) (storage.Provider, error)) *MockBootstrapEnvironStorageProviderCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironStorageProviderCall) DoAndReturn(f func(storage.ProviderType) (storage.Provider, error)) *MockBootstrapEnvironStorageProviderCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// StorageProviderTypes mocks base method.
func (m *MockBootstrapEnviron) StorageProviderTypes() ([]storage.ProviderType, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageProviderTypes")
	ret0, _ := ret[0].([]storage.ProviderType)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StorageProviderTypes indicates an expected call of StorageProviderTypes.
func (mr *MockBootstrapEnvironMockRecorder) StorageProviderTypes() *MockBootstrapEnvironStorageProviderTypesCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageProviderTypes", reflect.TypeOf((*MockBootstrapEnviron)(nil).StorageProviderTypes))
	return &MockBootstrapEnvironStorageProviderTypesCall{Call: call}
}

// MockBootstrapEnvironStorageProviderTypesCall wrap *gomock.Call
type MockBootstrapEnvironStorageProviderTypesCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockBootstrapEnvironStorageProviderTypesCall) Return(arg0 []storage.ProviderType, arg1 error) *MockBootstrapEnvironStorageProviderTypesCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockBootstrapEnvironStorageProviderTypesCall) Do(f func() ([]storage.ProviderType, error)) *MockBootstrapEnvironStorageProviderTypesCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockBootstrapEnvironStorageProviderTypesCall) DoAndReturn(f func() ([]storage.ProviderType, error)) *MockBootstrapEnvironStorageProviderTypesCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
