// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/internal/secrets/provider (interfaces: SecretBackendProvider,SecretsBackend)
//
// Generated by this command:
//
//	mockgen -package service -destination provider_mock_test.go github.com/juju/juju/internal/secrets/provider SecretBackendProvider,SecretsBackend
//

// Package service is a generated GoMock package.
package service

import (
	context "context"
	reflect "reflect"

	secrets "github.com/juju/juju/core/secrets"
	provider "github.com/juju/juju/internal/secrets/provider"
	names "github.com/juju/names/v5"
	gomock "go.uber.org/mock/gomock"
)

// MockSecretBackendProvider is a mock of SecretBackendProvider interface.
type MockSecretBackendProvider struct {
	ctrl     *gomock.Controller
	recorder *MockSecretBackendProviderMockRecorder
}

// MockSecretBackendProviderMockRecorder is the mock recorder for MockSecretBackendProvider.
type MockSecretBackendProviderMockRecorder struct {
	mock *MockSecretBackendProvider
}

// NewMockSecretBackendProvider creates a new mock instance.
func NewMockSecretBackendProvider(ctrl *gomock.Controller) *MockSecretBackendProvider {
	mock := &MockSecretBackendProvider{ctrl: ctrl}
	mock.recorder = &MockSecretBackendProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecretBackendProvider) EXPECT() *MockSecretBackendProviderMockRecorder {
	return m.recorder
}

// CleanupModel mocks base method.
func (m *MockSecretBackendProvider) CleanupModel(arg0 *provider.ModelBackendConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CleanupModel", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// CleanupModel indicates an expected call of CleanupModel.
func (mr *MockSecretBackendProviderMockRecorder) CleanupModel(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CleanupModel", reflect.TypeOf((*MockSecretBackendProvider)(nil).CleanupModel), arg0)
}

// CleanupSecrets mocks base method.
func (m *MockSecretBackendProvider) CleanupSecrets(arg0 context.Context, arg1 *provider.ModelBackendConfig, arg2 names.Tag, arg3 provider.SecretRevisions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CleanupSecrets", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// CleanupSecrets indicates an expected call of CleanupSecrets.
func (mr *MockSecretBackendProviderMockRecorder) CleanupSecrets(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CleanupSecrets", reflect.TypeOf((*MockSecretBackendProvider)(nil).CleanupSecrets), arg0, arg1, arg2, arg3)
}

// Initialise mocks base method.
func (m *MockSecretBackendProvider) Initialise(arg0 *provider.ModelBackendConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Initialise", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Initialise indicates an expected call of Initialise.
func (mr *MockSecretBackendProviderMockRecorder) Initialise(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Initialise", reflect.TypeOf((*MockSecretBackendProvider)(nil).Initialise), arg0)
}

// NewBackend mocks base method.
func (m *MockSecretBackendProvider) NewBackend(arg0 *provider.ModelBackendConfig) (provider.SecretsBackend, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewBackend", arg0)
	ret0, _ := ret[0].(provider.SecretsBackend)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewBackend indicates an expected call of NewBackend.
func (mr *MockSecretBackendProviderMockRecorder) NewBackend(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewBackend", reflect.TypeOf((*MockSecretBackendProvider)(nil).NewBackend), arg0)
}

// RestrictedConfig mocks base method.
func (m *MockSecretBackendProvider) RestrictedConfig(arg0 context.Context, arg1 *provider.ModelBackendConfig, arg2, arg3 bool, arg4 names.Tag, arg5, arg6 provider.SecretRevisions) (*provider.BackendConfig, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RestrictedConfig", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
	ret0, _ := ret[0].(*provider.BackendConfig)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RestrictedConfig indicates an expected call of RestrictedConfig.
func (mr *MockSecretBackendProviderMockRecorder) RestrictedConfig(arg0, arg1, arg2, arg3, arg4, arg5, arg6 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RestrictedConfig", reflect.TypeOf((*MockSecretBackendProvider)(nil).RestrictedConfig), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
}

// Type mocks base method.
func (m *MockSecretBackendProvider) Type() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Type")
	ret0, _ := ret[0].(string)
	return ret0
}

// Type indicates an expected call of Type.
func (mr *MockSecretBackendProviderMockRecorder) Type() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Type", reflect.TypeOf((*MockSecretBackendProvider)(nil).Type))
}

// MockSecretsBackend is a mock of SecretsBackend interface.
type MockSecretsBackend struct {
	ctrl     *gomock.Controller
	recorder *MockSecretsBackendMockRecorder
}

// MockSecretsBackendMockRecorder is the mock recorder for MockSecretsBackend.
type MockSecretsBackendMockRecorder struct {
	mock *MockSecretsBackend
}

// NewMockSecretsBackend creates a new mock instance.
func NewMockSecretsBackend(ctrl *gomock.Controller) *MockSecretsBackend {
	mock := &MockSecretsBackend{ctrl: ctrl}
	mock.recorder = &MockSecretsBackendMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecretsBackend) EXPECT() *MockSecretsBackendMockRecorder {
	return m.recorder
}

// DeleteContent mocks base method.
func (m *MockSecretsBackend) DeleteContent(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteContent", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteContent indicates an expected call of DeleteContent.
func (mr *MockSecretsBackendMockRecorder) DeleteContent(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteContent", reflect.TypeOf((*MockSecretsBackend)(nil).DeleteContent), arg0, arg1)
}

// GetContent mocks base method.
func (m *MockSecretsBackend) GetContent(arg0 context.Context, arg1 string) (secrets.SecretValue, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetContent", arg0, arg1)
	ret0, _ := ret[0].(secrets.SecretValue)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetContent indicates an expected call of GetContent.
func (mr *MockSecretsBackendMockRecorder) GetContent(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetContent", reflect.TypeOf((*MockSecretsBackend)(nil).GetContent), arg0, arg1)
}

// Ping mocks base method.
func (m *MockSecretsBackend) Ping() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Ping")
	ret0, _ := ret[0].(error)
	return ret0
}

// Ping indicates an expected call of Ping.
func (mr *MockSecretsBackendMockRecorder) Ping() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Ping", reflect.TypeOf((*MockSecretsBackend)(nil).Ping))
}

// SaveContent mocks base method.
func (m *MockSecretsBackend) SaveContent(arg0 context.Context, arg1 *secrets.URI, arg2 int, arg3 secrets.SecretValue) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveContent", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SaveContent indicates an expected call of SaveContent.
func (mr *MockSecretsBackendMockRecorder) SaveContent(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveContent", reflect.TypeOf((*MockSecretsBackend)(nil).SaveContent), arg0, arg1, arg2, arg3)
}
