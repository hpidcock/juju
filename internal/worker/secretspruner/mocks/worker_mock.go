// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/internal/worker/secretspruner (interfaces: SecretsFacade)
//
// Generated by this command:
//
//	mockgen -typed -package mocks -destination mocks/worker_mock.go github.com/juju/juju/internal/worker/secretspruner SecretsFacade
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	secrets "github.com/juju/juju/core/secrets"
	watcher "github.com/juju/juju/core/watcher"
	gomock "go.uber.org/mock/gomock"
)

// MockSecretsFacade is a mock of SecretsFacade interface.
type MockSecretsFacade struct {
	ctrl     *gomock.Controller
	recorder *MockSecretsFacadeMockRecorder
}

// MockSecretsFacadeMockRecorder is the mock recorder for MockSecretsFacade.
type MockSecretsFacadeMockRecorder struct {
	mock *MockSecretsFacade
}

// NewMockSecretsFacade creates a new mock instance.
func NewMockSecretsFacade(ctrl *gomock.Controller) *MockSecretsFacade {
	mock := &MockSecretsFacade{ctrl: ctrl}
	mock.recorder = &MockSecretsFacadeMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecretsFacade) EXPECT() *MockSecretsFacadeMockRecorder {
	return m.recorder
}

// DeleteObsoleteUserSecrets mocks base method.
func (m *MockSecretsFacade) DeleteObsoleteUserSecrets(arg0 *secrets.URI, arg1 ...int) error {
	m.ctrl.T.Helper()
	varargs := []any{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteObsoleteUserSecrets", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteObsoleteUserSecrets indicates an expected call of DeleteObsoleteUserSecrets.
func (mr *MockSecretsFacadeMockRecorder) DeleteObsoleteUserSecrets(arg0 any, arg1 ...any) *MockSecretsFacadeDeleteObsoleteUserSecretsCall {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{arg0}, arg1...)
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteObsoleteUserSecrets", reflect.TypeOf((*MockSecretsFacade)(nil).DeleteObsoleteUserSecrets), varargs...)
	return &MockSecretsFacadeDeleteObsoleteUserSecretsCall{Call: call}
}

// MockSecretsFacadeDeleteObsoleteUserSecretsCall wrap *gomock.Call
type MockSecretsFacadeDeleteObsoleteUserSecretsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSecretsFacadeDeleteObsoleteUserSecretsCall) Return(arg0 error) *MockSecretsFacadeDeleteObsoleteUserSecretsCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSecretsFacadeDeleteObsoleteUserSecretsCall) Do(f func(*secrets.URI, ...int) error) *MockSecretsFacadeDeleteObsoleteUserSecretsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSecretsFacadeDeleteObsoleteUserSecretsCall) DoAndReturn(f func(*secrets.URI, ...int) error) *MockSecretsFacadeDeleteObsoleteUserSecretsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// WatchRevisionsToPrune mocks base method.
func (m *MockSecretsFacade) WatchRevisionsToPrune() (watcher.Watcher[[]string], error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WatchRevisionsToPrune")
	ret0, _ := ret[0].(watcher.Watcher[[]string])
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WatchRevisionsToPrune indicates an expected call of WatchRevisionsToPrune.
func (mr *MockSecretsFacadeMockRecorder) WatchRevisionsToPrune() *MockSecretsFacadeWatchRevisionsToPruneCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WatchRevisionsToPrune", reflect.TypeOf((*MockSecretsFacade)(nil).WatchRevisionsToPrune))
	return &MockSecretsFacadeWatchRevisionsToPruneCall{Call: call}
}

// MockSecretsFacadeWatchRevisionsToPruneCall wrap *gomock.Call
type MockSecretsFacadeWatchRevisionsToPruneCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSecretsFacadeWatchRevisionsToPruneCall) Return(arg0 watcher.Watcher[[]string], arg1 error) *MockSecretsFacadeWatchRevisionsToPruneCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSecretsFacadeWatchRevisionsToPruneCall) Do(f func() (watcher.Watcher[[]string], error)) *MockSecretsFacadeWatchRevisionsToPruneCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSecretsFacadeWatchRevisionsToPruneCall) DoAndReturn(f func() (watcher.Watcher[[]string], error)) *MockSecretsFacadeWatchRevisionsToPruneCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
