// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/core/charm/downloader (interfaces: CharmRepository)
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/charm_archive_mocks.go github.com/juju/juju/core/charm/downloader CharmRepository
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	url "net/url"
	reflect "reflect"

	charm "github.com/juju/charm/v13"
	charm0 "github.com/juju/juju/core/charm"
	gomock "go.uber.org/mock/gomock"
)

// MockCharmRepository is a mock of CharmRepository interface.
type MockCharmRepository struct {
	ctrl     *gomock.Controller
	recorder *MockCharmRepositoryMockRecorder
}

// MockCharmRepositoryMockRecorder is the mock recorder for MockCharmRepository.
type MockCharmRepositoryMockRecorder struct {
	mock *MockCharmRepository
}

// NewMockCharmRepository creates a new mock instance.
func NewMockCharmRepository(ctrl *gomock.Controller) *MockCharmRepository {
	mock := &MockCharmRepository{ctrl: ctrl}
	mock.recorder = &MockCharmRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCharmRepository) EXPECT() *MockCharmRepositoryMockRecorder {
	return m.recorder
}

// DownloadCharm mocks base method.
func (m *MockCharmRepository) DownloadCharm(arg0 context.Context, arg1 string, arg2 charm0.Origin, arg3 string) (charm0.CharmArchive, charm0.Origin, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DownloadCharm", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(charm0.CharmArchive)
	ret1, _ := ret[1].(charm0.Origin)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// DownloadCharm indicates an expected call of DownloadCharm.
func (mr *MockCharmRepositoryMockRecorder) DownloadCharm(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DownloadCharm", reflect.TypeOf((*MockCharmRepository)(nil).DownloadCharm), arg0, arg1, arg2, arg3)
}

// GetDownloadURL mocks base method.
func (m *MockCharmRepository) GetDownloadURL(arg0 context.Context, arg1 string, arg2 charm0.Origin) (*url.URL, charm0.Origin, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDownloadURL", arg0, arg1, arg2)
	ret0, _ := ret[0].(*url.URL)
	ret1, _ := ret[1].(charm0.Origin)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetDownloadURL indicates an expected call of GetDownloadURL.
func (mr *MockCharmRepositoryMockRecorder) GetDownloadURL(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDownloadURL", reflect.TypeOf((*MockCharmRepository)(nil).GetDownloadURL), arg0, arg1, arg2)
}

// ResolveWithPreferredChannel mocks base method.
func (m *MockCharmRepository) ResolveWithPreferredChannel(arg0 context.Context, arg1 string, arg2 charm0.Origin) (*charm.URL, charm0.Origin, []charm0.Platform, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveWithPreferredChannel", arg0, arg1, arg2)
	ret0, _ := ret[0].(*charm.URL)
	ret1, _ := ret[1].(charm0.Origin)
	ret2, _ := ret[2].([]charm0.Platform)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// ResolveWithPreferredChannel indicates an expected call of ResolveWithPreferredChannel.
func (mr *MockCharmRepositoryMockRecorder) ResolveWithPreferredChannel(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveWithPreferredChannel", reflect.TypeOf((*MockCharmRepository)(nil).ResolveWithPreferredChannel), arg0, arg1, arg2)
}
