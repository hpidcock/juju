// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/internal/worker/uniter/runner/jujuc (interfaces: Context)
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/context_mock.go github.com/juju/juju/internal/worker/uniter/runner/jujuc Context
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"
	time "time"

	charm "github.com/juju/charm/v13"
	application "github.com/juju/juju/core/application"
	network "github.com/juju/juju/core/network"
	payloads "github.com/juju/juju/core/payloads"
	secrets "github.com/juju/juju/core/secrets"
	jujuc "github.com/juju/juju/internal/worker/uniter/runner/jujuc"
	params "github.com/juju/juju/rpc/params"
	loggo "github.com/juju/loggo/v2"
	names "github.com/juju/names/v5"
	gomock "go.uber.org/mock/gomock"
)

// MockContext is a mock of Context interface.
type MockContext struct {
	ctrl     *gomock.Controller
	recorder *MockContextMockRecorder
}

// MockContextMockRecorder is the mock recorder for MockContext.
type MockContextMockRecorder struct {
	mock *MockContext
}

// NewMockContext creates a new mock instance.
func NewMockContext(ctrl *gomock.Controller) *MockContext {
	mock := &MockContext{ctrl: ctrl}
	mock.recorder = &MockContextMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockContext) EXPECT() *MockContextMockRecorder {
	return m.recorder
}

// ActionParams mocks base method.
func (m *MockContext) ActionParams() (map[string]any, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ActionParams")
	ret0, _ := ret[0].(map[string]any)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ActionParams indicates an expected call of ActionParams.
func (mr *MockContextMockRecorder) ActionParams() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ActionParams", reflect.TypeOf((*MockContext)(nil).ActionParams))
}

// AddMetric mocks base method.
func (m *MockContext) AddMetric(arg0, arg1 string, arg2 time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddMetric", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddMetric indicates an expected call of AddMetric.
func (mr *MockContextMockRecorder) AddMetric(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddMetric", reflect.TypeOf((*MockContext)(nil).AddMetric), arg0, arg1, arg2)
}

// AddMetricLabels mocks base method.
func (m *MockContext) AddMetricLabels(arg0, arg1 string, arg2 time.Time, arg3 map[string]string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddMetricLabels", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddMetricLabels indicates an expected call of AddMetricLabels.
func (mr *MockContextMockRecorder) AddMetricLabels(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddMetricLabels", reflect.TypeOf((*MockContext)(nil).AddMetricLabels), arg0, arg1, arg2, arg3)
}

// AddUnitStorage mocks base method.
func (m *MockContext) AddUnitStorage(arg0 map[string]params.StorageConstraints) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddUnitStorage", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddUnitStorage indicates an expected call of AddUnitStorage.
func (mr *MockContextMockRecorder) AddUnitStorage(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddUnitStorage", reflect.TypeOf((*MockContext)(nil).AddUnitStorage), arg0)
}

// ApplicationStatus mocks base method.
func (m *MockContext) ApplicationStatus(arg0 context.Context) (jujuc.ApplicationStatusInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ApplicationStatus", arg0)
	ret0, _ := ret[0].(jujuc.ApplicationStatusInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ApplicationStatus indicates an expected call of ApplicationStatus.
func (mr *MockContextMockRecorder) ApplicationStatus(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ApplicationStatus", reflect.TypeOf((*MockContext)(nil).ApplicationStatus), arg0)
}

// AvailabilityZone mocks base method.
func (m *MockContext) AvailabilityZone() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AvailabilityZone")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AvailabilityZone indicates an expected call of AvailabilityZone.
func (mr *MockContextMockRecorder) AvailabilityZone() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AvailabilityZone", reflect.TypeOf((*MockContext)(nil).AvailabilityZone))
}

// ClosePortRange mocks base method.
func (m *MockContext) ClosePortRange(arg0 string, arg1 network.PortRange) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClosePortRange", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ClosePortRange indicates an expected call of ClosePortRange.
func (mr *MockContextMockRecorder) ClosePortRange(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClosePortRange", reflect.TypeOf((*MockContext)(nil).ClosePortRange), arg0, arg1)
}

// CloudSpec mocks base method.
func (m *MockContext) CloudSpec(arg0 context.Context) (*params.CloudSpec, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloudSpec", arg0)
	ret0, _ := ret[0].(*params.CloudSpec)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CloudSpec indicates an expected call of CloudSpec.
func (mr *MockContextMockRecorder) CloudSpec(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloudSpec", reflect.TypeOf((*MockContext)(nil).CloudSpec), arg0)
}

// ConfigSettings mocks base method.
func (m *MockContext) ConfigSettings() (charm.Settings, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConfigSettings")
	ret0, _ := ret[0].(charm.Settings)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConfigSettings indicates an expected call of ConfigSettings.
func (mr *MockContextMockRecorder) ConfigSettings() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigSettings", reflect.TypeOf((*MockContext)(nil).ConfigSettings))
}

// CreateSecret mocks base method.
func (m *MockContext) CreateSecret(arg0 *jujuc.SecretCreateArgs) (*secrets.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateSecret", arg0)
	ret0, _ := ret[0].(*secrets.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateSecret indicates an expected call of CreateSecret.
func (mr *MockContextMockRecorder) CreateSecret(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateSecret", reflect.TypeOf((*MockContext)(nil).CreateSecret), arg0)
}

// DeleteCharmStateValue mocks base method.
func (m *MockContext) DeleteCharmStateValue(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteCharmStateValue", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteCharmStateValue indicates an expected call of DeleteCharmStateValue.
func (mr *MockContextMockRecorder) DeleteCharmStateValue(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteCharmStateValue", reflect.TypeOf((*MockContext)(nil).DeleteCharmStateValue), arg0)
}

// DownloadResource mocks base method.
func (m *MockContext) DownloadResource(arg0 context.Context, arg1 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DownloadResource", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DownloadResource indicates an expected call of DownloadResource.
func (mr *MockContextMockRecorder) DownloadResource(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DownloadResource", reflect.TypeOf((*MockContext)(nil).DownloadResource), arg0, arg1)
}

// FlushPayloads mocks base method.
func (m *MockContext) FlushPayloads() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FlushPayloads")
	ret0, _ := ret[0].(error)
	return ret0
}

// FlushPayloads indicates an expected call of FlushPayloads.
func (mr *MockContextMockRecorder) FlushPayloads() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FlushPayloads", reflect.TypeOf((*MockContext)(nil).FlushPayloads))
}

// GetCharmState mocks base method.
func (m *MockContext) GetCharmState() (map[string]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCharmState")
	ret0, _ := ret[0].(map[string]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCharmState indicates an expected call of GetCharmState.
func (mr *MockContextMockRecorder) GetCharmState() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCharmState", reflect.TypeOf((*MockContext)(nil).GetCharmState))
}

// GetCharmStateValue mocks base method.
func (m *MockContext) GetCharmStateValue(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCharmStateValue", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCharmStateValue indicates an expected call of GetCharmStateValue.
func (mr *MockContextMockRecorder) GetCharmStateValue(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCharmStateValue", reflect.TypeOf((*MockContext)(nil).GetCharmStateValue), arg0)
}

// GetLogger mocks base method.
func (m *MockContext) GetLogger(arg0 string) loggo.Logger {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLogger", arg0)
	ret0, _ := ret[0].(loggo.Logger)
	return ret0
}

// GetLogger indicates an expected call of GetLogger.
func (mr *MockContextMockRecorder) GetLogger(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLogger", reflect.TypeOf((*MockContext)(nil).GetLogger), arg0)
}

// GetPayload mocks base method.
func (m *MockContext) GetPayload(arg0, arg1 string) (*payloads.Payload, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPayload", arg0, arg1)
	ret0, _ := ret[0].(*payloads.Payload)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPayload indicates an expected call of GetPayload.
func (mr *MockContextMockRecorder) GetPayload(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPayload", reflect.TypeOf((*MockContext)(nil).GetPayload), arg0, arg1)
}

// GetSecret mocks base method.
func (m *MockContext) GetSecret(arg0 *secrets.URI, arg1 string, arg2, arg3 bool) (secrets.SecretValue, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecret", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(secrets.SecretValue)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecret indicates an expected call of GetSecret.
func (mr *MockContextMockRecorder) GetSecret(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecret", reflect.TypeOf((*MockContext)(nil).GetSecret), arg0, arg1, arg2, arg3)
}

// GoalState mocks base method.
func (m *MockContext) GoalState(arg0 context.Context) (*application.GoalState, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GoalState", arg0)
	ret0, _ := ret[0].(*application.GoalState)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GoalState indicates an expected call of GoalState.
func (mr *MockContextMockRecorder) GoalState(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GoalState", reflect.TypeOf((*MockContext)(nil).GoalState), arg0)
}

// GrantSecret mocks base method.
func (m *MockContext) GrantSecret(arg0 *secrets.URI, arg1 *jujuc.SecretGrantRevokeArgs) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GrantSecret", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// GrantSecret indicates an expected call of GrantSecret.
func (mr *MockContextMockRecorder) GrantSecret(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrantSecret", reflect.TypeOf((*MockContext)(nil).GrantSecret), arg0, arg1)
}

// HookRelation mocks base method.
func (m *MockContext) HookRelation() (jujuc.ContextRelation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HookRelation")
	ret0, _ := ret[0].(jujuc.ContextRelation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HookRelation indicates an expected call of HookRelation.
func (mr *MockContextMockRecorder) HookRelation() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HookRelation", reflect.TypeOf((*MockContext)(nil).HookRelation))
}

// HookStorage mocks base method.
func (m *MockContext) HookStorage() (jujuc.ContextStorageAttachment, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HookStorage")
	ret0, _ := ret[0].(jujuc.ContextStorageAttachment)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HookStorage indicates an expected call of HookStorage.
func (mr *MockContextMockRecorder) HookStorage() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HookStorage", reflect.TypeOf((*MockContext)(nil).HookStorage))
}

// IsLeader mocks base method.
func (m *MockContext) IsLeader() (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsLeader")
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsLeader indicates an expected call of IsLeader.
func (mr *MockContextMockRecorder) IsLeader() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsLeader", reflect.TypeOf((*MockContext)(nil).IsLeader))
}

// LeaderSettings mocks base method.
func (m *MockContext) LeaderSettings() (map[string]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LeaderSettings")
	ret0, _ := ret[0].(map[string]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LeaderSettings indicates an expected call of LeaderSettings.
func (mr *MockContextMockRecorder) LeaderSettings() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LeaderSettings", reflect.TypeOf((*MockContext)(nil).LeaderSettings))
}

// ListPayloads mocks base method.
func (m *MockContext) ListPayloads() ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListPayloads")
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListPayloads indicates an expected call of ListPayloads.
func (mr *MockContextMockRecorder) ListPayloads() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListPayloads", reflect.TypeOf((*MockContext)(nil).ListPayloads))
}

// LogActionMessage mocks base method.
func (m *MockContext) LogActionMessage(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LogActionMessage", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// LogActionMessage indicates an expected call of LogActionMessage.
func (mr *MockContextMockRecorder) LogActionMessage(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LogActionMessage", reflect.TypeOf((*MockContext)(nil).LogActionMessage), arg0)
}

// NetworkInfo mocks base method.
func (m *MockContext) NetworkInfo(arg0 []string, arg1 int) (map[string]params.NetworkInfoResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NetworkInfo", arg0, arg1)
	ret0, _ := ret[0].(map[string]params.NetworkInfoResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NetworkInfo indicates an expected call of NetworkInfo.
func (mr *MockContextMockRecorder) NetworkInfo(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NetworkInfo", reflect.TypeOf((*MockContext)(nil).NetworkInfo), arg0, arg1)
}

// OpenPortRange mocks base method.
func (m *MockContext) OpenPortRange(arg0 string, arg1 network.PortRange) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenPortRange", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// OpenPortRange indicates an expected call of OpenPortRange.
func (mr *MockContextMockRecorder) OpenPortRange(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenPortRange", reflect.TypeOf((*MockContext)(nil).OpenPortRange), arg0, arg1)
}

// OpenedPortRanges mocks base method.
func (m *MockContext) OpenedPortRanges() network.GroupedPortRanges {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenedPortRanges")
	ret0, _ := ret[0].(network.GroupedPortRanges)
	return ret0
}

// OpenedPortRanges indicates an expected call of OpenedPortRanges.
func (mr *MockContextMockRecorder) OpenedPortRanges() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenedPortRanges", reflect.TypeOf((*MockContext)(nil).OpenedPortRanges))
}

// PrivateAddress mocks base method.
func (m *MockContext) PrivateAddress() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrivateAddress")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PrivateAddress indicates an expected call of PrivateAddress.
func (mr *MockContextMockRecorder) PrivateAddress() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrivateAddress", reflect.TypeOf((*MockContext)(nil).PrivateAddress))
}

// PublicAddress mocks base method.
func (m *MockContext) PublicAddress() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublicAddress")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PublicAddress indicates an expected call of PublicAddress.
func (mr *MockContextMockRecorder) PublicAddress() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublicAddress", reflect.TypeOf((*MockContext)(nil).PublicAddress))
}

// Relation mocks base method.
func (m *MockContext) Relation(arg0 int) (jujuc.ContextRelation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Relation", arg0)
	ret0, _ := ret[0].(jujuc.ContextRelation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Relation indicates an expected call of Relation.
func (mr *MockContextMockRecorder) Relation(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Relation", reflect.TypeOf((*MockContext)(nil).Relation), arg0)
}

// RelationIds mocks base method.
func (m *MockContext) RelationIds() ([]int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RelationIds")
	ret0, _ := ret[0].([]int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RelationIds indicates an expected call of RelationIds.
func (mr *MockContextMockRecorder) RelationIds() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RelationIds", reflect.TypeOf((*MockContext)(nil).RelationIds))
}

// RemoteApplicationName mocks base method.
func (m *MockContext) RemoteApplicationName() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoteApplicationName")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RemoteApplicationName indicates an expected call of RemoteApplicationName.
func (mr *MockContextMockRecorder) RemoteApplicationName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoteApplicationName", reflect.TypeOf((*MockContext)(nil).RemoteApplicationName))
}

// RemoteUnitName mocks base method.
func (m *MockContext) RemoteUnitName() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoteUnitName")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RemoteUnitName indicates an expected call of RemoteUnitName.
func (mr *MockContextMockRecorder) RemoteUnitName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoteUnitName", reflect.TypeOf((*MockContext)(nil).RemoteUnitName))
}

// RemoveSecret mocks base method.
func (m *MockContext) RemoveSecret(arg0 *secrets.URI, arg1 *int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveSecret", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveSecret indicates an expected call of RemoveSecret.
func (mr *MockContextMockRecorder) RemoveSecret(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveSecret", reflect.TypeOf((*MockContext)(nil).RemoveSecret), arg0, arg1)
}

// RequestReboot mocks base method.
func (m *MockContext) RequestReboot(arg0 jujuc.RebootPriority) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestReboot", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RequestReboot indicates an expected call of RequestReboot.
func (mr *MockContextMockRecorder) RequestReboot(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestReboot", reflect.TypeOf((*MockContext)(nil).RequestReboot), arg0)
}

// RevokeSecret mocks base method.
func (m *MockContext) RevokeSecret(arg0 *secrets.URI, arg1 *jujuc.SecretGrantRevokeArgs) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RevokeSecret", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// RevokeSecret indicates an expected call of RevokeSecret.
func (mr *MockContextMockRecorder) RevokeSecret(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RevokeSecret", reflect.TypeOf((*MockContext)(nil).RevokeSecret), arg0, arg1)
}

// SecretMetadata mocks base method.
func (m *MockContext) SecretMetadata() (map[string]jujuc.SecretMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SecretMetadata")
	ret0, _ := ret[0].(map[string]jujuc.SecretMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SecretMetadata indicates an expected call of SecretMetadata.
func (mr *MockContextMockRecorder) SecretMetadata() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SecretMetadata", reflect.TypeOf((*MockContext)(nil).SecretMetadata))
}

// SetActionFailed mocks base method.
func (m *MockContext) SetActionFailed() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetActionFailed")
	ret0, _ := ret[0].(error)
	return ret0
}

// SetActionFailed indicates an expected call of SetActionFailed.
func (mr *MockContextMockRecorder) SetActionFailed() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetActionFailed", reflect.TypeOf((*MockContext)(nil).SetActionFailed))
}

// SetActionMessage mocks base method.
func (m *MockContext) SetActionMessage(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetActionMessage", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetActionMessage indicates an expected call of SetActionMessage.
func (mr *MockContextMockRecorder) SetActionMessage(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetActionMessage", reflect.TypeOf((*MockContext)(nil).SetActionMessage), arg0)
}

// SetApplicationStatus mocks base method.
func (m *MockContext) SetApplicationStatus(arg0 context.Context, arg1 jujuc.StatusInfo) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetApplicationStatus", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetApplicationStatus indicates an expected call of SetApplicationStatus.
func (mr *MockContextMockRecorder) SetApplicationStatus(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetApplicationStatus", reflect.TypeOf((*MockContext)(nil).SetApplicationStatus), arg0, arg1)
}

// SetCharmStateValue mocks base method.
func (m *MockContext) SetCharmStateValue(arg0, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetCharmStateValue", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetCharmStateValue indicates an expected call of SetCharmStateValue.
func (mr *MockContextMockRecorder) SetCharmStateValue(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetCharmStateValue", reflect.TypeOf((*MockContext)(nil).SetCharmStateValue), arg0, arg1)
}

// SetPayloadStatus mocks base method.
func (m *MockContext) SetPayloadStatus(arg0, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetPayloadStatus", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetPayloadStatus indicates an expected call of SetPayloadStatus.
func (mr *MockContextMockRecorder) SetPayloadStatus(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetPayloadStatus", reflect.TypeOf((*MockContext)(nil).SetPayloadStatus), arg0, arg1, arg2)
}

// SetUnitStatus mocks base method.
func (m *MockContext) SetUnitStatus(arg0 context.Context, arg1 jujuc.StatusInfo) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetUnitStatus", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetUnitStatus indicates an expected call of SetUnitStatus.
func (mr *MockContextMockRecorder) SetUnitStatus(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUnitStatus", reflect.TypeOf((*MockContext)(nil).SetUnitStatus), arg0, arg1)
}

// SetUnitWorkloadVersion mocks base method.
func (m *MockContext) SetUnitWorkloadVersion(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetUnitWorkloadVersion", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetUnitWorkloadVersion indicates an expected call of SetUnitWorkloadVersion.
func (mr *MockContextMockRecorder) SetUnitWorkloadVersion(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUnitWorkloadVersion", reflect.TypeOf((*MockContext)(nil).SetUnitWorkloadVersion), arg0, arg1)
}

// Storage mocks base method.
func (m *MockContext) Storage(arg0 names.StorageTag) (jujuc.ContextStorageAttachment, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Storage", arg0)
	ret0, _ := ret[0].(jujuc.ContextStorageAttachment)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Storage indicates an expected call of Storage.
func (mr *MockContextMockRecorder) Storage(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Storage", reflect.TypeOf((*MockContext)(nil).Storage), arg0)
}

// StorageTags mocks base method.
func (m *MockContext) StorageTags() ([]names.StorageTag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageTags")
	ret0, _ := ret[0].([]names.StorageTag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StorageTags indicates an expected call of StorageTags.
func (mr *MockContextMockRecorder) StorageTags() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageTags", reflect.TypeOf((*MockContext)(nil).StorageTags))
}

// TrackPayload mocks base method.
func (m *MockContext) TrackPayload(arg0 payloads.Payload) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TrackPayload", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// TrackPayload indicates an expected call of TrackPayload.
func (mr *MockContextMockRecorder) TrackPayload(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TrackPayload", reflect.TypeOf((*MockContext)(nil).TrackPayload), arg0)
}

// UnitName mocks base method.
func (m *MockContext) UnitName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnitName")
	ret0, _ := ret[0].(string)
	return ret0
}

// UnitName indicates an expected call of UnitName.
func (mr *MockContextMockRecorder) UnitName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnitName", reflect.TypeOf((*MockContext)(nil).UnitName))
}

// UnitStatus mocks base method.
func (m *MockContext) UnitStatus(arg0 context.Context) (*jujuc.StatusInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnitStatus", arg0)
	ret0, _ := ret[0].(*jujuc.StatusInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UnitStatus indicates an expected call of UnitStatus.
func (mr *MockContextMockRecorder) UnitStatus(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnitStatus", reflect.TypeOf((*MockContext)(nil).UnitStatus), arg0)
}

// UnitWorkloadVersion mocks base method.
func (m *MockContext) UnitWorkloadVersion(arg0 context.Context) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnitWorkloadVersion", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UnitWorkloadVersion indicates an expected call of UnitWorkloadVersion.
func (mr *MockContextMockRecorder) UnitWorkloadVersion(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnitWorkloadVersion", reflect.TypeOf((*MockContext)(nil).UnitWorkloadVersion), arg0)
}

// UntrackPayload mocks base method.
func (m *MockContext) UntrackPayload(arg0, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UntrackPayload", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UntrackPayload indicates an expected call of UntrackPayload.
func (mr *MockContextMockRecorder) UntrackPayload(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UntrackPayload", reflect.TypeOf((*MockContext)(nil).UntrackPayload), arg0, arg1)
}

// UpdateActionResults mocks base method.
func (m *MockContext) UpdateActionResults(arg0 []string, arg1 any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateActionResults", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateActionResults indicates an expected call of UpdateActionResults.
func (mr *MockContextMockRecorder) UpdateActionResults(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateActionResults", reflect.TypeOf((*MockContext)(nil).UpdateActionResults), arg0, arg1)
}

// UpdateSecret mocks base method.
func (m *MockContext) UpdateSecret(arg0 *secrets.URI, arg1 *jujuc.SecretUpdateArgs) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateSecret", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateSecret indicates an expected call of UpdateSecret.
func (mr *MockContextMockRecorder) UpdateSecret(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSecret", reflect.TypeOf((*MockContext)(nil).UpdateSecret), arg0, arg1)
}

// WorkloadName mocks base method.
func (m *MockContext) WorkloadName() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WorkloadName")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WorkloadName indicates an expected call of WorkloadName.
func (mr *MockContextMockRecorder) WorkloadName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WorkloadName", reflect.TypeOf((*MockContext)(nil).WorkloadName))
}

// WriteLeaderSettings mocks base method.
func (m *MockContext) WriteLeaderSettings(arg0 map[string]string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteLeaderSettings", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// WriteLeaderSettings indicates an expected call of WriteLeaderSettings.
func (mr *MockContextMockRecorder) WriteLeaderSettings(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteLeaderSettings", reflect.TypeOf((*MockContext)(nil).WriteLeaderSettings), arg0)
}
