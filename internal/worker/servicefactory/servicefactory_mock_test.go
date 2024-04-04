// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/internal/servicefactory (interfaces: ControllerServiceFactory,ModelServiceFactory,ServiceFactory,ServiceFactoryGetter)
//
// Generated by this command:
//
//	mockgen -package servicefactory -destination servicefactory_mock_test.go github.com/juju/juju/internal/servicefactory ControllerServiceFactory,ModelServiceFactory,ServiceFactory,ServiceFactoryGetter
//

// Package servicefactory is a generated GoMock package.
package servicefactory

import (
	reflect "reflect"

	service "github.com/juju/juju/domain/access/service"
	service0 "github.com/juju/juju/domain/annotation/service"
	service1 "github.com/juju/juju/domain/application/service"
	service2 "github.com/juju/juju/domain/autocert/service"
	service3 "github.com/juju/juju/domain/blockdevice/service"
	service4 "github.com/juju/juju/domain/cloud/service"
	service5 "github.com/juju/juju/domain/controllerconfig/service"
	service6 "github.com/juju/juju/domain/controllernode/service"
	service7 "github.com/juju/juju/domain/credential/service"
	service8 "github.com/juju/juju/domain/externalcontroller/service"
	service9 "github.com/juju/juju/domain/flag/service"
	service10 "github.com/juju/juju/domain/machine/service"
	service11 "github.com/juju/juju/domain/model/service"
	service12 "github.com/juju/juju/domain/modelconfig/service"
	service13 "github.com/juju/juju/domain/modeldefaults/service"
	service14 "github.com/juju/juju/domain/network/service"
	service15 "github.com/juju/juju/domain/objectstore/service"
	service16 "github.com/juju/juju/domain/secret/service"
	service17 "github.com/juju/juju/domain/secretbackend/service"
	service18 "github.com/juju/juju/domain/storage/service"
	service19 "github.com/juju/juju/domain/unit/service"
	service20 "github.com/juju/juju/domain/upgrade/service"
	servicefactory "github.com/juju/juju/internal/servicefactory"
	storage "github.com/juju/juju/internal/storage"
	gomock "go.uber.org/mock/gomock"
)

// MockControllerServiceFactory is a mock of ControllerServiceFactory interface.
type MockControllerServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockControllerServiceFactoryMockRecorder
}

// MockControllerServiceFactoryMockRecorder is the mock recorder for MockControllerServiceFactory.
type MockControllerServiceFactoryMockRecorder struct {
	mock *MockControllerServiceFactory
}

// NewMockControllerServiceFactory creates a new mock instance.
func NewMockControllerServiceFactory(ctrl *gomock.Controller) *MockControllerServiceFactory {
	mock := &MockControllerServiceFactory{ctrl: ctrl}
	mock.recorder = &MockControllerServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockControllerServiceFactory) EXPECT() *MockControllerServiceFactoryMockRecorder {
	return m.recorder
}

// Access mocks base method.
func (m *MockControllerServiceFactory) Access() *service.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Access")
	ret0, _ := ret[0].(*service.Service)
	return ret0
}

// Access indicates an expected call of Access.
func (mr *MockControllerServiceFactoryMockRecorder) Access() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Access", reflect.TypeOf((*MockControllerServiceFactory)(nil).Access))
}

// AgentObjectStore mocks base method.
func (m *MockControllerServiceFactory) AgentObjectStore() *service15.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AgentObjectStore")
	ret0, _ := ret[0].(*service15.WatchableService)
	return ret0
}

// AgentObjectStore indicates an expected call of AgentObjectStore.
func (mr *MockControllerServiceFactoryMockRecorder) AgentObjectStore() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AgentObjectStore", reflect.TypeOf((*MockControllerServiceFactory)(nil).AgentObjectStore))
}

// AutocertCache mocks base method.
func (m *MockControllerServiceFactory) AutocertCache() *service2.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AutocertCache")
	ret0, _ := ret[0].(*service2.Service)
	return ret0
}

// AutocertCache indicates an expected call of AutocertCache.
func (mr *MockControllerServiceFactoryMockRecorder) AutocertCache() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AutocertCache", reflect.TypeOf((*MockControllerServiceFactory)(nil).AutocertCache))
}

// Cloud mocks base method.
func (m *MockControllerServiceFactory) Cloud() *service4.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Cloud")
	ret0, _ := ret[0].(*service4.WatchableService)
	return ret0
}

// Cloud indicates an expected call of Cloud.
func (mr *MockControllerServiceFactoryMockRecorder) Cloud() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cloud", reflect.TypeOf((*MockControllerServiceFactory)(nil).Cloud))
}

// ControllerConfig mocks base method.
func (m *MockControllerServiceFactory) ControllerConfig() *service5.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ControllerConfig")
	ret0, _ := ret[0].(*service5.WatchableService)
	return ret0
}

// ControllerConfig indicates an expected call of ControllerConfig.
func (mr *MockControllerServiceFactoryMockRecorder) ControllerConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ControllerConfig", reflect.TypeOf((*MockControllerServiceFactory)(nil).ControllerConfig))
}

// ControllerNode mocks base method.
func (m *MockControllerServiceFactory) ControllerNode() *service6.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ControllerNode")
	ret0, _ := ret[0].(*service6.Service)
	return ret0
}

// ControllerNode indicates an expected call of ControllerNode.
func (mr *MockControllerServiceFactoryMockRecorder) ControllerNode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ControllerNode", reflect.TypeOf((*MockControllerServiceFactory)(nil).ControllerNode))
}

// Credential mocks base method.
func (m *MockControllerServiceFactory) Credential() *service7.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Credential")
	ret0, _ := ret[0].(*service7.WatchableService)
	return ret0
}

// Credential indicates an expected call of Credential.
func (mr *MockControllerServiceFactoryMockRecorder) Credential() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Credential", reflect.TypeOf((*MockControllerServiceFactory)(nil).Credential))
}

// ExternalController mocks base method.
func (m *MockControllerServiceFactory) ExternalController() *service8.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExternalController")
	ret0, _ := ret[0].(*service8.WatchableService)
	return ret0
}

// ExternalController indicates an expected call of ExternalController.
func (mr *MockControllerServiceFactoryMockRecorder) ExternalController() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExternalController", reflect.TypeOf((*MockControllerServiceFactory)(nil).ExternalController))
}

// Flag mocks base method.
func (m *MockControllerServiceFactory) Flag() *service9.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Flag")
	ret0, _ := ret[0].(*service9.Service)
	return ret0
}

// Flag indicates an expected call of Flag.
func (mr *MockControllerServiceFactoryMockRecorder) Flag() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Flag", reflect.TypeOf((*MockControllerServiceFactory)(nil).Flag))
}

// Model mocks base method.
func (m *MockControllerServiceFactory) Model() *service11.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Model")
	ret0, _ := ret[0].(*service11.Service)
	return ret0
}

// Model indicates an expected call of Model.
func (mr *MockControllerServiceFactoryMockRecorder) Model() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Model", reflect.TypeOf((*MockControllerServiceFactory)(nil).Model))
}

// ModelDefaults mocks base method.
func (m *MockControllerServiceFactory) ModelDefaults() *service13.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModelDefaults")
	ret0, _ := ret[0].(*service13.Service)
	return ret0
}

// ModelDefaults indicates an expected call of ModelDefaults.
func (mr *MockControllerServiceFactoryMockRecorder) ModelDefaults() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModelDefaults", reflect.TypeOf((*MockControllerServiceFactory)(nil).ModelDefaults))
}

// SecretBackend mocks base method.
func (m *MockControllerServiceFactory) SecretBackend(arg0 string, arg1 service17.SecretProviderRegistry) *service17.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SecretBackend", arg0, arg1)
	ret0, _ := ret[0].(*service17.WatchableService)
	return ret0
}

// SecretBackend indicates an expected call of SecretBackend.
func (mr *MockControllerServiceFactoryMockRecorder) SecretBackend(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SecretBackend", reflect.TypeOf((*MockControllerServiceFactory)(nil).SecretBackend), arg0, arg1)
}

// Upgrade mocks base method.
func (m *MockControllerServiceFactory) Upgrade() *service20.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Upgrade")
	ret0, _ := ret[0].(*service20.WatchableService)
	return ret0
}

// Upgrade indicates an expected call of Upgrade.
func (mr *MockControllerServiceFactoryMockRecorder) Upgrade() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Upgrade", reflect.TypeOf((*MockControllerServiceFactory)(nil).Upgrade))
}

// MockModelServiceFactory is a mock of ModelServiceFactory interface.
type MockModelServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockModelServiceFactoryMockRecorder
}

// MockModelServiceFactoryMockRecorder is the mock recorder for MockModelServiceFactory.
type MockModelServiceFactoryMockRecorder struct {
	mock *MockModelServiceFactory
}

// NewMockModelServiceFactory creates a new mock instance.
func NewMockModelServiceFactory(ctrl *gomock.Controller) *MockModelServiceFactory {
	mock := &MockModelServiceFactory{ctrl: ctrl}
	mock.recorder = &MockModelServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockModelServiceFactory) EXPECT() *MockModelServiceFactoryMockRecorder {
	return m.recorder
}

// Annotation mocks base method.
func (m *MockModelServiceFactory) Annotation() *service0.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Annotation")
	ret0, _ := ret[0].(*service0.Service)
	return ret0
}

// Annotation indicates an expected call of Annotation.
func (mr *MockModelServiceFactoryMockRecorder) Annotation() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Annotation", reflect.TypeOf((*MockModelServiceFactory)(nil).Annotation))
}

// Application mocks base method.
func (m *MockModelServiceFactory) Application(arg0 storage.ProviderRegistry) *service1.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Application", arg0)
	ret0, _ := ret[0].(*service1.Service)
	return ret0
}

// Application indicates an expected call of Application.
func (mr *MockModelServiceFactoryMockRecorder) Application(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Application", reflect.TypeOf((*MockModelServiceFactory)(nil).Application), arg0)
}

// BlockDevice mocks base method.
func (m *MockModelServiceFactory) BlockDevice() *service3.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BlockDevice")
	ret0, _ := ret[0].(*service3.WatchableService)
	return ret0
}

// BlockDevice indicates an expected call of BlockDevice.
func (mr *MockModelServiceFactoryMockRecorder) BlockDevice() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BlockDevice", reflect.TypeOf((*MockModelServiceFactory)(nil).BlockDevice))
}

// Config mocks base method.
func (m *MockModelServiceFactory) Config(arg0 service12.ModelDefaultsProvider) *service12.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Config", arg0)
	ret0, _ := ret[0].(*service12.WatchableService)
	return ret0
}

// Config indicates an expected call of Config.
func (mr *MockModelServiceFactoryMockRecorder) Config(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Config", reflect.TypeOf((*MockModelServiceFactory)(nil).Config), arg0)
}

// Machine mocks base method.
func (m *MockModelServiceFactory) Machine() *service10.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Machine")
	ret0, _ := ret[0].(*service10.Service)
	return ret0
}

// Machine indicates an expected call of Machine.
func (mr *MockModelServiceFactoryMockRecorder) Machine() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Machine", reflect.TypeOf((*MockModelServiceFactory)(nil).Machine))
}

// ModelInfo mocks base method.
func (m *MockModelServiceFactory) ModelInfo() *service11.ModelService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModelInfo")
	ret0, _ := ret[0].(*service11.ModelService)
	return ret0
}

// ModelInfo indicates an expected call of ModelInfo.
func (mr *MockModelServiceFactoryMockRecorder) ModelInfo() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModelInfo", reflect.TypeOf((*MockModelServiceFactory)(nil).ModelInfo))
}

// Network mocks base method.
func (m *MockModelServiceFactory) Network() *service14.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Network")
	ret0, _ := ret[0].(*service14.Service)
	return ret0
}

// Network indicates an expected call of Network.
func (mr *MockModelServiceFactoryMockRecorder) Network() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Network", reflect.TypeOf((*MockModelServiceFactory)(nil).Network))
}

// ObjectStore mocks base method.
func (m *MockModelServiceFactory) ObjectStore() *service15.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ObjectStore")
	ret0, _ := ret[0].(*service15.WatchableService)
	return ret0
}

// ObjectStore indicates an expected call of ObjectStore.
func (mr *MockModelServiceFactoryMockRecorder) ObjectStore() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ObjectStore", reflect.TypeOf((*MockModelServiceFactory)(nil).ObjectStore))
}

// Secret mocks base method.
func (m *MockModelServiceFactory) Secret(arg0 service16.BackendAdminConfigGetter) *service16.SecretService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Secret", arg0)
	ret0, _ := ret[0].(*service16.SecretService)
	return ret0
}

// Secret indicates an expected call of Secret.
func (mr *MockModelServiceFactoryMockRecorder) Secret(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Secret", reflect.TypeOf((*MockModelServiceFactory)(nil).Secret), arg0)
}

// Storage mocks base method.
func (m *MockModelServiceFactory) Storage(arg0 storage.ProviderRegistry) *service18.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Storage", arg0)
	ret0, _ := ret[0].(*service18.Service)
	return ret0
}

// Storage indicates an expected call of Storage.
func (mr *MockModelServiceFactoryMockRecorder) Storage(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Storage", reflect.TypeOf((*MockModelServiceFactory)(nil).Storage), arg0)
}

// Unit mocks base method.
func (m *MockModelServiceFactory) Unit() *service19.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unit")
	ret0, _ := ret[0].(*service19.Service)
	return ret0
}

// Unit indicates an expected call of Unit.
func (mr *MockModelServiceFactoryMockRecorder) Unit() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unit", reflect.TypeOf((*MockModelServiceFactory)(nil).Unit))
}

// MockServiceFactory is a mock of ServiceFactory interface.
type MockServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockServiceFactoryMockRecorder
}

// MockServiceFactoryMockRecorder is the mock recorder for MockServiceFactory.
type MockServiceFactoryMockRecorder struct {
	mock *MockServiceFactory
}

// NewMockServiceFactory creates a new mock instance.
func NewMockServiceFactory(ctrl *gomock.Controller) *MockServiceFactory {
	mock := &MockServiceFactory{ctrl: ctrl}
	mock.recorder = &MockServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockServiceFactory) EXPECT() *MockServiceFactoryMockRecorder {
	return m.recorder
}

// Access mocks base method.
func (m *MockServiceFactory) Access() *service.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Access")
	ret0, _ := ret[0].(*service.Service)
	return ret0
}

// Access indicates an expected call of Access.
func (mr *MockServiceFactoryMockRecorder) Access() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Access", reflect.TypeOf((*MockServiceFactory)(nil).Access))
}

// AgentObjectStore mocks base method.
func (m *MockServiceFactory) AgentObjectStore() *service15.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AgentObjectStore")
	ret0, _ := ret[0].(*service15.WatchableService)
	return ret0
}

// AgentObjectStore indicates an expected call of AgentObjectStore.
func (mr *MockServiceFactoryMockRecorder) AgentObjectStore() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AgentObjectStore", reflect.TypeOf((*MockServiceFactory)(nil).AgentObjectStore))
}

// Annotation mocks base method.
func (m *MockServiceFactory) Annotation() *service0.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Annotation")
	ret0, _ := ret[0].(*service0.Service)
	return ret0
}

// Annotation indicates an expected call of Annotation.
func (mr *MockServiceFactoryMockRecorder) Annotation() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Annotation", reflect.TypeOf((*MockServiceFactory)(nil).Annotation))
}

// Application mocks base method.
func (m *MockServiceFactory) Application(arg0 storage.ProviderRegistry) *service1.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Application", arg0)
	ret0, _ := ret[0].(*service1.Service)
	return ret0
}

// Application indicates an expected call of Application.
func (mr *MockServiceFactoryMockRecorder) Application(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Application", reflect.TypeOf((*MockServiceFactory)(nil).Application), arg0)
}

// AutocertCache mocks base method.
func (m *MockServiceFactory) AutocertCache() *service2.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AutocertCache")
	ret0, _ := ret[0].(*service2.Service)
	return ret0
}

// AutocertCache indicates an expected call of AutocertCache.
func (mr *MockServiceFactoryMockRecorder) AutocertCache() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AutocertCache", reflect.TypeOf((*MockServiceFactory)(nil).AutocertCache))
}

// BlockDevice mocks base method.
func (m *MockServiceFactory) BlockDevice() *service3.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BlockDevice")
	ret0, _ := ret[0].(*service3.WatchableService)
	return ret0
}

// BlockDevice indicates an expected call of BlockDevice.
func (mr *MockServiceFactoryMockRecorder) BlockDevice() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BlockDevice", reflect.TypeOf((*MockServiceFactory)(nil).BlockDevice))
}

// Cloud mocks base method.
func (m *MockServiceFactory) Cloud() *service4.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Cloud")
	ret0, _ := ret[0].(*service4.WatchableService)
	return ret0
}

// Cloud indicates an expected call of Cloud.
func (mr *MockServiceFactoryMockRecorder) Cloud() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cloud", reflect.TypeOf((*MockServiceFactory)(nil).Cloud))
}

// Config mocks base method.
func (m *MockServiceFactory) Config(arg0 service12.ModelDefaultsProvider) *service12.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Config", arg0)
	ret0, _ := ret[0].(*service12.WatchableService)
	return ret0
}

// Config indicates an expected call of Config.
func (mr *MockServiceFactoryMockRecorder) Config(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Config", reflect.TypeOf((*MockServiceFactory)(nil).Config), arg0)
}

// ControllerConfig mocks base method.
func (m *MockServiceFactory) ControllerConfig() *service5.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ControllerConfig")
	ret0, _ := ret[0].(*service5.WatchableService)
	return ret0
}

// ControllerConfig indicates an expected call of ControllerConfig.
func (mr *MockServiceFactoryMockRecorder) ControllerConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ControllerConfig", reflect.TypeOf((*MockServiceFactory)(nil).ControllerConfig))
}

// ControllerNode mocks base method.
func (m *MockServiceFactory) ControllerNode() *service6.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ControllerNode")
	ret0, _ := ret[0].(*service6.Service)
	return ret0
}

// ControllerNode indicates an expected call of ControllerNode.
func (mr *MockServiceFactoryMockRecorder) ControllerNode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ControllerNode", reflect.TypeOf((*MockServiceFactory)(nil).ControllerNode))
}

// Credential mocks base method.
func (m *MockServiceFactory) Credential() *service7.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Credential")
	ret0, _ := ret[0].(*service7.WatchableService)
	return ret0
}

// Credential indicates an expected call of Credential.
func (mr *MockServiceFactoryMockRecorder) Credential() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Credential", reflect.TypeOf((*MockServiceFactory)(nil).Credential))
}

// ExternalController mocks base method.
func (m *MockServiceFactory) ExternalController() *service8.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExternalController")
	ret0, _ := ret[0].(*service8.WatchableService)
	return ret0
}

// ExternalController indicates an expected call of ExternalController.
func (mr *MockServiceFactoryMockRecorder) ExternalController() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExternalController", reflect.TypeOf((*MockServiceFactory)(nil).ExternalController))
}

// Flag mocks base method.
func (m *MockServiceFactory) Flag() *service9.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Flag")
	ret0, _ := ret[0].(*service9.Service)
	return ret0
}

// Flag indicates an expected call of Flag.
func (mr *MockServiceFactoryMockRecorder) Flag() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Flag", reflect.TypeOf((*MockServiceFactory)(nil).Flag))
}

// Machine mocks base method.
func (m *MockServiceFactory) Machine() *service10.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Machine")
	ret0, _ := ret[0].(*service10.Service)
	return ret0
}

// Machine indicates an expected call of Machine.
func (mr *MockServiceFactoryMockRecorder) Machine() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Machine", reflect.TypeOf((*MockServiceFactory)(nil).Machine))
}

// Model mocks base method.
func (m *MockServiceFactory) Model() *service11.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Model")
	ret0, _ := ret[0].(*service11.Service)
	return ret0
}

// Model indicates an expected call of Model.
func (mr *MockServiceFactoryMockRecorder) Model() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Model", reflect.TypeOf((*MockServiceFactory)(nil).Model))
}

// ModelDefaults mocks base method.
func (m *MockServiceFactory) ModelDefaults() *service13.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModelDefaults")
	ret0, _ := ret[0].(*service13.Service)
	return ret0
}

// ModelDefaults indicates an expected call of ModelDefaults.
func (mr *MockServiceFactoryMockRecorder) ModelDefaults() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModelDefaults", reflect.TypeOf((*MockServiceFactory)(nil).ModelDefaults))
}

// ModelInfo mocks base method.
func (m *MockServiceFactory) ModelInfo() *service11.ModelService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModelInfo")
	ret0, _ := ret[0].(*service11.ModelService)
	return ret0
}

// ModelInfo indicates an expected call of ModelInfo.
func (mr *MockServiceFactoryMockRecorder) ModelInfo() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModelInfo", reflect.TypeOf((*MockServiceFactory)(nil).ModelInfo))
}

// Network mocks base method.
func (m *MockServiceFactory) Network() *service14.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Network")
	ret0, _ := ret[0].(*service14.Service)
	return ret0
}

// Network indicates an expected call of Network.
func (mr *MockServiceFactoryMockRecorder) Network() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Network", reflect.TypeOf((*MockServiceFactory)(nil).Network))
}

// ObjectStore mocks base method.
func (m *MockServiceFactory) ObjectStore() *service15.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ObjectStore")
	ret0, _ := ret[0].(*service15.WatchableService)
	return ret0
}

// ObjectStore indicates an expected call of ObjectStore.
func (mr *MockServiceFactoryMockRecorder) ObjectStore() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ObjectStore", reflect.TypeOf((*MockServiceFactory)(nil).ObjectStore))
}

// Secret mocks base method.
func (m *MockServiceFactory) Secret(arg0 service16.BackendAdminConfigGetter) *service16.SecretService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Secret", arg0)
	ret0, _ := ret[0].(*service16.SecretService)
	return ret0
}

// Secret indicates an expected call of Secret.
func (mr *MockServiceFactoryMockRecorder) Secret(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Secret", reflect.TypeOf((*MockServiceFactory)(nil).Secret), arg0)
}

// SecretBackend mocks base method.
func (m *MockServiceFactory) SecretBackend(arg0 string, arg1 service17.SecretProviderRegistry) *service17.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SecretBackend", arg0, arg1)
	ret0, _ := ret[0].(*service17.WatchableService)
	return ret0
}

// SecretBackend indicates an expected call of SecretBackend.
func (mr *MockServiceFactoryMockRecorder) SecretBackend(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SecretBackend", reflect.TypeOf((*MockServiceFactory)(nil).SecretBackend), arg0, arg1)
}

// Storage mocks base method.
func (m *MockServiceFactory) Storage(arg0 storage.ProviderRegistry) *service18.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Storage", arg0)
	ret0, _ := ret[0].(*service18.Service)
	return ret0
}

// Storage indicates an expected call of Storage.
func (mr *MockServiceFactoryMockRecorder) Storage(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Storage", reflect.TypeOf((*MockServiceFactory)(nil).Storage), arg0)
}

// Unit mocks base method.
func (m *MockServiceFactory) Unit() *service19.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unit")
	ret0, _ := ret[0].(*service19.Service)
	return ret0
}

// Unit indicates an expected call of Unit.
func (mr *MockServiceFactoryMockRecorder) Unit() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unit", reflect.TypeOf((*MockServiceFactory)(nil).Unit))
}

// Upgrade mocks base method.
func (m *MockServiceFactory) Upgrade() *service20.WatchableService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Upgrade")
	ret0, _ := ret[0].(*service20.WatchableService)
	return ret0
}

// Upgrade indicates an expected call of Upgrade.
func (mr *MockServiceFactoryMockRecorder) Upgrade() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Upgrade", reflect.TypeOf((*MockServiceFactory)(nil).Upgrade))
}

// MockServiceFactoryGetter is a mock of ServiceFactoryGetter interface.
type MockServiceFactoryGetter struct {
	ctrl     *gomock.Controller
	recorder *MockServiceFactoryGetterMockRecorder
}

// MockServiceFactoryGetterMockRecorder is the mock recorder for MockServiceFactoryGetter.
type MockServiceFactoryGetterMockRecorder struct {
	mock *MockServiceFactoryGetter
}

// NewMockServiceFactoryGetter creates a new mock instance.
func NewMockServiceFactoryGetter(ctrl *gomock.Controller) *MockServiceFactoryGetter {
	mock := &MockServiceFactoryGetter{ctrl: ctrl}
	mock.recorder = &MockServiceFactoryGetterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockServiceFactoryGetter) EXPECT() *MockServiceFactoryGetterMockRecorder {
	return m.recorder
}

// FactoryForModel mocks base method.
func (m *MockServiceFactoryGetter) FactoryForModel(arg0 string) servicefactory.ServiceFactory {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FactoryForModel", arg0)
	ret0, _ := ret[0].(servicefactory.ServiceFactory)
	return ret0
}

// FactoryForModel indicates an expected call of FactoryForModel.
func (mr *MockServiceFactoryGetterMockRecorder) FactoryForModel(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FactoryForModel", reflect.TypeOf((*MockServiceFactoryGetter)(nil).FactoryForModel), arg0)
}
