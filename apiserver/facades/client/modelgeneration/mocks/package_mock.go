// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/apiserver/facades/client/modelgeneration (interfaces: State,Model,Generation,Application)
//
// Generated by this command:
//
//	mockgen -typed -package mocks -destination mocks/package_mock.go github.com/juju/juju/apiserver/facades/client/modelgeneration State,Model,Generation,Application
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	modelgeneration "github.com/juju/juju/apiserver/facades/client/modelgeneration"
	settings "github.com/juju/juju/core/settings"
	charm "github.com/juju/juju/internal/charm"
	names "github.com/juju/names/v5"
	gomock "go.uber.org/mock/gomock"
)

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

// Application mocks base method.
func (m *MockState) Application(arg0 string) (modelgeneration.Application, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Application", arg0)
	ret0, _ := ret[0].(modelgeneration.Application)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Application indicates an expected call of Application.
func (mr *MockStateMockRecorder) Application(arg0 any) *MockStateApplicationCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Application", reflect.TypeOf((*MockState)(nil).Application), arg0)
	return &MockStateApplicationCall{Call: call}
}

// MockStateApplicationCall wrap *gomock.Call
type MockStateApplicationCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockStateApplicationCall) Return(arg0 modelgeneration.Application, arg1 error) *MockStateApplicationCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockStateApplicationCall) Do(f func(string) (modelgeneration.Application, error)) *MockStateApplicationCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockStateApplicationCall) DoAndReturn(f func(string) (modelgeneration.Application, error)) *MockStateApplicationCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ControllerTag mocks base method.
func (m *MockState) ControllerTag() names.ControllerTag {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ControllerTag")
	ret0, _ := ret[0].(names.ControllerTag)
	return ret0
}

// ControllerTag indicates an expected call of ControllerTag.
func (mr *MockStateMockRecorder) ControllerTag() *MockStateControllerTagCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ControllerTag", reflect.TypeOf((*MockState)(nil).ControllerTag))
	return &MockStateControllerTagCall{Call: call}
}

// MockStateControllerTagCall wrap *gomock.Call
type MockStateControllerTagCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockStateControllerTagCall) Return(arg0 names.ControllerTag) *MockStateControllerTagCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockStateControllerTagCall) Do(f func() names.ControllerTag) *MockStateControllerTagCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockStateControllerTagCall) DoAndReturn(f func() names.ControllerTag) *MockStateControllerTagCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Model mocks base method.
func (m *MockState) Model() (modelgeneration.Model, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Model")
	ret0, _ := ret[0].(modelgeneration.Model)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Model indicates an expected call of Model.
func (mr *MockStateMockRecorder) Model() *MockStateModelCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Model", reflect.TypeOf((*MockState)(nil).Model))
	return &MockStateModelCall{Call: call}
}

// MockStateModelCall wrap *gomock.Call
type MockStateModelCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockStateModelCall) Return(arg0 modelgeneration.Model, arg1 error) *MockStateModelCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockStateModelCall) Do(f func() (modelgeneration.Model, error)) *MockStateModelCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockStateModelCall) DoAndReturn(f func() (modelgeneration.Model, error)) *MockStateModelCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// MockModel is a mock of Model interface.
type MockModel struct {
	ctrl     *gomock.Controller
	recorder *MockModelMockRecorder
}

// MockModelMockRecorder is the mock recorder for MockModel.
type MockModelMockRecorder struct {
	mock *MockModel
}

// NewMockModel creates a new mock instance.
func NewMockModel(ctrl *gomock.Controller) *MockModel {
	mock := &MockModel{ctrl: ctrl}
	mock.recorder = &MockModelMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockModel) EXPECT() *MockModelMockRecorder {
	return m.recorder
}

// AddBranch mocks base method.
func (m *MockModel) AddBranch(arg0, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddBranch", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddBranch indicates an expected call of AddBranch.
func (mr *MockModelMockRecorder) AddBranch(arg0, arg1 any) *MockModelAddBranchCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBranch", reflect.TypeOf((*MockModel)(nil).AddBranch), arg0, arg1)
	return &MockModelAddBranchCall{Call: call}
}

// MockModelAddBranchCall wrap *gomock.Call
type MockModelAddBranchCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockModelAddBranchCall) Return(arg0 error) *MockModelAddBranchCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockModelAddBranchCall) Do(f func(string, string) error) *MockModelAddBranchCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockModelAddBranchCall) DoAndReturn(f func(string, string) error) *MockModelAddBranchCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Branch mocks base method.
func (m *MockModel) Branch(arg0 string) (modelgeneration.Generation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Branch", arg0)
	ret0, _ := ret[0].(modelgeneration.Generation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Branch indicates an expected call of Branch.
func (mr *MockModelMockRecorder) Branch(arg0 any) *MockModelBranchCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Branch", reflect.TypeOf((*MockModel)(nil).Branch), arg0)
	return &MockModelBranchCall{Call: call}
}

// MockModelBranchCall wrap *gomock.Call
type MockModelBranchCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockModelBranchCall) Return(arg0 modelgeneration.Generation, arg1 error) *MockModelBranchCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockModelBranchCall) Do(f func(string) (modelgeneration.Generation, error)) *MockModelBranchCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockModelBranchCall) DoAndReturn(f func(string) (modelgeneration.Generation, error)) *MockModelBranchCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Branches mocks base method.
func (m *MockModel) Branches() ([]modelgeneration.Generation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Branches")
	ret0, _ := ret[0].([]modelgeneration.Generation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Branches indicates an expected call of Branches.
func (mr *MockModelMockRecorder) Branches() *MockModelBranchesCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Branches", reflect.TypeOf((*MockModel)(nil).Branches))
	return &MockModelBranchesCall{Call: call}
}

// MockModelBranchesCall wrap *gomock.Call
type MockModelBranchesCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockModelBranchesCall) Return(arg0 []modelgeneration.Generation, arg1 error) *MockModelBranchesCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockModelBranchesCall) Do(f func() ([]modelgeneration.Generation, error)) *MockModelBranchesCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockModelBranchesCall) DoAndReturn(f func() ([]modelgeneration.Generation, error)) *MockModelBranchesCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Generation mocks base method.
func (m *MockModel) Generation(arg0 int) (modelgeneration.Generation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Generation", arg0)
	ret0, _ := ret[0].(modelgeneration.Generation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Generation indicates an expected call of Generation.
func (mr *MockModelMockRecorder) Generation(arg0 any) *MockModelGenerationCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Generation", reflect.TypeOf((*MockModel)(nil).Generation), arg0)
	return &MockModelGenerationCall{Call: call}
}

// MockModelGenerationCall wrap *gomock.Call
type MockModelGenerationCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockModelGenerationCall) Return(arg0 modelgeneration.Generation, arg1 error) *MockModelGenerationCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockModelGenerationCall) Do(f func(int) (modelgeneration.Generation, error)) *MockModelGenerationCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockModelGenerationCall) DoAndReturn(f func(int) (modelgeneration.Generation, error)) *MockModelGenerationCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Generations mocks base method.
func (m *MockModel) Generations() ([]modelgeneration.Generation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Generations")
	ret0, _ := ret[0].([]modelgeneration.Generation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Generations indicates an expected call of Generations.
func (mr *MockModelMockRecorder) Generations() *MockModelGenerationsCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Generations", reflect.TypeOf((*MockModel)(nil).Generations))
	return &MockModelGenerationsCall{Call: call}
}

// MockModelGenerationsCall wrap *gomock.Call
type MockModelGenerationsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockModelGenerationsCall) Return(arg0 []modelgeneration.Generation, arg1 error) *MockModelGenerationsCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockModelGenerationsCall) Do(f func() ([]modelgeneration.Generation, error)) *MockModelGenerationsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockModelGenerationsCall) DoAndReturn(f func() ([]modelgeneration.Generation, error)) *MockModelGenerationsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ModelTag mocks base method.
func (m *MockModel) ModelTag() names.ModelTag {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModelTag")
	ret0, _ := ret[0].(names.ModelTag)
	return ret0
}

// ModelTag indicates an expected call of ModelTag.
func (mr *MockModelMockRecorder) ModelTag() *MockModelModelTagCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModelTag", reflect.TypeOf((*MockModel)(nil).ModelTag))
	return &MockModelModelTagCall{Call: call}
}

// MockModelModelTagCall wrap *gomock.Call
type MockModelModelTagCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockModelModelTagCall) Return(arg0 names.ModelTag) *MockModelModelTagCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockModelModelTagCall) Do(f func() names.ModelTag) *MockModelModelTagCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockModelModelTagCall) DoAndReturn(f func() names.ModelTag) *MockModelModelTagCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// MockGeneration is a mock of Generation interface.
type MockGeneration struct {
	ctrl     *gomock.Controller
	recorder *MockGenerationMockRecorder
}

// MockGenerationMockRecorder is the mock recorder for MockGeneration.
type MockGenerationMockRecorder struct {
	mock *MockGeneration
}

// NewMockGeneration creates a new mock instance.
func NewMockGeneration(ctrl *gomock.Controller) *MockGeneration {
	mock := &MockGeneration{ctrl: ctrl}
	mock.recorder = &MockGenerationMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockGeneration) EXPECT() *MockGenerationMockRecorder {
	return m.recorder
}

// Abort mocks base method.
func (m *MockGeneration) Abort(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Abort", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Abort indicates an expected call of Abort.
func (mr *MockGenerationMockRecorder) Abort(arg0 any) *MockGenerationAbortCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Abort", reflect.TypeOf((*MockGeneration)(nil).Abort), arg0)
	return &MockGenerationAbortCall{Call: call}
}

// MockGenerationAbortCall wrap *gomock.Call
type MockGenerationAbortCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationAbortCall) Return(arg0 error) *MockGenerationAbortCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationAbortCall) Do(f func(string) error) *MockGenerationAbortCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationAbortCall) DoAndReturn(f func(string) error) *MockGenerationAbortCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AssignAllUnits mocks base method.
func (m *MockGeneration) AssignAllUnits(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssignAllUnits", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AssignAllUnits indicates an expected call of AssignAllUnits.
func (mr *MockGenerationMockRecorder) AssignAllUnits(arg0 any) *MockGenerationAssignAllUnitsCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssignAllUnits", reflect.TypeOf((*MockGeneration)(nil).AssignAllUnits), arg0)
	return &MockGenerationAssignAllUnitsCall{Call: call}
}

// MockGenerationAssignAllUnitsCall wrap *gomock.Call
type MockGenerationAssignAllUnitsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationAssignAllUnitsCall) Return(arg0 error) *MockGenerationAssignAllUnitsCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationAssignAllUnitsCall) Do(f func(string) error) *MockGenerationAssignAllUnitsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationAssignAllUnitsCall) DoAndReturn(f func(string) error) *MockGenerationAssignAllUnitsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AssignUnit mocks base method.
func (m *MockGeneration) AssignUnit(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssignUnit", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AssignUnit indicates an expected call of AssignUnit.
func (mr *MockGenerationMockRecorder) AssignUnit(arg0 any) *MockGenerationAssignUnitCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssignUnit", reflect.TypeOf((*MockGeneration)(nil).AssignUnit), arg0)
	return &MockGenerationAssignUnitCall{Call: call}
}

// MockGenerationAssignUnitCall wrap *gomock.Call
type MockGenerationAssignUnitCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationAssignUnitCall) Return(arg0 error) *MockGenerationAssignUnitCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationAssignUnitCall) Do(f func(string) error) *MockGenerationAssignUnitCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationAssignUnitCall) DoAndReturn(f func(string) error) *MockGenerationAssignUnitCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AssignUnits mocks base method.
func (m *MockGeneration) AssignUnits(arg0 string, arg1 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssignUnits", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AssignUnits indicates an expected call of AssignUnits.
func (mr *MockGenerationMockRecorder) AssignUnits(arg0, arg1 any) *MockGenerationAssignUnitsCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssignUnits", reflect.TypeOf((*MockGeneration)(nil).AssignUnits), arg0, arg1)
	return &MockGenerationAssignUnitsCall{Call: call}
}

// MockGenerationAssignUnitsCall wrap *gomock.Call
type MockGenerationAssignUnitsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationAssignUnitsCall) Return(arg0 error) *MockGenerationAssignUnitsCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationAssignUnitsCall) Do(f func(string, int) error) *MockGenerationAssignUnitsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationAssignUnitsCall) DoAndReturn(f func(string, int) error) *MockGenerationAssignUnitsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AssignedUnits mocks base method.
func (m *MockGeneration) AssignedUnits() map[string][]string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssignedUnits")
	ret0, _ := ret[0].(map[string][]string)
	return ret0
}

// AssignedUnits indicates an expected call of AssignedUnits.
func (mr *MockGenerationMockRecorder) AssignedUnits() *MockGenerationAssignedUnitsCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssignedUnits", reflect.TypeOf((*MockGeneration)(nil).AssignedUnits))
	return &MockGenerationAssignedUnitsCall{Call: call}
}

// MockGenerationAssignedUnitsCall wrap *gomock.Call
type MockGenerationAssignedUnitsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationAssignedUnitsCall) Return(arg0 map[string][]string) *MockGenerationAssignedUnitsCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationAssignedUnitsCall) Do(f func() map[string][]string) *MockGenerationAssignedUnitsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationAssignedUnitsCall) DoAndReturn(f func() map[string][]string) *MockGenerationAssignedUnitsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// BranchName mocks base method.
func (m *MockGeneration) BranchName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BranchName")
	ret0, _ := ret[0].(string)
	return ret0
}

// BranchName indicates an expected call of BranchName.
func (mr *MockGenerationMockRecorder) BranchName() *MockGenerationBranchNameCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BranchName", reflect.TypeOf((*MockGeneration)(nil).BranchName))
	return &MockGenerationBranchNameCall{Call: call}
}

// MockGenerationBranchNameCall wrap *gomock.Call
type MockGenerationBranchNameCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationBranchNameCall) Return(arg0 string) *MockGenerationBranchNameCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationBranchNameCall) Do(f func() string) *MockGenerationBranchNameCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationBranchNameCall) DoAndReturn(f func() string) *MockGenerationBranchNameCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Commit mocks base method.
func (m *MockGeneration) Commit(arg0 string) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Commit", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Commit indicates an expected call of Commit.
func (mr *MockGenerationMockRecorder) Commit(arg0 any) *MockGenerationCommitCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Commit", reflect.TypeOf((*MockGeneration)(nil).Commit), arg0)
	return &MockGenerationCommitCall{Call: call}
}

// MockGenerationCommitCall wrap *gomock.Call
type MockGenerationCommitCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationCommitCall) Return(arg0 int, arg1 error) *MockGenerationCommitCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationCommitCall) Do(f func(string) (int, error)) *MockGenerationCommitCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationCommitCall) DoAndReturn(f func(string) (int, error)) *MockGenerationCommitCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Completed mocks base method.
func (m *MockGeneration) Completed() int64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Completed")
	ret0, _ := ret[0].(int64)
	return ret0
}

// Completed indicates an expected call of Completed.
func (mr *MockGenerationMockRecorder) Completed() *MockGenerationCompletedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Completed", reflect.TypeOf((*MockGeneration)(nil).Completed))
	return &MockGenerationCompletedCall{Call: call}
}

// MockGenerationCompletedCall wrap *gomock.Call
type MockGenerationCompletedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationCompletedCall) Return(arg0 int64) *MockGenerationCompletedCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationCompletedCall) Do(f func() int64) *MockGenerationCompletedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationCompletedCall) DoAndReturn(f func() int64) *MockGenerationCompletedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// CompletedBy mocks base method.
func (m *MockGeneration) CompletedBy() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CompletedBy")
	ret0, _ := ret[0].(string)
	return ret0
}

// CompletedBy indicates an expected call of CompletedBy.
func (mr *MockGenerationMockRecorder) CompletedBy() *MockGenerationCompletedByCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CompletedBy", reflect.TypeOf((*MockGeneration)(nil).CompletedBy))
	return &MockGenerationCompletedByCall{Call: call}
}

// MockGenerationCompletedByCall wrap *gomock.Call
type MockGenerationCompletedByCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationCompletedByCall) Return(arg0 string) *MockGenerationCompletedByCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationCompletedByCall) Do(f func() string) *MockGenerationCompletedByCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationCompletedByCall) DoAndReturn(f func() string) *MockGenerationCompletedByCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Config mocks base method.
func (m *MockGeneration) Config() map[string]settings.ItemChanges {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Config")
	ret0, _ := ret[0].(map[string]settings.ItemChanges)
	return ret0
}

// Config indicates an expected call of Config.
func (mr *MockGenerationMockRecorder) Config() *MockGenerationConfigCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Config", reflect.TypeOf((*MockGeneration)(nil).Config))
	return &MockGenerationConfigCall{Call: call}
}

// MockGenerationConfigCall wrap *gomock.Call
type MockGenerationConfigCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationConfigCall) Return(arg0 map[string]settings.ItemChanges) *MockGenerationConfigCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationConfigCall) Do(f func() map[string]settings.ItemChanges) *MockGenerationConfigCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationConfigCall) DoAndReturn(f func() map[string]settings.ItemChanges) *MockGenerationConfigCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Created mocks base method.
func (m *MockGeneration) Created() int64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Created")
	ret0, _ := ret[0].(int64)
	return ret0
}

// Created indicates an expected call of Created.
func (mr *MockGenerationMockRecorder) Created() *MockGenerationCreatedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Created", reflect.TypeOf((*MockGeneration)(nil).Created))
	return &MockGenerationCreatedCall{Call: call}
}

// MockGenerationCreatedCall wrap *gomock.Call
type MockGenerationCreatedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationCreatedCall) Return(arg0 int64) *MockGenerationCreatedCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationCreatedCall) Do(f func() int64) *MockGenerationCreatedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationCreatedCall) DoAndReturn(f func() int64) *MockGenerationCreatedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// CreatedBy mocks base method.
func (m *MockGeneration) CreatedBy() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatedBy")
	ret0, _ := ret[0].(string)
	return ret0
}

// CreatedBy indicates an expected call of CreatedBy.
func (mr *MockGenerationMockRecorder) CreatedBy() *MockGenerationCreatedByCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatedBy", reflect.TypeOf((*MockGeneration)(nil).CreatedBy))
	return &MockGenerationCreatedByCall{Call: call}
}

// MockGenerationCreatedByCall wrap *gomock.Call
type MockGenerationCreatedByCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationCreatedByCall) Return(arg0 string) *MockGenerationCreatedByCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationCreatedByCall) Do(f func() string) *MockGenerationCreatedByCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationCreatedByCall) DoAndReturn(f func() string) *MockGenerationCreatedByCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GenerationId mocks base method.
func (m *MockGeneration) GenerationId() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerationId")
	ret0, _ := ret[0].(int)
	return ret0
}

// GenerationId indicates an expected call of GenerationId.
func (mr *MockGenerationMockRecorder) GenerationId() *MockGenerationGenerationIdCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerationId", reflect.TypeOf((*MockGeneration)(nil).GenerationId))
	return &MockGenerationGenerationIdCall{Call: call}
}

// MockGenerationGenerationIdCall wrap *gomock.Call
type MockGenerationGenerationIdCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockGenerationGenerationIdCall) Return(arg0 int) *MockGenerationGenerationIdCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockGenerationGenerationIdCall) Do(f func() int) *MockGenerationGenerationIdCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockGenerationGenerationIdCall) DoAndReturn(f func() int) *MockGenerationGenerationIdCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// MockApplication is a mock of Application interface.
type MockApplication struct {
	ctrl     *gomock.Controller
	recorder *MockApplicationMockRecorder
}

// MockApplicationMockRecorder is the mock recorder for MockApplication.
type MockApplicationMockRecorder struct {
	mock *MockApplication
}

// NewMockApplication creates a new mock instance.
func NewMockApplication(ctrl *gomock.Controller) *MockApplication {
	mock := &MockApplication{ctrl: ctrl}
	mock.recorder = &MockApplicationMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockApplication) EXPECT() *MockApplicationMockRecorder {
	return m.recorder
}

// DefaultCharmConfig mocks base method.
func (m *MockApplication) DefaultCharmConfig() (charm.Settings, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DefaultCharmConfig")
	ret0, _ := ret[0].(charm.Settings)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DefaultCharmConfig indicates an expected call of DefaultCharmConfig.
func (mr *MockApplicationMockRecorder) DefaultCharmConfig() *MockApplicationDefaultCharmConfigCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DefaultCharmConfig", reflect.TypeOf((*MockApplication)(nil).DefaultCharmConfig))
	return &MockApplicationDefaultCharmConfigCall{Call: call}
}

// MockApplicationDefaultCharmConfigCall wrap *gomock.Call
type MockApplicationDefaultCharmConfigCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockApplicationDefaultCharmConfigCall) Return(arg0 charm.Settings, arg1 error) *MockApplicationDefaultCharmConfigCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockApplicationDefaultCharmConfigCall) Do(f func() (charm.Settings, error)) *MockApplicationDefaultCharmConfigCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockApplicationDefaultCharmConfigCall) DoAndReturn(f func() (charm.Settings, error)) *MockApplicationDefaultCharmConfigCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// UnitNames mocks base method.
func (m *MockApplication) UnitNames() ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnitNames")
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UnitNames indicates an expected call of UnitNames.
func (mr *MockApplicationMockRecorder) UnitNames() *MockApplicationUnitNamesCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnitNames", reflect.TypeOf((*MockApplication)(nil).UnitNames))
	return &MockApplicationUnitNamesCall{Call: call}
}

// MockApplicationUnitNamesCall wrap *gomock.Call
type MockApplicationUnitNamesCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockApplicationUnitNamesCall) Return(arg0 []string, arg1 error) *MockApplicationUnitNamesCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockApplicationUnitNamesCall) Do(f func() ([]string, error)) *MockApplicationUnitNamesCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockApplicationUnitNamesCall) DoAndReturn(f func() ([]string, error)) *MockApplicationUnitNamesCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
