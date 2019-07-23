package api

import (
	methods "github.com/vmware/govmomi/vim25/methods"
	time "time"
	context "context"
	soap "github.com/vmware/govmomi/vim25/soap"
	types "github.com/vmware/govmomi/vim25/types"
)

type Context interface {
	AbdicateDomOwnership(ctx context.Context, r soap.RoundTripper, req *types.AbdicateDomOwnership) (*types.AbdicateDomOwnershipResponse, error)
	AcknowledgeAlarm(ctx context.Context, r soap.RoundTripper, req *types.AcknowledgeAlarm) (*types.AcknowledgeAlarmResponse, error)
	AcquireCimServicesTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireCimServicesTicket) (*types.AcquireCimServicesTicketResponse, error)
	AcquireCloneTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireCloneTicket) (*types.AcquireCloneTicketResponse, error)
	AcquireCredentialsInGuest(ctx context.Context, r soap.RoundTripper, req *types.AcquireCredentialsInGuest) (*types.AcquireCredentialsInGuestResponse, error)
	AcquireGenericServiceTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireGenericServiceTicket) (*types.AcquireGenericServiceTicketResponse, error)
	AcquireLocalTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireLocalTicket) (*types.AcquireLocalTicketResponse, error)
	AcquireMksTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireMksTicket) (*types.AcquireMksTicketResponse, error)
	AcquireTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireTicket) (*types.AcquireTicketResponse, error)
	AddAuthorizationRole(ctx context.Context, r soap.RoundTripper, req *types.AddAuthorizationRole) (*types.AddAuthorizationRoleResponse, error)
	AddCustomFieldDef(ctx context.Context, r soap.RoundTripper, req *types.AddCustomFieldDef) (*types.AddCustomFieldDefResponse, error)
	AddDVPortgroup_Task(ctx context.Context, r soap.RoundTripper, req *types.AddDVPortgroup_Task) (*types.AddDVPortgroup_TaskResponse, error)
	AddDisks_Task(ctx context.Context, r soap.RoundTripper, req *types.AddDisks_Task) (*types.AddDisks_TaskResponse, error)
	AddFilter(ctx context.Context, r soap.RoundTripper, req *types.AddFilter) (*types.AddFilterResponse, error)
	AddFilterEntities(ctx context.Context, r soap.RoundTripper, req *types.AddFilterEntities) (*types.AddFilterEntitiesResponse, error)
	AddGuestAlias(ctx context.Context, r soap.RoundTripper, req *types.AddGuestAlias) (*types.AddGuestAliasResponse, error)
	AddHost_Task(ctx context.Context, r soap.RoundTripper, req *types.AddHost_Task) (*types.AddHost_TaskResponse, error)
	AddInternetScsiSendTargets(ctx context.Context, r soap.RoundTripper, req *types.AddInternetScsiSendTargets) (*types.AddInternetScsiSendTargetsResponse, error)
	AddInternetScsiStaticTargets(ctx context.Context, r soap.RoundTripper, req *types.AddInternetScsiStaticTargets) (*types.AddInternetScsiStaticTargetsResponse, error)
	AddKey(ctx context.Context, r soap.RoundTripper, req *types.AddKey) (*types.AddKeyResponse, error)
	AddKeys(ctx context.Context, r soap.RoundTripper, req *types.AddKeys) (*types.AddKeysResponse, error)
	AddLicense(ctx context.Context, r soap.RoundTripper, req *types.AddLicense) (*types.AddLicenseResponse, error)
	AddMonitoredEntities(ctx context.Context, r soap.RoundTripper, req *types.AddMonitoredEntities) (*types.AddMonitoredEntitiesResponse, error)
	AddNetworkResourcePool(ctx context.Context, r soap.RoundTripper, req *types.AddNetworkResourcePool) (*types.AddNetworkResourcePoolResponse, error)
	AddPortGroup(ctx context.Context, r soap.RoundTripper, req *types.AddPortGroup) (*types.AddPortGroupResponse, error)
	AddServiceConsoleVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.AddServiceConsoleVirtualNic) (*types.AddServiceConsoleVirtualNicResponse, error)
	AddStandaloneHost_Task(ctx context.Context, r soap.RoundTripper, req *types.AddStandaloneHost_Task) (*types.AddStandaloneHost_TaskResponse, error)
	AddVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.AddVirtualNic) (*types.AddVirtualNicResponse, error)
	AddVirtualSwitch(ctx context.Context, r soap.RoundTripper, req *types.AddVirtualSwitch) (*types.AddVirtualSwitchResponse, error)
	AllocateIpv4Address(ctx context.Context, r soap.RoundTripper, req *types.AllocateIpv4Address) (*types.AllocateIpv4AddressResponse, error)
	AllocateIpv6Address(ctx context.Context, r soap.RoundTripper, req *types.AllocateIpv6Address) (*types.AllocateIpv6AddressResponse, error)
	AnswerVM(ctx context.Context, r soap.RoundTripper, req *types.AnswerVM) (*types.AnswerVMResponse, error)
	ApplyEntitiesConfig_Task(ctx context.Context, r soap.RoundTripper, req *types.ApplyEntitiesConfig_Task) (*types.ApplyEntitiesConfig_TaskResponse, error)
	ApplyHostConfig_Task(ctx context.Context, r soap.RoundTripper, req *types.ApplyHostConfig_Task) (*types.ApplyHostConfig_TaskResponse, error)
	ApplyRecommendation(ctx context.Context, r soap.RoundTripper, req *types.ApplyRecommendation) (*types.ApplyRecommendationResponse, error)
	ApplyStorageDrsRecommendationToPod_Task(ctx context.Context, r soap.RoundTripper, req *types.ApplyStorageDrsRecommendationToPod_Task) (*types.ApplyStorageDrsRecommendationToPod_TaskResponse, error)
	ApplyStorageDrsRecommendation_Task(ctx context.Context, r soap.RoundTripper, req *types.ApplyStorageDrsRecommendation_Task) (*types.ApplyStorageDrsRecommendation_TaskResponse, error)
	AreAlarmActionsEnabled(ctx context.Context, r soap.RoundTripper, req *types.AreAlarmActionsEnabled) (*types.AreAlarmActionsEnabledResponse, error)
	AssignUserToGroup(ctx context.Context, r soap.RoundTripper, req *types.AssignUserToGroup) (*types.AssignUserToGroupResponse, error)
	AssociateProfile(ctx context.Context, r soap.RoundTripper, req *types.AssociateProfile) (*types.AssociateProfileResponse, error)
	AttachDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.AttachDisk_Task) (*types.AttachDisk_TaskResponse, error)
	AttachScsiLun(ctx context.Context, r soap.RoundTripper, req *types.AttachScsiLun) (*types.AttachScsiLunResponse, error)
	AttachScsiLunEx_Task(ctx context.Context, r soap.RoundTripper, req *types.AttachScsiLunEx_Task) (*types.AttachScsiLunEx_TaskResponse, error)
	AttachTagToVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.AttachTagToVStorageObject) (*types.AttachTagToVStorageObjectResponse, error)
	AttachVmfsExtent(ctx context.Context, r soap.RoundTripper, req *types.AttachVmfsExtent) (*types.AttachVmfsExtentResponse, error)
	AutoStartPowerOff(ctx context.Context, r soap.RoundTripper, req *types.AutoStartPowerOff) (*types.AutoStartPowerOffResponse, error)
	AutoStartPowerOn(ctx context.Context, r soap.RoundTripper, req *types.AutoStartPowerOn) (*types.AutoStartPowerOnResponse, error)
	BackupFirmwareConfiguration(ctx context.Context, r soap.RoundTripper, req *types.BackupFirmwareConfiguration) (*types.BackupFirmwareConfigurationResponse, error)
	BindVnic(ctx context.Context, r soap.RoundTripper, req *types.BindVnic) (*types.BindVnicResponse, error)
	BrowseDiagnosticLog(ctx context.Context, r soap.RoundTripper, req *types.BrowseDiagnosticLog) (*types.BrowseDiagnosticLogResponse, error)
	CanProvisionObjects(ctx context.Context, r soap.RoundTripper, req *types.CanProvisionObjects) (*types.CanProvisionObjectsResponse, error)
	CancelRecommendation(ctx context.Context, r soap.RoundTripper, req *types.CancelRecommendation) (*types.CancelRecommendationResponse, error)
	CancelRetrievePropertiesEx(ctx context.Context, r soap.RoundTripper, req *types.CancelRetrievePropertiesEx) (*types.CancelRetrievePropertiesExResponse, error)
	CancelStorageDrsRecommendation(ctx context.Context, r soap.RoundTripper, req *types.CancelStorageDrsRecommendation) (*types.CancelStorageDrsRecommendationResponse, error)
	CancelTask(ctx context.Context, r soap.RoundTripper, req *types.CancelTask) (*types.CancelTaskResponse, error)
	CancelWaitForUpdates(ctx context.Context, r soap.RoundTripper, req *types.CancelWaitForUpdates) (*types.CancelWaitForUpdatesResponse, error)
	CertMgrRefreshCACertificatesAndCRLs_Task(ctx context.Context, r soap.RoundTripper, req *types.CertMgrRefreshCACertificatesAndCRLs_Task) (*types.CertMgrRefreshCACertificatesAndCRLs_TaskResponse, error)
	CertMgrRefreshCertificates_Task(ctx context.Context, r soap.RoundTripper, req *types.CertMgrRefreshCertificates_Task) (*types.CertMgrRefreshCertificates_TaskResponse, error)
	CertMgrRevokeCertificates_Task(ctx context.Context, r soap.RoundTripper, req *types.CertMgrRevokeCertificates_Task) (*types.CertMgrRevokeCertificates_TaskResponse, error)
	ChangeAccessMode(ctx context.Context, r soap.RoundTripper, req *types.ChangeAccessMode) (*types.ChangeAccessModeResponse, error)
	ChangeFileAttributesInGuest(ctx context.Context, r soap.RoundTripper, req *types.ChangeFileAttributesInGuest) (*types.ChangeFileAttributesInGuestResponse, error)
	ChangeLockdownMode(ctx context.Context, r soap.RoundTripper, req *types.ChangeLockdownMode) (*types.ChangeLockdownModeResponse, error)
	ChangeNFSUserPassword(ctx context.Context, r soap.RoundTripper, req *types.ChangeNFSUserPassword) (*types.ChangeNFSUserPasswordResponse, error)
	ChangeOwner(ctx context.Context, r soap.RoundTripper, req *types.ChangeOwner) (*types.ChangeOwnerResponse, error)
	CheckAddHostEvc_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckAddHostEvc_Task) (*types.CheckAddHostEvc_TaskResponse, error)
	CheckAnswerFileStatus_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckAnswerFileStatus_Task) (*types.CheckAnswerFileStatus_TaskResponse, error)
	CheckCompatibility_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckCompatibility_Task) (*types.CheckCompatibility_TaskResponse, error)
	CheckCompliance_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckCompliance_Task) (*types.CheckCompliance_TaskResponse, error)
	CheckConfigureEvcMode_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckConfigureEvcMode_Task) (*types.CheckConfigureEvcMode_TaskResponse, error)
	CheckCustomizationResources(ctx context.Context, r soap.RoundTripper, req *types.CheckCustomizationResources) (*types.CheckCustomizationResourcesResponse, error)
	CheckCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.CheckCustomizationSpec) (*types.CheckCustomizationSpecResponse, error)
	CheckForUpdates(ctx context.Context, r soap.RoundTripper, req *types.CheckForUpdates) (*types.CheckForUpdatesResponse, error)
	CheckHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckHostPatch_Task) (*types.CheckHostPatch_TaskResponse, error)
	CheckLicenseFeature(ctx context.Context, r soap.RoundTripper, req *types.CheckLicenseFeature) (*types.CheckLicenseFeatureResponse, error)
	CheckMigrate_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckMigrate_Task) (*types.CheckMigrate_TaskResponse, error)
	CheckProfileCompliance_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckProfileCompliance_Task) (*types.CheckProfileCompliance_TaskResponse, error)
	CheckRelocate_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckRelocate_Task) (*types.CheckRelocate_TaskResponse, error)
	ClearComplianceStatus(ctx context.Context, r soap.RoundTripper, req *types.ClearComplianceStatus) (*types.ClearComplianceStatusResponse, error)
	ClearNFSUser(ctx context.Context, r soap.RoundTripper, req *types.ClearNFSUser) (*types.ClearNFSUserResponse, error)
	ClearSystemEventLog(ctx context.Context, r soap.RoundTripper, req *types.ClearSystemEventLog) (*types.ClearSystemEventLogResponse, error)
	CloneSession(ctx context.Context, r soap.RoundTripper, req *types.CloneSession) (*types.CloneSessionResponse, error)
	CloneVApp_Task(ctx context.Context, r soap.RoundTripper, req *types.CloneVApp_Task) (*types.CloneVApp_TaskResponse, error)
	CloneVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CloneVM_Task) (*types.CloneVM_TaskResponse, error)
	CloneVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.CloneVStorageObject_Task) (*types.CloneVStorageObject_TaskResponse, error)
	CloseInventoryViewFolder(ctx context.Context, r soap.RoundTripper, req *types.CloseInventoryViewFolder) (*types.CloseInventoryViewFolderResponse, error)
	ClusterEnterMaintenanceMode(ctx context.Context, r soap.RoundTripper, req *types.ClusterEnterMaintenanceMode) (*types.ClusterEnterMaintenanceModeResponse, error)
	ComputeDiskPartitionInfo(ctx context.Context, r soap.RoundTripper, req *types.ComputeDiskPartitionInfo) (*types.ComputeDiskPartitionInfoResponse, error)
	ComputeDiskPartitionInfoForResize(ctx context.Context, r soap.RoundTripper, req *types.ComputeDiskPartitionInfoForResize) (*types.ComputeDiskPartitionInfoForResizeResponse, error)
	ConfigureCryptoKey(ctx context.Context, r soap.RoundTripper, req *types.ConfigureCryptoKey) (*types.ConfigureCryptoKeyResponse, error)
	ConfigureDatastoreIORM_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureDatastoreIORM_Task) (*types.ConfigureDatastoreIORM_TaskResponse, error)
	ConfigureDatastorePrincipal(ctx context.Context, r soap.RoundTripper, req *types.ConfigureDatastorePrincipal) (*types.ConfigureDatastorePrincipalResponse, error)
	ConfigureEvcMode_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureEvcMode_Task) (*types.ConfigureEvcMode_TaskResponse, error)
	ConfigureHostCache_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureHostCache_Task) (*types.ConfigureHostCache_TaskResponse, error)
	ConfigureLicenseSource(ctx context.Context, r soap.RoundTripper, req *types.ConfigureLicenseSource) (*types.ConfigureLicenseSourceResponse, error)
	ConfigurePowerPolicy(ctx context.Context, r soap.RoundTripper, req *types.ConfigurePowerPolicy) (*types.ConfigurePowerPolicyResponse, error)
	ConfigureStorageDrsForPod_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureStorageDrsForPod_Task) (*types.ConfigureStorageDrsForPod_TaskResponse, error)
	ConfigureVFlashResourceEx_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureVFlashResourceEx_Task) (*types.ConfigureVFlashResourceEx_TaskResponse, error)
	ConsolidateVMDisks_Task(ctx context.Context, r soap.RoundTripper, req *types.ConsolidateVMDisks_Task) (*types.ConsolidateVMDisks_TaskResponse, error)
	ContinueRetrievePropertiesEx(ctx context.Context, r soap.RoundTripper, req *types.ContinueRetrievePropertiesEx) (*types.ContinueRetrievePropertiesExResponse, error)
	ConvertNamespacePathToUuidPath(ctx context.Context, r soap.RoundTripper, req *types.ConvertNamespacePathToUuidPath) (*types.ConvertNamespacePathToUuidPathResponse, error)
	CopyDatastoreFile_Task(ctx context.Context, r soap.RoundTripper, req *types.CopyDatastoreFile_Task) (*types.CopyDatastoreFile_TaskResponse, error)
	CopyVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.CopyVirtualDisk_Task) (*types.CopyVirtualDisk_TaskResponse, error)
	CreateAlarm(ctx context.Context, r soap.RoundTripper, req *types.CreateAlarm) (*types.CreateAlarmResponse, error)
	CreateChildVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateChildVM_Task) (*types.CreateChildVM_TaskResponse, error)
	CreateCluster(ctx context.Context, r soap.RoundTripper, req *types.CreateCluster) (*types.CreateClusterResponse, error)
	CreateClusterEx(ctx context.Context, r soap.RoundTripper, req *types.CreateClusterEx) (*types.CreateClusterExResponse, error)
	CreateCollectorForEvents(ctx context.Context, r soap.RoundTripper, req *types.CreateCollectorForEvents) (*types.CreateCollectorForEventsResponse, error)
	CreateCollectorForTasks(ctx context.Context, r soap.RoundTripper, req *types.CreateCollectorForTasks) (*types.CreateCollectorForTasksResponse, error)
	CreateContainerView(ctx context.Context, r soap.RoundTripper, req *types.CreateContainerView) (*types.CreateContainerViewResponse, error)
	CreateCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.CreateCustomizationSpec) (*types.CreateCustomizationSpecResponse, error)
	CreateDVPortgroup_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateDVPortgroup_Task) (*types.CreateDVPortgroup_TaskResponse, error)
	CreateDVS_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateDVS_Task) (*types.CreateDVS_TaskResponse, error)
	CreateDatacenter(ctx context.Context, r soap.RoundTripper, req *types.CreateDatacenter) (*types.CreateDatacenterResponse, error)
	CreateDefaultProfile(ctx context.Context, r soap.RoundTripper, req *types.CreateDefaultProfile) (*types.CreateDefaultProfileResponse, error)
	CreateDescriptor(ctx context.Context, r soap.RoundTripper, req *types.CreateDescriptor) (*types.CreateDescriptorResponse, error)
	CreateDiagnosticPartition(ctx context.Context, r soap.RoundTripper, req *types.CreateDiagnosticPartition) (*types.CreateDiagnosticPartitionResponse, error)
	CreateDirectory(ctx context.Context, r soap.RoundTripper, req *types.CreateDirectory) (*types.CreateDirectoryResponse, error)
	CreateDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateDisk_Task) (*types.CreateDisk_TaskResponse, error)
	CreateFilter(ctx context.Context, r soap.RoundTripper, req *types.CreateFilter) (*types.CreateFilterResponse, error)
	CreateFolder(ctx context.Context, r soap.RoundTripper, req *types.CreateFolder) (*types.CreateFolderResponse, error)
	CreateGroup(ctx context.Context, r soap.RoundTripper, req *types.CreateGroup) (*types.CreateGroupResponse, error)
	CreateImportSpec(ctx context.Context, r soap.RoundTripper, req *types.CreateImportSpec) (*types.CreateImportSpecResponse, error)
	CreateInventoryView(ctx context.Context, r soap.RoundTripper, req *types.CreateInventoryView) (*types.CreateInventoryViewResponse, error)
	CreateIpPool(ctx context.Context, r soap.RoundTripper, req *types.CreateIpPool) (*types.CreateIpPoolResponse, error)
	CreateListView(ctx context.Context, r soap.RoundTripper, req *types.CreateListView) (*types.CreateListViewResponse, error)
	CreateListViewFromView(ctx context.Context, r soap.RoundTripper, req *types.CreateListViewFromView) (*types.CreateListViewFromViewResponse, error)
	CreateLocalDatastore(ctx context.Context, r soap.RoundTripper, req *types.CreateLocalDatastore) (*types.CreateLocalDatastoreResponse, error)
	CreateNasDatastore(ctx context.Context, r soap.RoundTripper, req *types.CreateNasDatastore) (*types.CreateNasDatastoreResponse, error)
	CreateObjectScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.CreateObjectScheduledTask) (*types.CreateObjectScheduledTaskResponse, error)
	CreatePerfInterval(ctx context.Context, r soap.RoundTripper, req *types.CreatePerfInterval) (*types.CreatePerfIntervalResponse, error)
	CreateProfile(ctx context.Context, r soap.RoundTripper, req *types.CreateProfile) (*types.CreateProfileResponse, error)
	CreatePropertyCollector(ctx context.Context, r soap.RoundTripper, req *types.CreatePropertyCollector) (*types.CreatePropertyCollectorResponse, error)
	CreateRegistryKeyInGuest(ctx context.Context, r soap.RoundTripper, req *types.CreateRegistryKeyInGuest) (*types.CreateRegistryKeyInGuestResponse, error)
	CreateResourcePool(ctx context.Context, r soap.RoundTripper, req *types.CreateResourcePool) (*types.CreateResourcePoolResponse, error)
	CreateScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.CreateScheduledTask) (*types.CreateScheduledTaskResponse, error)
	CreateScreenshot_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateScreenshot_Task) (*types.CreateScreenshot_TaskResponse, error)
	CreateSecondaryVMEx_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateSecondaryVMEx_Task) (*types.CreateSecondaryVMEx_TaskResponse, error)
	CreateSecondaryVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateSecondaryVM_Task) (*types.CreateSecondaryVM_TaskResponse, error)
	CreateSnapshotEx_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateSnapshotEx_Task) (*types.CreateSnapshotEx_TaskResponse, error)
	CreateSnapshot_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateSnapshot_Task) (*types.CreateSnapshot_TaskResponse, error)
	CreateStoragePod(ctx context.Context, r soap.RoundTripper, req *types.CreateStoragePod) (*types.CreateStoragePodResponse, error)
	CreateTask(ctx context.Context, r soap.RoundTripper, req *types.CreateTask) (*types.CreateTaskResponse, error)
	CreateTemporaryDirectoryInGuest(ctx context.Context, r soap.RoundTripper, req *types.CreateTemporaryDirectoryInGuest) (*types.CreateTemporaryDirectoryInGuestResponse, error)
	CreateTemporaryFileInGuest(ctx context.Context, r soap.RoundTripper, req *types.CreateTemporaryFileInGuest) (*types.CreateTemporaryFileInGuestResponse, error)
	CreateUser(ctx context.Context, r soap.RoundTripper, req *types.CreateUser) (*types.CreateUserResponse, error)
	CreateVApp(ctx context.Context, r soap.RoundTripper, req *types.CreateVApp) (*types.CreateVAppResponse, error)
	CreateVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateVM_Task) (*types.CreateVM_TaskResponse, error)
	CreateVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateVirtualDisk_Task) (*types.CreateVirtualDisk_TaskResponse, error)
	CreateVmfsDatastore(ctx context.Context, r soap.RoundTripper, req *types.CreateVmfsDatastore) (*types.CreateVmfsDatastoreResponse, error)
	CreateVvolDatastore(ctx context.Context, r soap.RoundTripper, req *types.CreateVvolDatastore) (*types.CreateVvolDatastoreResponse, error)
	CurrentTime(ctx context.Context, r soap.RoundTripper, req *types.CurrentTime) (*types.CurrentTimeResponse, error)
	CustomizationSpecItemToXml(ctx context.Context, r soap.RoundTripper, req *types.CustomizationSpecItemToXml) (*types.CustomizationSpecItemToXmlResponse, error)
	CustomizeVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CustomizeVM_Task) (*types.CustomizeVM_TaskResponse, error)
	DVPortgroupRollback_Task(ctx context.Context, r soap.RoundTripper, req *types.DVPortgroupRollback_Task) (*types.DVPortgroupRollback_TaskResponse, error)
	DVSManagerExportEntity_Task(ctx context.Context, r soap.RoundTripper, req *types.DVSManagerExportEntity_Task) (*types.DVSManagerExportEntity_TaskResponse, error)
	DVSManagerImportEntity_Task(ctx context.Context, r soap.RoundTripper, req *types.DVSManagerImportEntity_Task) (*types.DVSManagerImportEntity_TaskResponse, error)
	DVSManagerLookupDvPortGroup(ctx context.Context, r soap.RoundTripper, req *types.DVSManagerLookupDvPortGroup) (*types.DVSManagerLookupDvPortGroupResponse, error)
	DVSRollback_Task(ctx context.Context, r soap.RoundTripper, req *types.DVSRollback_Task) (*types.DVSRollback_TaskResponse, error)
	DatastoreEnterMaintenanceMode(ctx context.Context, r soap.RoundTripper, req *types.DatastoreEnterMaintenanceMode) (*types.DatastoreEnterMaintenanceModeResponse, error)
	DatastoreExitMaintenanceMode_Task(ctx context.Context, r soap.RoundTripper, req *types.DatastoreExitMaintenanceMode_Task) (*types.DatastoreExitMaintenanceMode_TaskResponse, error)
	DecodeLicense(ctx context.Context, r soap.RoundTripper, req *types.DecodeLicense) (*types.DecodeLicenseResponse, error)
	DefragmentAllDisks(ctx context.Context, r soap.RoundTripper, req *types.DefragmentAllDisks) (*types.DefragmentAllDisksResponse, error)
	DefragmentVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.DefragmentVirtualDisk_Task) (*types.DefragmentVirtualDisk_TaskResponse, error)
	DeleteCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.DeleteCustomizationSpec) (*types.DeleteCustomizationSpecResponse, error)
	DeleteDatastoreFile_Task(ctx context.Context, r soap.RoundTripper, req *types.DeleteDatastoreFile_Task) (*types.DeleteDatastoreFile_TaskResponse, error)
	DeleteDirectory(ctx context.Context, r soap.RoundTripper, req *types.DeleteDirectory) (*types.DeleteDirectoryResponse, error)
	DeleteDirectoryInGuest(ctx context.Context, r soap.RoundTripper, req *types.DeleteDirectoryInGuest) (*types.DeleteDirectoryInGuestResponse, error)
	DeleteFile(ctx context.Context, r soap.RoundTripper, req *types.DeleteFile) (*types.DeleteFileResponse, error)
	DeleteFileInGuest(ctx context.Context, r soap.RoundTripper, req *types.DeleteFileInGuest) (*types.DeleteFileInGuestResponse, error)
	DeleteHostSpecification(ctx context.Context, r soap.RoundTripper, req *types.DeleteHostSpecification) (*types.DeleteHostSpecificationResponse, error)
	DeleteHostSubSpecification(ctx context.Context, r soap.RoundTripper, req *types.DeleteHostSubSpecification) (*types.DeleteHostSubSpecificationResponse, error)
	DeleteRegistryKeyInGuest(ctx context.Context, r soap.RoundTripper, req *types.DeleteRegistryKeyInGuest) (*types.DeleteRegistryKeyInGuestResponse, error)
	DeleteRegistryValueInGuest(ctx context.Context, r soap.RoundTripper, req *types.DeleteRegistryValueInGuest) (*types.DeleteRegistryValueInGuestResponse, error)
	DeleteScsiLunState(ctx context.Context, r soap.RoundTripper, req *types.DeleteScsiLunState) (*types.DeleteScsiLunStateResponse, error)
	DeleteVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.DeleteVStorageObject_Task) (*types.DeleteVStorageObject_TaskResponse, error)
	DeleteVffsVolumeState(ctx context.Context, r soap.RoundTripper, req *types.DeleteVffsVolumeState) (*types.DeleteVffsVolumeStateResponse, error)
	DeleteVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.DeleteVirtualDisk_Task) (*types.DeleteVirtualDisk_TaskResponse, error)
	DeleteVmfsVolumeState(ctx context.Context, r soap.RoundTripper, req *types.DeleteVmfsVolumeState) (*types.DeleteVmfsVolumeStateResponse, error)
	DeleteVsanObjects(ctx context.Context, r soap.RoundTripper, req *types.DeleteVsanObjects) (*types.DeleteVsanObjectsResponse, error)
	DeselectVnic(ctx context.Context, r soap.RoundTripper, req *types.DeselectVnic) (*types.DeselectVnicResponse, error)
	DeselectVnicForNicType(ctx context.Context, r soap.RoundTripper, req *types.DeselectVnicForNicType) (*types.DeselectVnicForNicTypeResponse, error)
	DestroyChildren(ctx context.Context, r soap.RoundTripper, req *types.DestroyChildren) (*types.DestroyChildrenResponse, error)
	DestroyCollector(ctx context.Context, r soap.RoundTripper, req *types.DestroyCollector) (*types.DestroyCollectorResponse, error)
	DestroyDatastore(ctx context.Context, r soap.RoundTripper, req *types.DestroyDatastore) (*types.DestroyDatastoreResponse, error)
	DestroyIpPool(ctx context.Context, r soap.RoundTripper, req *types.DestroyIpPool) (*types.DestroyIpPoolResponse, error)
	DestroyNetwork(ctx context.Context, r soap.RoundTripper, req *types.DestroyNetwork) (*types.DestroyNetworkResponse, error)
	DestroyProfile(ctx context.Context, r soap.RoundTripper, req *types.DestroyProfile) (*types.DestroyProfileResponse, error)
	DestroyPropertyCollector(ctx context.Context, r soap.RoundTripper, req *types.DestroyPropertyCollector) (*types.DestroyPropertyCollectorResponse, error)
	DestroyPropertyFilter(ctx context.Context, r soap.RoundTripper, req *types.DestroyPropertyFilter) (*types.DestroyPropertyFilterResponse, error)
	DestroyVffs(ctx context.Context, r soap.RoundTripper, req *types.DestroyVffs) (*types.DestroyVffsResponse, error)
	DestroyView(ctx context.Context, r soap.RoundTripper, req *types.DestroyView) (*types.DestroyViewResponse, error)
	Destroy_Task(ctx context.Context, r soap.RoundTripper, req *types.Destroy_Task) (*types.Destroy_TaskResponse, error)
	DetachDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.DetachDisk_Task) (*types.DetachDisk_TaskResponse, error)
	DetachScsiLun(ctx context.Context, r soap.RoundTripper, req *types.DetachScsiLun) (*types.DetachScsiLunResponse, error)
	DetachScsiLunEx_Task(ctx context.Context, r soap.RoundTripper, req *types.DetachScsiLunEx_Task) (*types.DetachScsiLunEx_TaskResponse, error)
	DetachTagFromVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.DetachTagFromVStorageObject) (*types.DetachTagFromVStorageObjectResponse, error)
	DisableEvcMode_Task(ctx context.Context, r soap.RoundTripper, req *types.DisableEvcMode_Task) (*types.DisableEvcMode_TaskResponse, error)
	DisableFeature(ctx context.Context, r soap.RoundTripper, req *types.DisableFeature) (*types.DisableFeatureResponse, error)
	DisableHyperThreading(ctx context.Context, r soap.RoundTripper, req *types.DisableHyperThreading) (*types.DisableHyperThreadingResponse, error)
	DisableMultipathPath(ctx context.Context, r soap.RoundTripper, req *types.DisableMultipathPath) (*types.DisableMultipathPathResponse, error)
	DisableRuleset(ctx context.Context, r soap.RoundTripper, req *types.DisableRuleset) (*types.DisableRulesetResponse, error)
	DisableSecondaryVM_Task(ctx context.Context, r soap.RoundTripper, req *types.DisableSecondaryVM_Task) (*types.DisableSecondaryVM_TaskResponse, error)
	DisableSmartCardAuthentication(ctx context.Context, r soap.RoundTripper, req *types.DisableSmartCardAuthentication) (*types.DisableSmartCardAuthenticationResponse, error)
	DisconnectHost_Task(ctx context.Context, r soap.RoundTripper, req *types.DisconnectHost_Task) (*types.DisconnectHost_TaskResponse, error)
	DiscoverFcoeHbas(ctx context.Context, r soap.RoundTripper, req *types.DiscoverFcoeHbas) (*types.DiscoverFcoeHbasResponse, error)
	DissociateProfile(ctx context.Context, r soap.RoundTripper, req *types.DissociateProfile) (*types.DissociateProfileResponse, error)
	DoesCustomizationSpecExist(ctx context.Context, r soap.RoundTripper, req *types.DoesCustomizationSpecExist) (*types.DoesCustomizationSpecExistResponse, error)
	DuplicateCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.DuplicateCustomizationSpec) (*types.DuplicateCustomizationSpecResponse, error)
	DvsReconfigureVmVnicNetworkResourcePool_Task(ctx context.Context, r soap.RoundTripper, req *types.DvsReconfigureVmVnicNetworkResourcePool_Task) (*types.DvsReconfigureVmVnicNetworkResourcePool_TaskResponse, error)
	EagerZeroVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.EagerZeroVirtualDisk_Task) (*types.EagerZeroVirtualDisk_TaskResponse, error)
	EnableAlarmActions(ctx context.Context, r soap.RoundTripper, req *types.EnableAlarmActions) (*types.EnableAlarmActionsResponse, error)
	EnableCrypto(ctx context.Context, r soap.RoundTripper, req *types.EnableCrypto) (*types.EnableCryptoResponse, error)
	EnableFeature(ctx context.Context, r soap.RoundTripper, req *types.EnableFeature) (*types.EnableFeatureResponse, error)
	EnableHyperThreading(ctx context.Context, r soap.RoundTripper, req *types.EnableHyperThreading) (*types.EnableHyperThreadingResponse, error)
	EnableMultipathPath(ctx context.Context, r soap.RoundTripper, req *types.EnableMultipathPath) (*types.EnableMultipathPathResponse, error)
	EnableNetworkResourceManagement(ctx context.Context, r soap.RoundTripper, req *types.EnableNetworkResourceManagement) (*types.EnableNetworkResourceManagementResponse, error)
	EnableRuleset(ctx context.Context, r soap.RoundTripper, req *types.EnableRuleset) (*types.EnableRulesetResponse, error)
	EnableSecondaryVM_Task(ctx context.Context, r soap.RoundTripper, req *types.EnableSecondaryVM_Task) (*types.EnableSecondaryVM_TaskResponse, error)
	EnableSmartCardAuthentication(ctx context.Context, r soap.RoundTripper, req *types.EnableSmartCardAuthentication) (*types.EnableSmartCardAuthenticationResponse, error)
	EnterLockdownMode(ctx context.Context, r soap.RoundTripper, req *types.EnterLockdownMode) (*types.EnterLockdownModeResponse, error)
	EnterMaintenanceMode_Task(ctx context.Context, r soap.RoundTripper, req *types.EnterMaintenanceMode_Task) (*types.EnterMaintenanceMode_TaskResponse, error)
	EstimateDatabaseSize(ctx context.Context, r soap.RoundTripper, req *types.EstimateDatabaseSize) (*types.EstimateDatabaseSizeResponse, error)
	EstimateStorageForConsolidateSnapshots_Task(ctx context.Context, r soap.RoundTripper, req *types.EstimateStorageForConsolidateSnapshots_Task) (*types.EstimateStorageForConsolidateSnapshots_TaskResponse, error)
	EsxAgentHostManagerUpdateConfig(ctx context.Context, r soap.RoundTripper, req *types.EsxAgentHostManagerUpdateConfig) (*types.EsxAgentHostManagerUpdateConfigResponse, error)
	EvacuateVsanNode_Task(ctx context.Context, r soap.RoundTripper, req *types.EvacuateVsanNode_Task) (*types.EvacuateVsanNode_TaskResponse, error)
	EvcManager(ctx context.Context, r soap.RoundTripper, req *types.EvcManager) (*types.EvcManagerResponse, error)
	ExecuteHostProfile(ctx context.Context, r soap.RoundTripper, req *types.ExecuteHostProfile) (*types.ExecuteHostProfileResponse, error)
	ExecuteSimpleCommand(ctx context.Context, r soap.RoundTripper, req *types.ExecuteSimpleCommand) (*types.ExecuteSimpleCommandResponse, error)
	ExitLockdownMode(ctx context.Context, r soap.RoundTripper, req *types.ExitLockdownMode) (*types.ExitLockdownModeResponse, error)
	ExitMaintenanceMode_Task(ctx context.Context, r soap.RoundTripper, req *types.ExitMaintenanceMode_Task) (*types.ExitMaintenanceMode_TaskResponse, error)
	ExpandVmfsDatastore(ctx context.Context, r soap.RoundTripper, req *types.ExpandVmfsDatastore) (*types.ExpandVmfsDatastoreResponse, error)
	ExpandVmfsExtent(ctx context.Context, r soap.RoundTripper, req *types.ExpandVmfsExtent) (*types.ExpandVmfsExtentResponse, error)
	ExportAnswerFile_Task(ctx context.Context, r soap.RoundTripper, req *types.ExportAnswerFile_Task) (*types.ExportAnswerFile_TaskResponse, error)
	ExportProfile(ctx context.Context, r soap.RoundTripper, req *types.ExportProfile) (*types.ExportProfileResponse, error)
	ExportSnapshot(ctx context.Context, r soap.RoundTripper, req *types.ExportSnapshot) (*types.ExportSnapshotResponse, error)
	ExportVApp(ctx context.Context, r soap.RoundTripper, req *types.ExportVApp) (*types.ExportVAppResponse, error)
	ExportVm(ctx context.Context, r soap.RoundTripper, req *types.ExportVm) (*types.ExportVmResponse, error)
	ExtendDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.ExtendDisk_Task) (*types.ExtendDisk_TaskResponse, error)
	ExtendVffs(ctx context.Context, r soap.RoundTripper, req *types.ExtendVffs) (*types.ExtendVffsResponse, error)
	ExtendVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.ExtendVirtualDisk_Task) (*types.ExtendVirtualDisk_TaskResponse, error)
	ExtendVmfsDatastore(ctx context.Context, r soap.RoundTripper, req *types.ExtendVmfsDatastore) (*types.ExtendVmfsDatastoreResponse, error)
	ExtractOvfEnvironment(ctx context.Context, r soap.RoundTripper, req *types.ExtractOvfEnvironment) (*types.ExtractOvfEnvironmentResponse, error)
	FetchDVPortKeys(ctx context.Context, r soap.RoundTripper, req *types.FetchDVPortKeys) (*types.FetchDVPortKeysResponse, error)
	FetchDVPorts(ctx context.Context, r soap.RoundTripper, req *types.FetchDVPorts) (*types.FetchDVPortsResponse, error)
	FetchSystemEventLog(ctx context.Context, r soap.RoundTripper, req *types.FetchSystemEventLog) (*types.FetchSystemEventLogResponse, error)
	FetchUserPrivilegeOnEntities(ctx context.Context, r soap.RoundTripper, req *types.FetchUserPrivilegeOnEntities) (*types.FetchUserPrivilegeOnEntitiesResponse, error)
	FindAllByDnsName(ctx context.Context, r soap.RoundTripper, req *types.FindAllByDnsName) (*types.FindAllByDnsNameResponse, error)
	FindAllByIp(ctx context.Context, r soap.RoundTripper, req *types.FindAllByIp) (*types.FindAllByIpResponse, error)
	FindAllByUuid(ctx context.Context, r soap.RoundTripper, req *types.FindAllByUuid) (*types.FindAllByUuidResponse, error)
	FindAssociatedProfile(ctx context.Context, r soap.RoundTripper, req *types.FindAssociatedProfile) (*types.FindAssociatedProfileResponse, error)
	FindByDatastorePath(ctx context.Context, r soap.RoundTripper, req *types.FindByDatastorePath) (*types.FindByDatastorePathResponse, error)
	FindByDnsName(ctx context.Context, r soap.RoundTripper, req *types.FindByDnsName) (*types.FindByDnsNameResponse, error)
	FindByInventoryPath(ctx context.Context, r soap.RoundTripper, req *types.FindByInventoryPath) (*types.FindByInventoryPathResponse, error)
	FindByIp(ctx context.Context, r soap.RoundTripper, req *types.FindByIp) (*types.FindByIpResponse, error)
	FindByUuid(ctx context.Context, r soap.RoundTripper, req *types.FindByUuid) (*types.FindByUuidResponse, error)
	FindChild(ctx context.Context, r soap.RoundTripper, req *types.FindChild) (*types.FindChildResponse, error)
	FindExtension(ctx context.Context, r soap.RoundTripper, req *types.FindExtension) (*types.FindExtensionResponse, error)
	FindRulesForVm(ctx context.Context, r soap.RoundTripper, req *types.FindRulesForVm) (*types.FindRulesForVmResponse, error)
	FormatVffs(ctx context.Context, r soap.RoundTripper, req *types.FormatVffs) (*types.FormatVffsResponse, error)
	FormatVmfs(ctx context.Context, r soap.RoundTripper, req *types.FormatVmfs) (*types.FormatVmfsResponse, error)
	GenerateCertificateSigningRequest(ctx context.Context, r soap.RoundTripper, req *types.GenerateCertificateSigningRequest) (*types.GenerateCertificateSigningRequestResponse, error)
	GenerateCertificateSigningRequestByDn(ctx context.Context, r soap.RoundTripper, req *types.GenerateCertificateSigningRequestByDn) (*types.GenerateCertificateSigningRequestByDnResponse, error)
	GenerateClientCsr(ctx context.Context, r soap.RoundTripper, req *types.GenerateClientCsr) (*types.GenerateClientCsrResponse, error)
	GenerateConfigTaskList(ctx context.Context, r soap.RoundTripper, req *types.GenerateConfigTaskList) (*types.GenerateConfigTaskListResponse, error)
	GenerateHostConfigTaskSpec_Task(ctx context.Context, r soap.RoundTripper, req *types.GenerateHostConfigTaskSpec_Task) (*types.GenerateHostConfigTaskSpec_TaskResponse, error)
	GenerateHostProfileTaskList_Task(ctx context.Context, r soap.RoundTripper, req *types.GenerateHostProfileTaskList_Task) (*types.GenerateHostProfileTaskList_TaskResponse, error)
	GenerateKey(ctx context.Context, r soap.RoundTripper, req *types.GenerateKey) (*types.GenerateKeyResponse, error)
	GenerateLogBundles_Task(ctx context.Context, r soap.RoundTripper, req *types.GenerateLogBundles_Task) (*types.GenerateLogBundles_TaskResponse, error)
	GenerateSelfSignedClientCert(ctx context.Context, r soap.RoundTripper, req *types.GenerateSelfSignedClientCert) (*types.GenerateSelfSignedClientCertResponse, error)
	GetAlarm(ctx context.Context, r soap.RoundTripper, req *types.GetAlarm) (*types.GetAlarmResponse, error)
	GetAlarmState(ctx context.Context, r soap.RoundTripper, req *types.GetAlarmState) (*types.GetAlarmStateResponse, error)
	GetCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.GetCustomizationSpec) (*types.GetCustomizationSpecResponse, error)
	GetPublicKey(ctx context.Context, r soap.RoundTripper, req *types.GetPublicKey) (*types.GetPublicKeyResponse, error)
	GetResourceUsage(ctx context.Context, r soap.RoundTripper, req *types.GetResourceUsage) (*types.GetResourceUsageResponse, error)
	GetVchaClusterHealth(ctx context.Context, r soap.RoundTripper, req *types.GetVchaClusterHealth) (*types.GetVchaClusterHealthResponse, error)
	GetVsanObjExtAttrs(ctx context.Context, r soap.RoundTripper, req *types.GetVsanObjExtAttrs) (*types.GetVsanObjExtAttrsResponse, error)
	HasMonitoredEntity(ctx context.Context, r soap.RoundTripper, req *types.HasMonitoredEntity) (*types.HasMonitoredEntityResponse, error)
	HasPrivilegeOnEntities(ctx context.Context, r soap.RoundTripper, req *types.HasPrivilegeOnEntities) (*types.HasPrivilegeOnEntitiesResponse, error)
	HasPrivilegeOnEntity(ctx context.Context, r soap.RoundTripper, req *types.HasPrivilegeOnEntity) (*types.HasPrivilegeOnEntityResponse, error)
	HasProvider(ctx context.Context, r soap.RoundTripper, req *types.HasProvider) (*types.HasProviderResponse, error)
	HasUserPrivilegeOnEntities(ctx context.Context, r soap.RoundTripper, req *types.HasUserPrivilegeOnEntities) (*types.HasUserPrivilegeOnEntitiesResponse, error)
	HostCloneVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.HostCloneVStorageObject_Task) (*types.HostCloneVStorageObject_TaskResponse, error)
	HostConfigVFlashCache(ctx context.Context, r soap.RoundTripper, req *types.HostConfigVFlashCache) (*types.HostConfigVFlashCacheResponse, error)
	HostConfigureVFlashResource(ctx context.Context, r soap.RoundTripper, req *types.HostConfigureVFlashResource) (*types.HostConfigureVFlashResourceResponse, error)
	HostCreateDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.HostCreateDisk_Task) (*types.HostCreateDisk_TaskResponse, error)
	HostDeleteVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.HostDeleteVStorageObject_Task) (*types.HostDeleteVStorageObject_TaskResponse, error)
	HostExtendDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.HostExtendDisk_Task) (*types.HostExtendDisk_TaskResponse, error)
	HostGetVFlashModuleDefaultConfig(ctx context.Context, r soap.RoundTripper, req *types.HostGetVFlashModuleDefaultConfig) (*types.HostGetVFlashModuleDefaultConfigResponse, error)
	HostImageConfigGetAcceptance(ctx context.Context, r soap.RoundTripper, req *types.HostImageConfigGetAcceptance) (*types.HostImageConfigGetAcceptanceResponse, error)
	HostImageConfigGetProfile(ctx context.Context, r soap.RoundTripper, req *types.HostImageConfigGetProfile) (*types.HostImageConfigGetProfileResponse, error)
	HostInflateDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.HostInflateDisk_Task) (*types.HostInflateDisk_TaskResponse, error)
	HostListVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.HostListVStorageObject) (*types.HostListVStorageObjectResponse, error)
	HostReconcileDatastoreInventory_Task(ctx context.Context, r soap.RoundTripper, req *types.HostReconcileDatastoreInventory_Task) (*types.HostReconcileDatastoreInventory_TaskResponse, error)
	HostRegisterDisk(ctx context.Context, r soap.RoundTripper, req *types.HostRegisterDisk) (*types.HostRegisterDiskResponse, error)
	HostRelocateVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.HostRelocateVStorageObject_Task) (*types.HostRelocateVStorageObject_TaskResponse, error)
	HostRemoveVFlashResource(ctx context.Context, r soap.RoundTripper, req *types.HostRemoveVFlashResource) (*types.HostRemoveVFlashResourceResponse, error)
	HostRenameVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.HostRenameVStorageObject) (*types.HostRenameVStorageObjectResponse, error)
	HostRetrieveVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.HostRetrieveVStorageObject) (*types.HostRetrieveVStorageObjectResponse, error)
	HostRetrieveVStorageObjectState(ctx context.Context, r soap.RoundTripper, req *types.HostRetrieveVStorageObjectState) (*types.HostRetrieveVStorageObjectStateResponse, error)
	HostScheduleReconcileDatastoreInventory(ctx context.Context, r soap.RoundTripper, req *types.HostScheduleReconcileDatastoreInventory) (*types.HostScheduleReconcileDatastoreInventoryResponse, error)
	HostSpecGetUpdatedHosts(ctx context.Context, r soap.RoundTripper, req *types.HostSpecGetUpdatedHosts) (*types.HostSpecGetUpdatedHostsResponse, error)
	HttpNfcLeaseAbort(ctx context.Context, r soap.RoundTripper, req *types.HttpNfcLeaseAbort) (*types.HttpNfcLeaseAbortResponse, error)
	HttpNfcLeaseComplete(ctx context.Context, r soap.RoundTripper, req *types.HttpNfcLeaseComplete) (*types.HttpNfcLeaseCompleteResponse, error)
	HttpNfcLeaseGetManifest(ctx context.Context, r soap.RoundTripper, req *types.HttpNfcLeaseGetManifest) (*types.HttpNfcLeaseGetManifestResponse, error)
	HttpNfcLeaseProgress(ctx context.Context, r soap.RoundTripper, req *types.HttpNfcLeaseProgress) (*types.HttpNfcLeaseProgressResponse, error)
	ImpersonateUser(ctx context.Context, r soap.RoundTripper, req *types.ImpersonateUser) (*types.ImpersonateUserResponse, error)
	ImportCertificateForCAM_Task(ctx context.Context, r soap.RoundTripper, req *types.ImportCertificateForCAM_Task) (*types.ImportCertificateForCAM_TaskResponse, error)
	ImportUnmanagedSnapshot(ctx context.Context, r soap.RoundTripper, req *types.ImportUnmanagedSnapshot) (*types.ImportUnmanagedSnapshotResponse, error)
	ImportVApp(ctx context.Context, r soap.RoundTripper, req *types.ImportVApp) (*types.ImportVAppResponse, error)
	InflateDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.InflateDisk_Task) (*types.InflateDisk_TaskResponse, error)
	InflateVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.InflateVirtualDisk_Task) (*types.InflateVirtualDisk_TaskResponse, error)
	InitializeDisks_Task(ctx context.Context, r soap.RoundTripper, req *types.InitializeDisks_Task) (*types.InitializeDisks_TaskResponse, error)
	InitiateFileTransferFromGuest(ctx context.Context, r soap.RoundTripper, req *types.InitiateFileTransferFromGuest) (*types.InitiateFileTransferFromGuestResponse, error)
	InitiateFileTransferToGuest(ctx context.Context, r soap.RoundTripper, req *types.InitiateFileTransferToGuest) (*types.InitiateFileTransferToGuestResponse, error)
	InstallHostPatchV2_Task(ctx context.Context, r soap.RoundTripper, req *types.InstallHostPatchV2_Task) (*types.InstallHostPatchV2_TaskResponse, error)
	InstallHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.InstallHostPatch_Task) (*types.InstallHostPatch_TaskResponse, error)
	InstallIoFilter_Task(ctx context.Context, r soap.RoundTripper, req *types.InstallIoFilter_Task) (*types.InstallIoFilter_TaskResponse, error)
	InstallServerCertificate(ctx context.Context, r soap.RoundTripper, req *types.InstallServerCertificate) (*types.InstallServerCertificateResponse, error)
	InstallSmartCardTrustAnchor(ctx context.Context, r soap.RoundTripper, req *types.InstallSmartCardTrustAnchor) (*types.InstallSmartCardTrustAnchorResponse, error)
	IsSharedGraphicsActive(ctx context.Context, r soap.RoundTripper, req *types.IsSharedGraphicsActive) (*types.IsSharedGraphicsActiveResponse, error)
	JoinDomainWithCAM_Task(ctx context.Context, r soap.RoundTripper, req *types.JoinDomainWithCAM_Task) (*types.JoinDomainWithCAM_TaskResponse, error)
	JoinDomain_Task(ctx context.Context, r soap.RoundTripper, req *types.JoinDomain_Task) (*types.JoinDomain_TaskResponse, error)
	LeaveCurrentDomain_Task(ctx context.Context, r soap.RoundTripper, req *types.LeaveCurrentDomain_Task) (*types.LeaveCurrentDomain_TaskResponse, error)
	ListCACertificateRevocationLists(ctx context.Context, r soap.RoundTripper, req *types.ListCACertificateRevocationLists) (*types.ListCACertificateRevocationListsResponse, error)
	ListCACertificates(ctx context.Context, r soap.RoundTripper, req *types.ListCACertificates) (*types.ListCACertificatesResponse, error)
	ListFilesInGuest(ctx context.Context, r soap.RoundTripper, req *types.ListFilesInGuest) (*types.ListFilesInGuestResponse, error)
	ListGuestAliases(ctx context.Context, r soap.RoundTripper, req *types.ListGuestAliases) (*types.ListGuestAliasesResponse, error)
	ListGuestMappedAliases(ctx context.Context, r soap.RoundTripper, req *types.ListGuestMappedAliases) (*types.ListGuestMappedAliasesResponse, error)
	ListKeys(ctx context.Context, r soap.RoundTripper, req *types.ListKeys) (*types.ListKeysResponse, error)
	ListKmipServers(ctx context.Context, r soap.RoundTripper, req *types.ListKmipServers) (*types.ListKmipServersResponse, error)
	ListProcessesInGuest(ctx context.Context, r soap.RoundTripper, req *types.ListProcessesInGuest) (*types.ListProcessesInGuestResponse, error)
	ListRegistryKeysInGuest(ctx context.Context, r soap.RoundTripper, req *types.ListRegistryKeysInGuest) (*types.ListRegistryKeysInGuestResponse, error)
	ListRegistryValuesInGuest(ctx context.Context, r soap.RoundTripper, req *types.ListRegistryValuesInGuest) (*types.ListRegistryValuesInGuestResponse, error)
	ListSmartCardTrustAnchors(ctx context.Context, r soap.RoundTripper, req *types.ListSmartCardTrustAnchors) (*types.ListSmartCardTrustAnchorsResponse, error)
	ListTagsAttachedToVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.ListTagsAttachedToVStorageObject) (*types.ListTagsAttachedToVStorageObjectResponse, error)
	ListVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.ListVStorageObject) (*types.ListVStorageObjectResponse, error)
	ListVStorageObjectsAttachedToTag(ctx context.Context, r soap.RoundTripper, req *types.ListVStorageObjectsAttachedToTag) (*types.ListVStorageObjectsAttachedToTagResponse, error)
	LogUserEvent(ctx context.Context, r soap.RoundTripper, req *types.LogUserEvent) (*types.LogUserEventResponse, error)
	Login(ctx context.Context, r soap.RoundTripper, req *types.Login) (*types.LoginResponse, error)
	LoginBySSPI(ctx context.Context, r soap.RoundTripper, req *types.LoginBySSPI) (*types.LoginBySSPIResponse, error)
	LoginByToken(ctx context.Context, r soap.RoundTripper, req *types.LoginByToken) (*types.LoginByTokenResponse, error)
	LoginExtensionByCertificate(ctx context.Context, r soap.RoundTripper, req *types.LoginExtensionByCertificate) (*types.LoginExtensionByCertificateResponse, error)
	LoginExtensionBySubjectName(ctx context.Context, r soap.RoundTripper, req *types.LoginExtensionBySubjectName) (*types.LoginExtensionBySubjectNameResponse, error)
	Logout(ctx context.Context, r soap.RoundTripper, req *types.Logout) (*types.LogoutResponse, error)
	LookupDvPortGroup(ctx context.Context, r soap.RoundTripper, req *types.LookupDvPortGroup) (*types.LookupDvPortGroupResponse, error)
	LookupVmOverheadMemory(ctx context.Context, r soap.RoundTripper, req *types.LookupVmOverheadMemory) (*types.LookupVmOverheadMemoryResponse, error)
	MakeDirectory(ctx context.Context, r soap.RoundTripper, req *types.MakeDirectory) (*types.MakeDirectoryResponse, error)
	MakeDirectoryInGuest(ctx context.Context, r soap.RoundTripper, req *types.MakeDirectoryInGuest) (*types.MakeDirectoryInGuestResponse, error)
	MakePrimaryVM_Task(ctx context.Context, r soap.RoundTripper, req *types.MakePrimaryVM_Task) (*types.MakePrimaryVM_TaskResponse, error)
	MarkAsLocal_Task(ctx context.Context, r soap.RoundTripper, req *types.MarkAsLocal_Task) (*types.MarkAsLocal_TaskResponse, error)
	MarkAsNonLocal_Task(ctx context.Context, r soap.RoundTripper, req *types.MarkAsNonLocal_Task) (*types.MarkAsNonLocal_TaskResponse, error)
	MarkAsNonSsd_Task(ctx context.Context, r soap.RoundTripper, req *types.MarkAsNonSsd_Task) (*types.MarkAsNonSsd_TaskResponse, error)
	MarkAsSsd_Task(ctx context.Context, r soap.RoundTripper, req *types.MarkAsSsd_Task) (*types.MarkAsSsd_TaskResponse, error)
	MarkAsTemplate(ctx context.Context, r soap.RoundTripper, req *types.MarkAsTemplate) (*types.MarkAsTemplateResponse, error)
	MarkAsVirtualMachine(ctx context.Context, r soap.RoundTripper, req *types.MarkAsVirtualMachine) (*types.MarkAsVirtualMachineResponse, error)
	MarkDefault(ctx context.Context, r soap.RoundTripper, req *types.MarkDefault) (*types.MarkDefaultResponse, error)
	MarkForRemoval(ctx context.Context, r soap.RoundTripper, req *types.MarkForRemoval) (*types.MarkForRemovalResponse, error)
	MergeDvs_Task(ctx context.Context, r soap.RoundTripper, req *types.MergeDvs_Task) (*types.MergeDvs_TaskResponse, error)
	MergePermissions(ctx context.Context, r soap.RoundTripper, req *types.MergePermissions) (*types.MergePermissionsResponse, error)
	MigrateVM_Task(ctx context.Context, r soap.RoundTripper, req *types.MigrateVM_Task) (*types.MigrateVM_TaskResponse, error)
	ModifyListView(ctx context.Context, r soap.RoundTripper, req *types.ModifyListView) (*types.ModifyListViewResponse, error)
	MountToolsInstaller(ctx context.Context, r soap.RoundTripper, req *types.MountToolsInstaller) (*types.MountToolsInstallerResponse, error)
	MountVffsVolume(ctx context.Context, r soap.RoundTripper, req *types.MountVffsVolume) (*types.MountVffsVolumeResponse, error)
	MountVmfsVolume(ctx context.Context, r soap.RoundTripper, req *types.MountVmfsVolume) (*types.MountVmfsVolumeResponse, error)
	MountVmfsVolumeEx_Task(ctx context.Context, r soap.RoundTripper, req *types.MountVmfsVolumeEx_Task) (*types.MountVmfsVolumeEx_TaskResponse, error)
	MoveDVPort_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveDVPort_Task) (*types.MoveDVPort_TaskResponse, error)
	MoveDatastoreFile_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveDatastoreFile_Task) (*types.MoveDatastoreFile_TaskResponse, error)
	MoveDirectoryInGuest(ctx context.Context, r soap.RoundTripper, req *types.MoveDirectoryInGuest) (*types.MoveDirectoryInGuestResponse, error)
	MoveFileInGuest(ctx context.Context, r soap.RoundTripper, req *types.MoveFileInGuest) (*types.MoveFileInGuestResponse, error)
	MoveHostInto_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveHostInto_Task) (*types.MoveHostInto_TaskResponse, error)
	MoveIntoFolder_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveIntoFolder_Task) (*types.MoveIntoFolder_TaskResponse, error)
	MoveIntoResourcePool(ctx context.Context, r soap.RoundTripper, req *types.MoveIntoResourcePool) (*types.MoveIntoResourcePoolResponse, error)
	MoveInto_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveInto_Task) (*types.MoveInto_TaskResponse, error)
	MoveVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveVirtualDisk_Task) (*types.MoveVirtualDisk_TaskResponse, error)
	OpenInventoryViewFolder(ctx context.Context, r soap.RoundTripper, req *types.OpenInventoryViewFolder) (*types.OpenInventoryViewFolderResponse, error)
	OverwriteCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.OverwriteCustomizationSpec) (*types.OverwriteCustomizationSpecResponse, error)
	ParseDescriptor(ctx context.Context, r soap.RoundTripper, req *types.ParseDescriptor) (*types.ParseDescriptorResponse, error)
	PerformDvsProductSpecOperation_Task(ctx context.Context, r soap.RoundTripper, req *types.PerformDvsProductSpecOperation_Task) (*types.PerformDvsProductSpecOperation_TaskResponse, error)
	PerformVsanUpgradePreflightCheck(ctx context.Context, r soap.RoundTripper, req *types.PerformVsanUpgradePreflightCheck) (*types.PerformVsanUpgradePreflightCheckResponse, error)
	PerformVsanUpgrade_Task(ctx context.Context, r soap.RoundTripper, req *types.PerformVsanUpgrade_Task) (*types.PerformVsanUpgrade_TaskResponse, error)
	PlaceVm(ctx context.Context, r soap.RoundTripper, req *types.PlaceVm) (*types.PlaceVmResponse, error)
	PostEvent(ctx context.Context, r soap.RoundTripper, req *types.PostEvent) (*types.PostEventResponse, error)
	PostHealthUpdates(ctx context.Context, r soap.RoundTripper, req *types.PostHealthUpdates) (*types.PostHealthUpdatesResponse, error)
	PowerDownHostToStandBy_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerDownHostToStandBy_Task) (*types.PowerDownHostToStandBy_TaskResponse, error)
	PowerOffVApp_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOffVApp_Task) (*types.PowerOffVApp_TaskResponse, error)
	PowerOffVM_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOffVM_Task) (*types.PowerOffVM_TaskResponse, error)
	PowerOnMultiVM_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOnMultiVM_Task) (*types.PowerOnMultiVM_TaskResponse, error)
	PowerOnVApp_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOnVApp_Task) (*types.PowerOnVApp_TaskResponse, error)
	PowerOnVM_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOnVM_Task) (*types.PowerOnVM_TaskResponse, error)
	PowerUpHostFromStandBy_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerUpHostFromStandBy_Task) (*types.PowerUpHostFromStandBy_TaskResponse, error)
	PrepareCrypto(ctx context.Context, r soap.RoundTripper, req *types.PrepareCrypto) (*types.PrepareCryptoResponse, error)
	PromoteDisks_Task(ctx context.Context, r soap.RoundTripper, req *types.PromoteDisks_Task) (*types.PromoteDisks_TaskResponse, error)
	PutUsbScanCodes(ctx context.Context, r soap.RoundTripper, req *types.PutUsbScanCodes) (*types.PutUsbScanCodesResponse, error)
	QueryAnswerFileStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryAnswerFileStatus) (*types.QueryAnswerFileStatusResponse, error)
	QueryAssignedLicenses(ctx context.Context, r soap.RoundTripper, req *types.QueryAssignedLicenses) (*types.QueryAssignedLicensesResponse, error)
	QueryAvailableDisksForVmfs(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailableDisksForVmfs) (*types.QueryAvailableDisksForVmfsResponse, error)
	QueryAvailableDvsSpec(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailableDvsSpec) (*types.QueryAvailableDvsSpecResponse, error)
	QueryAvailablePartition(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailablePartition) (*types.QueryAvailablePartitionResponse, error)
	QueryAvailablePerfMetric(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailablePerfMetric) (*types.QueryAvailablePerfMetricResponse, error)
	QueryAvailableSsds(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailableSsds) (*types.QueryAvailableSsdsResponse, error)
	QueryAvailableTimeZones(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailableTimeZones) (*types.QueryAvailableTimeZonesResponse, error)
	QueryBootDevices(ctx context.Context, r soap.RoundTripper, req *types.QueryBootDevices) (*types.QueryBootDevicesResponse, error)
	QueryBoundVnics(ctx context.Context, r soap.RoundTripper, req *types.QueryBoundVnics) (*types.QueryBoundVnicsResponse, error)
	QueryCandidateNics(ctx context.Context, r soap.RoundTripper, req *types.QueryCandidateNics) (*types.QueryCandidateNicsResponse, error)
	QueryChangedDiskAreas(ctx context.Context, r soap.RoundTripper, req *types.QueryChangedDiskAreas) (*types.QueryChangedDiskAreasResponse, error)
	QueryCmmds(ctx context.Context, r soap.RoundTripper, req *types.QueryCmmds) (*types.QueryCmmdsResponse, error)
	QueryCompatibleHostForExistingDvs(ctx context.Context, r soap.RoundTripper, req *types.QueryCompatibleHostForExistingDvs) (*types.QueryCompatibleHostForExistingDvsResponse, error)
	QueryCompatibleHostForNewDvs(ctx context.Context, r soap.RoundTripper, req *types.QueryCompatibleHostForNewDvs) (*types.QueryCompatibleHostForNewDvsResponse, error)
	QueryComplianceStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryComplianceStatus) (*types.QueryComplianceStatusResponse, error)
	QueryConfigOption(ctx context.Context, r soap.RoundTripper, req *types.QueryConfigOption) (*types.QueryConfigOptionResponse, error)
	QueryConfigOptionDescriptor(ctx context.Context, r soap.RoundTripper, req *types.QueryConfigOptionDescriptor) (*types.QueryConfigOptionDescriptorResponse, error)
	QueryConfigOptionEx(ctx context.Context, r soap.RoundTripper, req *types.QueryConfigOptionEx) (*types.QueryConfigOptionExResponse, error)
	QueryConfigTarget(ctx context.Context, r soap.RoundTripper, req *types.QueryConfigTarget) (*types.QueryConfigTargetResponse, error)
	QueryConfiguredModuleOptionString(ctx context.Context, r soap.RoundTripper, req *types.QueryConfiguredModuleOptionString) (*types.QueryConfiguredModuleOptionStringResponse, error)
	QueryConnectionInfo(ctx context.Context, r soap.RoundTripper, req *types.QueryConnectionInfo) (*types.QueryConnectionInfoResponse, error)
	QueryConnectionInfoViaSpec(ctx context.Context, r soap.RoundTripper, req *types.QueryConnectionInfoViaSpec) (*types.QueryConnectionInfoViaSpecResponse, error)
	QueryDatastorePerformanceSummary(ctx context.Context, r soap.RoundTripper, req *types.QueryDatastorePerformanceSummary) (*types.QueryDatastorePerformanceSummaryResponse, error)
	QueryDateTime(ctx context.Context, r soap.RoundTripper, req *types.QueryDateTime) (*types.QueryDateTimeResponse, error)
	QueryDescriptions(ctx context.Context, r soap.RoundTripper, req *types.QueryDescriptions) (*types.QueryDescriptionsResponse, error)
	QueryDisksForVsan(ctx context.Context, r soap.RoundTripper, req *types.QueryDisksForVsan) (*types.QueryDisksForVsanResponse, error)
	QueryDisksUsingFilter(ctx context.Context, r soap.RoundTripper, req *types.QueryDisksUsingFilter) (*types.QueryDisksUsingFilterResponse, error)
	QueryDvsByUuid(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsByUuid) (*types.QueryDvsByUuidResponse, error)
	QueryDvsCheckCompatibility(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsCheckCompatibility) (*types.QueryDvsCheckCompatibilityResponse, error)
	QueryDvsCompatibleHostSpec(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsCompatibleHostSpec) (*types.QueryDvsCompatibleHostSpecResponse, error)
	QueryDvsConfigTarget(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsConfigTarget) (*types.QueryDvsConfigTargetResponse, error)
	QueryDvsFeatureCapability(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsFeatureCapability) (*types.QueryDvsFeatureCapabilityResponse, error)
	QueryEvents(ctx context.Context, r soap.RoundTripper, req *types.QueryEvents) (*types.QueryEventsResponse, error)
	QueryExpressionMetadata(ctx context.Context, r soap.RoundTripper, req *types.QueryExpressionMetadata) (*types.QueryExpressionMetadataResponse, error)
	QueryExtensionIpAllocationUsage(ctx context.Context, r soap.RoundTripper, req *types.QueryExtensionIpAllocationUsage) (*types.QueryExtensionIpAllocationUsageResponse, error)
	QueryFaultToleranceCompatibility(ctx context.Context, r soap.RoundTripper, req *types.QueryFaultToleranceCompatibility) (*types.QueryFaultToleranceCompatibilityResponse, error)
	QueryFaultToleranceCompatibilityEx(ctx context.Context, r soap.RoundTripper, req *types.QueryFaultToleranceCompatibilityEx) (*types.QueryFaultToleranceCompatibilityExResponse, error)
	QueryFilterEntities(ctx context.Context, r soap.RoundTripper, req *types.QueryFilterEntities) (*types.QueryFilterEntitiesResponse, error)
	QueryFilterInfoIds(ctx context.Context, r soap.RoundTripper, req *types.QueryFilterInfoIds) (*types.QueryFilterInfoIdsResponse, error)
	QueryFilterList(ctx context.Context, r soap.RoundTripper, req *types.QueryFilterList) (*types.QueryFilterListResponse, error)
	QueryFilterName(ctx context.Context, r soap.RoundTripper, req *types.QueryFilterName) (*types.QueryFilterNameResponse, error)
	QueryFirmwareConfigUploadURL(ctx context.Context, r soap.RoundTripper, req *types.QueryFirmwareConfigUploadURL) (*types.QueryFirmwareConfigUploadURLResponse, error)
	QueryHealthUpdateInfos(ctx context.Context, r soap.RoundTripper, req *types.QueryHealthUpdateInfos) (*types.QueryHealthUpdateInfosResponse, error)
	QueryHealthUpdates(ctx context.Context, r soap.RoundTripper, req *types.QueryHealthUpdates) (*types.QueryHealthUpdatesResponse, error)
	QueryHostConnectionInfo(ctx context.Context, r soap.RoundTripper, req *types.QueryHostConnectionInfo) (*types.QueryHostConnectionInfoResponse, error)
	QueryHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.QueryHostPatch_Task) (*types.QueryHostPatch_TaskResponse, error)
	QueryHostProfileMetadata(ctx context.Context, r soap.RoundTripper, req *types.QueryHostProfileMetadata) (*types.QueryHostProfileMetadataResponse, error)
	QueryHostStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryHostStatus) (*types.QueryHostStatusResponse, error)
	QueryIORMConfigOption(ctx context.Context, r soap.RoundTripper, req *types.QueryIORMConfigOption) (*types.QueryIORMConfigOptionResponse, error)
	QueryIPAllocations(ctx context.Context, r soap.RoundTripper, req *types.QueryIPAllocations) (*types.QueryIPAllocationsResponse, error)
	QueryIoFilterInfo(ctx context.Context, r soap.RoundTripper, req *types.QueryIoFilterInfo) (*types.QueryIoFilterInfoResponse, error)
	QueryIoFilterIssues(ctx context.Context, r soap.RoundTripper, req *types.QueryIoFilterIssues) (*types.QueryIoFilterIssuesResponse, error)
	QueryIpPools(ctx context.Context, r soap.RoundTripper, req *types.QueryIpPools) (*types.QueryIpPoolsResponse, error)
	QueryLicenseSourceAvailability(ctx context.Context, r soap.RoundTripper, req *types.QueryLicenseSourceAvailability) (*types.QueryLicenseSourceAvailabilityResponse, error)
	QueryLicenseUsage(ctx context.Context, r soap.RoundTripper, req *types.QueryLicenseUsage) (*types.QueryLicenseUsageResponse, error)
	QueryLockdownExceptions(ctx context.Context, r soap.RoundTripper, req *types.QueryLockdownExceptions) (*types.QueryLockdownExceptionsResponse, error)
	QueryManagedBy(ctx context.Context, r soap.RoundTripper, req *types.QueryManagedBy) (*types.QueryManagedByResponse, error)
	QueryMemoryOverhead(ctx context.Context, r soap.RoundTripper, req *types.QueryMemoryOverhead) (*types.QueryMemoryOverheadResponse, error)
	QueryMemoryOverheadEx(ctx context.Context, r soap.RoundTripper, req *types.QueryMemoryOverheadEx) (*types.QueryMemoryOverheadExResponse, error)
	QueryMigrationDependencies(ctx context.Context, r soap.RoundTripper, req *types.QueryMigrationDependencies) (*types.QueryMigrationDependenciesResponse, error)
	QueryModules(ctx context.Context, r soap.RoundTripper, req *types.QueryModules) (*types.QueryModulesResponse, error)
	QueryMonitoredEntities(ctx context.Context, r soap.RoundTripper, req *types.QueryMonitoredEntities) (*types.QueryMonitoredEntitiesResponse, error)
	QueryNFSUser(ctx context.Context, r soap.RoundTripper, req *types.QueryNFSUser) (*types.QueryNFSUserResponse, error)
	QueryNetConfig(ctx context.Context, r soap.RoundTripper, req *types.QueryNetConfig) (*types.QueryNetConfigResponse, error)
	QueryNetworkHint(ctx context.Context, r soap.RoundTripper, req *types.QueryNetworkHint) (*types.QueryNetworkHintResponse, error)
	QueryObjectsOnPhysicalVsanDisk(ctx context.Context, r soap.RoundTripper, req *types.QueryObjectsOnPhysicalVsanDisk) (*types.QueryObjectsOnPhysicalVsanDiskResponse, error)
	QueryOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryOptions) (*types.QueryOptionsResponse, error)
	QueryPartitionCreateDesc(ctx context.Context, r soap.RoundTripper, req *types.QueryPartitionCreateDesc) (*types.QueryPartitionCreateDescResponse, error)
	QueryPartitionCreateOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryPartitionCreateOptions) (*types.QueryPartitionCreateOptionsResponse, error)
	QueryPathSelectionPolicyOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryPathSelectionPolicyOptions) (*types.QueryPathSelectionPolicyOptionsResponse, error)
	QueryPerf(ctx context.Context, r soap.RoundTripper, req *types.QueryPerf) (*types.QueryPerfResponse, error)
	QueryPerfComposite(ctx context.Context, r soap.RoundTripper, req *types.QueryPerfComposite) (*types.QueryPerfCompositeResponse, error)
	QueryPerfCounter(ctx context.Context, r soap.RoundTripper, req *types.QueryPerfCounter) (*types.QueryPerfCounterResponse, error)
	QueryPerfCounterByLevel(ctx context.Context, r soap.RoundTripper, req *types.QueryPerfCounterByLevel) (*types.QueryPerfCounterByLevelResponse, error)
	QueryPerfProviderSummary(ctx context.Context, r soap.RoundTripper, req *types.QueryPerfProviderSummary) (*types.QueryPerfProviderSummaryResponse, error)
	QueryPhysicalVsanDisks(ctx context.Context, r soap.RoundTripper, req *types.QueryPhysicalVsanDisks) (*types.QueryPhysicalVsanDisksResponse, error)
	QueryPnicStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryPnicStatus) (*types.QueryPnicStatusResponse, error)
	QueryPolicyMetadata(ctx context.Context, r soap.RoundTripper, req *types.QueryPolicyMetadata) (*types.QueryPolicyMetadataResponse, error)
	QueryProfileStructure(ctx context.Context, r soap.RoundTripper, req *types.QueryProfileStructure) (*types.QueryProfileStructureResponse, error)
	QueryProviderList(ctx context.Context, r soap.RoundTripper, req *types.QueryProviderList) (*types.QueryProviderListResponse, error)
	QueryProviderName(ctx context.Context, r soap.RoundTripper, req *types.QueryProviderName) (*types.QueryProviderNameResponse, error)
	QueryResourceConfigOption(ctx context.Context, r soap.RoundTripper, req *types.QueryResourceConfigOption) (*types.QueryResourceConfigOptionResponse, error)
	QueryServiceList(ctx context.Context, r soap.RoundTripper, req *types.QueryServiceList) (*types.QueryServiceListResponse, error)
	QueryStorageArrayTypePolicyOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryStorageArrayTypePolicyOptions) (*types.QueryStorageArrayTypePolicyOptionsResponse, error)
	QuerySupportedFeatures(ctx context.Context, r soap.RoundTripper, req *types.QuerySupportedFeatures) (*types.QuerySupportedFeaturesResponse, error)
	QuerySyncingVsanObjects(ctx context.Context, r soap.RoundTripper, req *types.QuerySyncingVsanObjects) (*types.QuerySyncingVsanObjectsResponse, error)
	QuerySystemUsers(ctx context.Context, r soap.RoundTripper, req *types.QuerySystemUsers) (*types.QuerySystemUsersResponse, error)
	QueryTargetCapabilities(ctx context.Context, r soap.RoundTripper, req *types.QueryTargetCapabilities) (*types.QueryTargetCapabilitiesResponse, error)
	QueryTpmAttestationReport(ctx context.Context, r soap.RoundTripper, req *types.QueryTpmAttestationReport) (*types.QueryTpmAttestationReportResponse, error)
	QueryUnmonitoredHosts(ctx context.Context, r soap.RoundTripper, req *types.QueryUnmonitoredHosts) (*types.QueryUnmonitoredHostsResponse, error)
	QueryUnownedFiles(ctx context.Context, r soap.RoundTripper, req *types.QueryUnownedFiles) (*types.QueryUnownedFilesResponse, error)
	QueryUnresolvedVmfsVolume(ctx context.Context, r soap.RoundTripper, req *types.QueryUnresolvedVmfsVolume) (*types.QueryUnresolvedVmfsVolumeResponse, error)
	QueryUnresolvedVmfsVolumes(ctx context.Context, r soap.RoundTripper, req *types.QueryUnresolvedVmfsVolumes) (*types.QueryUnresolvedVmfsVolumesResponse, error)
	QueryUsedVlanIdInDvs(ctx context.Context, r soap.RoundTripper, req *types.QueryUsedVlanIdInDvs) (*types.QueryUsedVlanIdInDvsResponse, error)
	QueryVMotionCompatibility(ctx context.Context, r soap.RoundTripper, req *types.QueryVMotionCompatibility) (*types.QueryVMotionCompatibilityResponse, error)
	QueryVMotionCompatibilityEx_Task(ctx context.Context, r soap.RoundTripper, req *types.QueryVMotionCompatibilityEx_Task) (*types.QueryVMotionCompatibilityEx_TaskResponse, error)
	QueryVirtualDiskFragmentation(ctx context.Context, r soap.RoundTripper, req *types.QueryVirtualDiskFragmentation) (*types.QueryVirtualDiskFragmentationResponse, error)
	QueryVirtualDiskGeometry(ctx context.Context, r soap.RoundTripper, req *types.QueryVirtualDiskGeometry) (*types.QueryVirtualDiskGeometryResponse, error)
	QueryVirtualDiskUuid(ctx context.Context, r soap.RoundTripper, req *types.QueryVirtualDiskUuid) (*types.QueryVirtualDiskUuidResponse, error)
	QueryVmfsConfigOption(ctx context.Context, r soap.RoundTripper, req *types.QueryVmfsConfigOption) (*types.QueryVmfsConfigOptionResponse, error)
	QueryVmfsDatastoreCreateOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryVmfsDatastoreCreateOptions) (*types.QueryVmfsDatastoreCreateOptionsResponse, error)
	QueryVmfsDatastoreExpandOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryVmfsDatastoreExpandOptions) (*types.QueryVmfsDatastoreExpandOptionsResponse, error)
	QueryVmfsDatastoreExtendOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryVmfsDatastoreExtendOptions) (*types.QueryVmfsDatastoreExtendOptionsResponse, error)
	QueryVnicStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryVnicStatus) (*types.QueryVnicStatusResponse, error)
	QueryVsanObjectUuidsByFilter(ctx context.Context, r soap.RoundTripper, req *types.QueryVsanObjectUuidsByFilter) (*types.QueryVsanObjectUuidsByFilterResponse, error)
	QueryVsanObjects(ctx context.Context, r soap.RoundTripper, req *types.QueryVsanObjects) (*types.QueryVsanObjectsResponse, error)
	QueryVsanStatistics(ctx context.Context, r soap.RoundTripper, req *types.QueryVsanStatistics) (*types.QueryVsanStatisticsResponse, error)
	QueryVsanUpgradeStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryVsanUpgradeStatus) (*types.QueryVsanUpgradeStatusResponse, error)
	ReadEnvironmentVariableInGuest(ctx context.Context, r soap.RoundTripper, req *types.ReadEnvironmentVariableInGuest) (*types.ReadEnvironmentVariableInGuestResponse, error)
	ReadNextEvents(ctx context.Context, r soap.RoundTripper, req *types.ReadNextEvents) (*types.ReadNextEventsResponse, error)
	ReadNextTasks(ctx context.Context, r soap.RoundTripper, req *types.ReadNextTasks) (*types.ReadNextTasksResponse, error)
	ReadPreviousEvents(ctx context.Context, r soap.RoundTripper, req *types.ReadPreviousEvents) (*types.ReadPreviousEventsResponse, error)
	ReadPreviousTasks(ctx context.Context, r soap.RoundTripper, req *types.ReadPreviousTasks) (*types.ReadPreviousTasksResponse, error)
	RebootGuest(ctx context.Context, r soap.RoundTripper, req *types.RebootGuest) (*types.RebootGuestResponse, error)
	RebootHost_Task(ctx context.Context, r soap.RoundTripper, req *types.RebootHost_Task) (*types.RebootHost_TaskResponse, error)
	RecommendDatastores(ctx context.Context, r soap.RoundTripper, req *types.RecommendDatastores) (*types.RecommendDatastoresResponse, error)
	RecommendHostsForVm(ctx context.Context, r soap.RoundTripper, req *types.RecommendHostsForVm) (*types.RecommendHostsForVmResponse, error)
	RecommissionVsanNode_Task(ctx context.Context, r soap.RoundTripper, req *types.RecommissionVsanNode_Task) (*types.RecommissionVsanNode_TaskResponse, error)
	ReconcileDatastoreInventory_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconcileDatastoreInventory_Task) (*types.ReconcileDatastoreInventory_TaskResponse, error)
	ReconfigVM_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigVM_Task) (*types.ReconfigVM_TaskResponse, error)
	ReconfigurationSatisfiable(ctx context.Context, r soap.RoundTripper, req *types.ReconfigurationSatisfiable) (*types.ReconfigurationSatisfiableResponse, error)
	ReconfigureAlarm(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureAlarm) (*types.ReconfigureAlarmResponse, error)
	ReconfigureAutostart(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureAutostart) (*types.ReconfigureAutostartResponse, error)
	ReconfigureCluster_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureCluster_Task) (*types.ReconfigureCluster_TaskResponse, error)
	ReconfigureComputeResource_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureComputeResource_Task) (*types.ReconfigureComputeResource_TaskResponse, error)
	ReconfigureDVPort_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDVPort_Task) (*types.ReconfigureDVPort_TaskResponse, error)
	ReconfigureDVPortgroup_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDVPortgroup_Task) (*types.ReconfigureDVPortgroup_TaskResponse, error)
	ReconfigureDatacenter_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDatacenter_Task) (*types.ReconfigureDatacenter_TaskResponse, error)
	ReconfigureDomObject(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDomObject) (*types.ReconfigureDomObjectResponse, error)
	ReconfigureDvs_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDvs_Task) (*types.ReconfigureDvs_TaskResponse, error)
	ReconfigureHostForDAS_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureHostForDAS_Task) (*types.ReconfigureHostForDAS_TaskResponse, error)
	ReconfigureScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureScheduledTask) (*types.ReconfigureScheduledTaskResponse, error)
	ReconfigureServiceConsoleReservation(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureServiceConsoleReservation) (*types.ReconfigureServiceConsoleReservationResponse, error)
	ReconfigureSnmpAgent(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureSnmpAgent) (*types.ReconfigureSnmpAgentResponse, error)
	ReconfigureVirtualMachineReservation(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureVirtualMachineReservation) (*types.ReconfigureVirtualMachineReservationResponse, error)
	ReconnectHost_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconnectHost_Task) (*types.ReconnectHost_TaskResponse, error)
	RectifyDvsHost_Task(ctx context.Context, r soap.RoundTripper, req *types.RectifyDvsHost_Task) (*types.RectifyDvsHost_TaskResponse, error)
	RectifyDvsOnHost_Task(ctx context.Context, r soap.RoundTripper, req *types.RectifyDvsOnHost_Task) (*types.RectifyDvsOnHost_TaskResponse, error)
	Refresh(ctx context.Context, r soap.RoundTripper, req *types.Refresh) (*types.RefreshResponse, error)
	RefreshDVPortState(ctx context.Context, r soap.RoundTripper, req *types.RefreshDVPortState) (*types.RefreshDVPortStateResponse, error)
	RefreshDatastore(ctx context.Context, r soap.RoundTripper, req *types.RefreshDatastore) (*types.RefreshDatastoreResponse, error)
	RefreshDatastoreStorageInfo(ctx context.Context, r soap.RoundTripper, req *types.RefreshDatastoreStorageInfo) (*types.RefreshDatastoreStorageInfoResponse, error)
	RefreshDateTimeSystem(ctx context.Context, r soap.RoundTripper, req *types.RefreshDateTimeSystem) (*types.RefreshDateTimeSystemResponse, error)
	RefreshFirewall(ctx context.Context, r soap.RoundTripper, req *types.RefreshFirewall) (*types.RefreshFirewallResponse, error)
	RefreshGraphicsManager(ctx context.Context, r soap.RoundTripper, req *types.RefreshGraphicsManager) (*types.RefreshGraphicsManagerResponse, error)
	RefreshHealthStatusSystem(ctx context.Context, r soap.RoundTripper, req *types.RefreshHealthStatusSystem) (*types.RefreshHealthStatusSystemResponse, error)
	RefreshNetworkSystem(ctx context.Context, r soap.RoundTripper, req *types.RefreshNetworkSystem) (*types.RefreshNetworkSystemResponse, error)
	RefreshRecommendation(ctx context.Context, r soap.RoundTripper, req *types.RefreshRecommendation) (*types.RefreshRecommendationResponse, error)
	RefreshRuntime(ctx context.Context, r soap.RoundTripper, req *types.RefreshRuntime) (*types.RefreshRuntimeResponse, error)
	RefreshServices(ctx context.Context, r soap.RoundTripper, req *types.RefreshServices) (*types.RefreshServicesResponse, error)
	RefreshStorageDrsRecommendation(ctx context.Context, r soap.RoundTripper, req *types.RefreshStorageDrsRecommendation) (*types.RefreshStorageDrsRecommendationResponse, error)
	RefreshStorageInfo(ctx context.Context, r soap.RoundTripper, req *types.RefreshStorageInfo) (*types.RefreshStorageInfoResponse, error)
	RefreshStorageSystem(ctx context.Context, r soap.RoundTripper, req *types.RefreshStorageSystem) (*types.RefreshStorageSystemResponse, error)
	RegisterChildVM_Task(ctx context.Context, r soap.RoundTripper, req *types.RegisterChildVM_Task) (*types.RegisterChildVM_TaskResponse, error)
	RegisterDisk(ctx context.Context, r soap.RoundTripper, req *types.RegisterDisk) (*types.RegisterDiskResponse, error)
	RegisterExtension(ctx context.Context, r soap.RoundTripper, req *types.RegisterExtension) (*types.RegisterExtensionResponse, error)
	RegisterHealthUpdateProvider(ctx context.Context, r soap.RoundTripper, req *types.RegisterHealthUpdateProvider) (*types.RegisterHealthUpdateProviderResponse, error)
	RegisterKmipServer(ctx context.Context, r soap.RoundTripper, req *types.RegisterKmipServer) (*types.RegisterKmipServerResponse, error)
	RegisterVM_Task(ctx context.Context, r soap.RoundTripper, req *types.RegisterVM_Task) (*types.RegisterVM_TaskResponse, error)
	ReleaseCredentialsInGuest(ctx context.Context, r soap.RoundTripper, req *types.ReleaseCredentialsInGuest) (*types.ReleaseCredentialsInGuestResponse, error)
	ReleaseIpAllocation(ctx context.Context, r soap.RoundTripper, req *types.ReleaseIpAllocation) (*types.ReleaseIpAllocationResponse, error)
	ReleaseManagedSnapshot(ctx context.Context, r soap.RoundTripper, req *types.ReleaseManagedSnapshot) (*types.ReleaseManagedSnapshotResponse, error)
	Reload(ctx context.Context, r soap.RoundTripper, req *types.Reload) (*types.ReloadResponse, error)
	RelocateVM_Task(ctx context.Context, r soap.RoundTripper, req *types.RelocateVM_Task) (*types.RelocateVM_TaskResponse, error)
	RelocateVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.RelocateVStorageObject_Task) (*types.RelocateVStorageObject_TaskResponse, error)
	RemoveAlarm(ctx context.Context, r soap.RoundTripper, req *types.RemoveAlarm) (*types.RemoveAlarmResponse, error)
	RemoveAllSnapshots_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveAllSnapshots_Task) (*types.RemoveAllSnapshots_TaskResponse, error)
	RemoveAssignedLicense(ctx context.Context, r soap.RoundTripper, req *types.RemoveAssignedLicense) (*types.RemoveAssignedLicenseResponse, error)
	RemoveAuthorizationRole(ctx context.Context, r soap.RoundTripper, req *types.RemoveAuthorizationRole) (*types.RemoveAuthorizationRoleResponse, error)
	RemoveCustomFieldDef(ctx context.Context, r soap.RoundTripper, req *types.RemoveCustomFieldDef) (*types.RemoveCustomFieldDefResponse, error)
	RemoveDatastore(ctx context.Context, r soap.RoundTripper, req *types.RemoveDatastore) (*types.RemoveDatastoreResponse, error)
	RemoveDatastoreEx_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveDatastoreEx_Task) (*types.RemoveDatastoreEx_TaskResponse, error)
	RemoveDiskMapping_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveDiskMapping_Task) (*types.RemoveDiskMapping_TaskResponse, error)
	RemoveDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveDisk_Task) (*types.RemoveDisk_TaskResponse, error)
	RemoveEntityPermission(ctx context.Context, r soap.RoundTripper, req *types.RemoveEntityPermission) (*types.RemoveEntityPermissionResponse, error)
	RemoveFilter(ctx context.Context, r soap.RoundTripper, req *types.RemoveFilter) (*types.RemoveFilterResponse, error)
	RemoveFilterEntities(ctx context.Context, r soap.RoundTripper, req *types.RemoveFilterEntities) (*types.RemoveFilterEntitiesResponse, error)
	RemoveGroup(ctx context.Context, r soap.RoundTripper, req *types.RemoveGroup) (*types.RemoveGroupResponse, error)
	RemoveGuestAlias(ctx context.Context, r soap.RoundTripper, req *types.RemoveGuestAlias) (*types.RemoveGuestAliasResponse, error)
	RemoveGuestAliasByCert(ctx context.Context, r soap.RoundTripper, req *types.RemoveGuestAliasByCert) (*types.RemoveGuestAliasByCertResponse, error)
	RemoveInternetScsiSendTargets(ctx context.Context, r soap.RoundTripper, req *types.RemoveInternetScsiSendTargets) (*types.RemoveInternetScsiSendTargetsResponse, error)
	RemoveInternetScsiStaticTargets(ctx context.Context, r soap.RoundTripper, req *types.RemoveInternetScsiStaticTargets) (*types.RemoveInternetScsiStaticTargetsResponse, error)
	RemoveKey(ctx context.Context, r soap.RoundTripper, req *types.RemoveKey) (*types.RemoveKeyResponse, error)
	RemoveKeys(ctx context.Context, r soap.RoundTripper, req *types.RemoveKeys) (*types.RemoveKeysResponse, error)
	RemoveKmipServer(ctx context.Context, r soap.RoundTripper, req *types.RemoveKmipServer) (*types.RemoveKmipServerResponse, error)
	RemoveLicense(ctx context.Context, r soap.RoundTripper, req *types.RemoveLicense) (*types.RemoveLicenseResponse, error)
	RemoveLicenseLabel(ctx context.Context, r soap.RoundTripper, req *types.RemoveLicenseLabel) (*types.RemoveLicenseLabelResponse, error)
	RemoveMonitoredEntities(ctx context.Context, r soap.RoundTripper, req *types.RemoveMonitoredEntities) (*types.RemoveMonitoredEntitiesResponse, error)
	RemoveNetworkResourcePool(ctx context.Context, r soap.RoundTripper, req *types.RemoveNetworkResourcePool) (*types.RemoveNetworkResourcePoolResponse, error)
	RemovePerfInterval(ctx context.Context, r soap.RoundTripper, req *types.RemovePerfInterval) (*types.RemovePerfIntervalResponse, error)
	RemovePortGroup(ctx context.Context, r soap.RoundTripper, req *types.RemovePortGroup) (*types.RemovePortGroupResponse, error)
	RemoveScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.RemoveScheduledTask) (*types.RemoveScheduledTaskResponse, error)
	RemoveServiceConsoleVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.RemoveServiceConsoleVirtualNic) (*types.RemoveServiceConsoleVirtualNicResponse, error)
	RemoveSmartCardTrustAnchor(ctx context.Context, r soap.RoundTripper, req *types.RemoveSmartCardTrustAnchor) (*types.RemoveSmartCardTrustAnchorResponse, error)
	RemoveSmartCardTrustAnchorByFingerprint(ctx context.Context, r soap.RoundTripper, req *types.RemoveSmartCardTrustAnchorByFingerprint) (*types.RemoveSmartCardTrustAnchorByFingerprintResponse, error)
	RemoveSnapshot_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveSnapshot_Task) (*types.RemoveSnapshot_TaskResponse, error)
	RemoveUser(ctx context.Context, r soap.RoundTripper, req *types.RemoveUser) (*types.RemoveUserResponse, error)
	RemoveVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.RemoveVirtualNic) (*types.RemoveVirtualNicResponse, error)
	RemoveVirtualSwitch(ctx context.Context, r soap.RoundTripper, req *types.RemoveVirtualSwitch) (*types.RemoveVirtualSwitchResponse, error)
	RenameCustomFieldDef(ctx context.Context, r soap.RoundTripper, req *types.RenameCustomFieldDef) (*types.RenameCustomFieldDefResponse, error)
	RenameCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.RenameCustomizationSpec) (*types.RenameCustomizationSpecResponse, error)
	RenameDatastore(ctx context.Context, r soap.RoundTripper, req *types.RenameDatastore) (*types.RenameDatastoreResponse, error)
	RenameSnapshot(ctx context.Context, r soap.RoundTripper, req *types.RenameSnapshot) (*types.RenameSnapshotResponse, error)
	RenameVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.RenameVStorageObject) (*types.RenameVStorageObjectResponse, error)
	Rename_Task(ctx context.Context, r soap.RoundTripper, req *types.Rename_Task) (*types.Rename_TaskResponse, error)
	ReplaceCACertificatesAndCRLs(ctx context.Context, r soap.RoundTripper, req *types.ReplaceCACertificatesAndCRLs) (*types.ReplaceCACertificatesAndCRLsResponse, error)
	ReplaceSmartCardTrustAnchors(ctx context.Context, r soap.RoundTripper, req *types.ReplaceSmartCardTrustAnchors) (*types.ReplaceSmartCardTrustAnchorsResponse, error)
	RescanAllHba(ctx context.Context, r soap.RoundTripper, req *types.RescanAllHba) (*types.RescanAllHbaResponse, error)
	RescanHba(ctx context.Context, r soap.RoundTripper, req *types.RescanHba) (*types.RescanHbaResponse, error)
	RescanVffs(ctx context.Context, r soap.RoundTripper, req *types.RescanVffs) (*types.RescanVffsResponse, error)
	RescanVmfs(ctx context.Context, r soap.RoundTripper, req *types.RescanVmfs) (*types.RescanVmfsResponse, error)
	ResetCollector(ctx context.Context, r soap.RoundTripper, req *types.ResetCollector) (*types.ResetCollectorResponse, error)
	ResetCounterLevelMapping(ctx context.Context, r soap.RoundTripper, req *types.ResetCounterLevelMapping) (*types.ResetCounterLevelMappingResponse, error)
	ResetEntityPermissions(ctx context.Context, r soap.RoundTripper, req *types.ResetEntityPermissions) (*types.ResetEntityPermissionsResponse, error)
	ResetFirmwareToFactoryDefaults(ctx context.Context, r soap.RoundTripper, req *types.ResetFirmwareToFactoryDefaults) (*types.ResetFirmwareToFactoryDefaultsResponse, error)
	ResetGuestInformation(ctx context.Context, r soap.RoundTripper, req *types.ResetGuestInformation) (*types.ResetGuestInformationResponse, error)
	ResetListView(ctx context.Context, r soap.RoundTripper, req *types.ResetListView) (*types.ResetListViewResponse, error)
	ResetListViewFromView(ctx context.Context, r soap.RoundTripper, req *types.ResetListViewFromView) (*types.ResetListViewFromViewResponse, error)
	ResetSystemHealthInfo(ctx context.Context, r soap.RoundTripper, req *types.ResetSystemHealthInfo) (*types.ResetSystemHealthInfoResponse, error)
	ResetVM_Task(ctx context.Context, r soap.RoundTripper, req *types.ResetVM_Task) (*types.ResetVM_TaskResponse, error)
	ResignatureUnresolvedVmfsVolume_Task(ctx context.Context, r soap.RoundTripper, req *types.ResignatureUnresolvedVmfsVolume_Task) (*types.ResignatureUnresolvedVmfsVolume_TaskResponse, error)
	ResolveInstallationErrorsOnCluster_Task(ctx context.Context, r soap.RoundTripper, req *types.ResolveInstallationErrorsOnCluster_Task) (*types.ResolveInstallationErrorsOnCluster_TaskResponse, error)
	ResolveInstallationErrorsOnHost_Task(ctx context.Context, r soap.RoundTripper, req *types.ResolveInstallationErrorsOnHost_Task) (*types.ResolveInstallationErrorsOnHost_TaskResponse, error)
	ResolveMultipleUnresolvedVmfsVolumes(ctx context.Context, r soap.RoundTripper, req *types.ResolveMultipleUnresolvedVmfsVolumes) (*types.ResolveMultipleUnresolvedVmfsVolumesResponse, error)
	ResolveMultipleUnresolvedVmfsVolumesEx_Task(ctx context.Context, r soap.RoundTripper, req *types.ResolveMultipleUnresolvedVmfsVolumesEx_Task) (*types.ResolveMultipleUnresolvedVmfsVolumesEx_TaskResponse, error)
	RestartService(ctx context.Context, r soap.RoundTripper, req *types.RestartService) (*types.RestartServiceResponse, error)
	RestartServiceConsoleVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.RestartServiceConsoleVirtualNic) (*types.RestartServiceConsoleVirtualNicResponse, error)
	RestoreFirmwareConfiguration(ctx context.Context, r soap.RoundTripper, req *types.RestoreFirmwareConfiguration) (*types.RestoreFirmwareConfigurationResponse, error)
	RetrieveAllPermissions(ctx context.Context, r soap.RoundTripper, req *types.RetrieveAllPermissions) (*types.RetrieveAllPermissionsResponse, error)
	RetrieveAnswerFile(ctx context.Context, r soap.RoundTripper, req *types.RetrieveAnswerFile) (*types.RetrieveAnswerFileResponse, error)
	RetrieveAnswerFileForProfile(ctx context.Context, r soap.RoundTripper, req *types.RetrieveAnswerFileForProfile) (*types.RetrieveAnswerFileForProfileResponse, error)
	RetrieveArgumentDescription(ctx context.Context, r soap.RoundTripper, req *types.RetrieveArgumentDescription) (*types.RetrieveArgumentDescriptionResponse, error)
	RetrieveClientCert(ctx context.Context, r soap.RoundTripper, req *types.RetrieveClientCert) (*types.RetrieveClientCertResponse, error)
	RetrieveClientCsr(ctx context.Context, r soap.RoundTripper, req *types.RetrieveClientCsr) (*types.RetrieveClientCsrResponse, error)
	RetrieveDasAdvancedRuntimeInfo(ctx context.Context, r soap.RoundTripper, req *types.RetrieveDasAdvancedRuntimeInfo) (*types.RetrieveDasAdvancedRuntimeInfoResponse, error)
	RetrieveDescription(ctx context.Context, r soap.RoundTripper, req *types.RetrieveDescription) (*types.RetrieveDescriptionResponse, error)
	RetrieveDiskPartitionInfo(ctx context.Context, r soap.RoundTripper, req *types.RetrieveDiskPartitionInfo) (*types.RetrieveDiskPartitionInfoResponse, error)
	RetrieveEntityPermissions(ctx context.Context, r soap.RoundTripper, req *types.RetrieveEntityPermissions) (*types.RetrieveEntityPermissionsResponse, error)
	RetrieveEntityScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.RetrieveEntityScheduledTask) (*types.RetrieveEntityScheduledTaskResponse, error)
	RetrieveHardwareUptime(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHardwareUptime) (*types.RetrieveHardwareUptimeResponse, error)
	RetrieveHostAccessControlEntries(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHostAccessControlEntries) (*types.RetrieveHostAccessControlEntriesResponse, error)
	RetrieveHostCustomizations(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHostCustomizations) (*types.RetrieveHostCustomizationsResponse, error)
	RetrieveHostCustomizationsForProfile(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHostCustomizationsForProfile) (*types.RetrieveHostCustomizationsForProfileResponse, error)
	RetrieveHostSpecification(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHostSpecification) (*types.RetrieveHostSpecificationResponse, error)
	RetrieveKmipServerCert(ctx context.Context, r soap.RoundTripper, req *types.RetrieveKmipServerCert) (*types.RetrieveKmipServerCertResponse, error)
	RetrieveKmipServersStatus_Task(ctx context.Context, r soap.RoundTripper, req *types.RetrieveKmipServersStatus_Task) (*types.RetrieveKmipServersStatus_TaskResponse, error)
	RetrieveObjectScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.RetrieveObjectScheduledTask) (*types.RetrieveObjectScheduledTaskResponse, error)
	RetrieveProductComponents(ctx context.Context, r soap.RoundTripper, req *types.RetrieveProductComponents) (*types.RetrieveProductComponentsResponse, error)
	RetrieveProperties(ctx context.Context, r soap.RoundTripper, req *types.RetrieveProperties) (*types.RetrievePropertiesResponse, error)
	RetrievePropertiesEx(ctx context.Context, r soap.RoundTripper, req *types.RetrievePropertiesEx) (*types.RetrievePropertiesExResponse, error)
	RetrieveRolePermissions(ctx context.Context, r soap.RoundTripper, req *types.RetrieveRolePermissions) (*types.RetrieveRolePermissionsResponse, error)
	RetrieveSelfSignedClientCert(ctx context.Context, r soap.RoundTripper, req *types.RetrieveSelfSignedClientCert) (*types.RetrieveSelfSignedClientCertResponse, error)
	RetrieveServiceContent(ctx context.Context, r soap.RoundTripper, req *types.RetrieveServiceContent) (*types.RetrieveServiceContentResponse, error)
	RetrieveUserGroups(ctx context.Context, r soap.RoundTripper, req *types.RetrieveUserGroups) (*types.RetrieveUserGroupsResponse, error)
	RetrieveVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.RetrieveVStorageObject) (*types.RetrieveVStorageObjectResponse, error)
	RetrieveVStorageObjectState(ctx context.Context, r soap.RoundTripper, req *types.RetrieveVStorageObjectState) (*types.RetrieveVStorageObjectStateResponse, error)
	RevertToCurrentSnapshot_Task(ctx context.Context, r soap.RoundTripper, req *types.RevertToCurrentSnapshot_Task) (*types.RevertToCurrentSnapshot_TaskResponse, error)
	RevertToSnapshot_Task(ctx context.Context, r soap.RoundTripper, req *types.RevertToSnapshot_Task) (*types.RevertToSnapshot_TaskResponse, error)
	RewindCollector(ctx context.Context, r soap.RoundTripper, req *types.RewindCollector) (*types.RewindCollectorResponse, error)
	RunScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.RunScheduledTask) (*types.RunScheduledTaskResponse, error)
	RunVsanPhysicalDiskDiagnostics(ctx context.Context, r soap.RoundTripper, req *types.RunVsanPhysicalDiskDiagnostics) (*types.RunVsanPhysicalDiskDiagnosticsResponse, error)
	ScanHostPatchV2_Task(ctx context.Context, r soap.RoundTripper, req *types.ScanHostPatchV2_Task) (*types.ScanHostPatchV2_TaskResponse, error)
	ScanHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.ScanHostPatch_Task) (*types.ScanHostPatch_TaskResponse, error)
	ScheduleReconcileDatastoreInventory(ctx context.Context, r soap.RoundTripper, req *types.ScheduleReconcileDatastoreInventory) (*types.ScheduleReconcileDatastoreInventoryResponse, error)
	SearchDatastoreSubFolders_Task(ctx context.Context, r soap.RoundTripper, req *types.SearchDatastoreSubFolders_Task) (*types.SearchDatastoreSubFolders_TaskResponse, error)
	SearchDatastore_Task(ctx context.Context, r soap.RoundTripper, req *types.SearchDatastore_Task) (*types.SearchDatastore_TaskResponse, error)
	SelectActivePartition(ctx context.Context, r soap.RoundTripper, req *types.SelectActivePartition) (*types.SelectActivePartitionResponse, error)
	SelectVnic(ctx context.Context, r soap.RoundTripper, req *types.SelectVnic) (*types.SelectVnicResponse, error)
	SelectVnicForNicType(ctx context.Context, r soap.RoundTripper, req *types.SelectVnicForNicType) (*types.SelectVnicForNicTypeResponse, error)
	SendNMI(ctx context.Context, r soap.RoundTripper, req *types.SendNMI) (*types.SendNMIResponse, error)
	SendTestNotification(ctx context.Context, r soap.RoundTripper, req *types.SendTestNotification) (*types.SendTestNotificationResponse, error)
	SessionIsActive(ctx context.Context, r soap.RoundTripper, req *types.SessionIsActive) (*types.SessionIsActiveResponse, error)
	SetCollectorPageSize(ctx context.Context, r soap.RoundTripper, req *types.SetCollectorPageSize) (*types.SetCollectorPageSizeResponse, error)
	SetDisplayTopology(ctx context.Context, r soap.RoundTripper, req *types.SetDisplayTopology) (*types.SetDisplayTopologyResponse, error)
	SetEntityPermissions(ctx context.Context, r soap.RoundTripper, req *types.SetEntityPermissions) (*types.SetEntityPermissionsResponse, error)
	SetExtensionCertificate(ctx context.Context, r soap.RoundTripper, req *types.SetExtensionCertificate) (*types.SetExtensionCertificateResponse, error)
	SetField(ctx context.Context, r soap.RoundTripper, req *types.SetField) (*types.SetFieldResponse, error)
	SetLicenseEdition(ctx context.Context, r soap.RoundTripper, req *types.SetLicenseEdition) (*types.SetLicenseEditionResponse, error)
	SetLocale(ctx context.Context, r soap.RoundTripper, req *types.SetLocale) (*types.SetLocaleResponse, error)
	SetMultipathLunPolicy(ctx context.Context, r soap.RoundTripper, req *types.SetMultipathLunPolicy) (*types.SetMultipathLunPolicyResponse, error)
	SetNFSUser(ctx context.Context, r soap.RoundTripper, req *types.SetNFSUser) (*types.SetNFSUserResponse, error)
	SetPublicKey(ctx context.Context, r soap.RoundTripper, req *types.SetPublicKey) (*types.SetPublicKeyResponse, error)
	SetRegistryValueInGuest(ctx context.Context, r soap.RoundTripper, req *types.SetRegistryValueInGuest) (*types.SetRegistryValueInGuestResponse, error)
	SetScreenResolution(ctx context.Context, r soap.RoundTripper, req *types.SetScreenResolution) (*types.SetScreenResolutionResponse, error)
	SetTaskDescription(ctx context.Context, r soap.RoundTripper, req *types.SetTaskDescription) (*types.SetTaskDescriptionResponse, error)
	SetTaskState(ctx context.Context, r soap.RoundTripper, req *types.SetTaskState) (*types.SetTaskStateResponse, error)
	SetVirtualDiskUuid(ctx context.Context, r soap.RoundTripper, req *types.SetVirtualDiskUuid) (*types.SetVirtualDiskUuidResponse, error)
	ShrinkVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.ShrinkVirtualDisk_Task) (*types.ShrinkVirtualDisk_TaskResponse, error)
	ShutdownGuest(ctx context.Context, r soap.RoundTripper, req *types.ShutdownGuest) (*types.ShutdownGuestResponse, error)
	ShutdownHost_Task(ctx context.Context, r soap.RoundTripper, req *types.ShutdownHost_Task) (*types.ShutdownHost_TaskResponse, error)
	StageHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.StageHostPatch_Task) (*types.StageHostPatch_TaskResponse, error)
	StampAllRulesWithUuid_Task(ctx context.Context, r soap.RoundTripper, req *types.StampAllRulesWithUuid_Task) (*types.StampAllRulesWithUuid_TaskResponse, error)
	StandbyGuest(ctx context.Context, r soap.RoundTripper, req *types.StandbyGuest) (*types.StandbyGuestResponse, error)
	StartProgramInGuest(ctx context.Context, r soap.RoundTripper, req *types.StartProgramInGuest) (*types.StartProgramInGuestResponse, error)
	StartRecording_Task(ctx context.Context, r soap.RoundTripper, req *types.StartRecording_Task) (*types.StartRecording_TaskResponse, error)
	StartReplaying_Task(ctx context.Context, r soap.RoundTripper, req *types.StartReplaying_Task) (*types.StartReplaying_TaskResponse, error)
	StartService(ctx context.Context, r soap.RoundTripper, req *types.StartService) (*types.StartServiceResponse, error)
	StopRecording_Task(ctx context.Context, r soap.RoundTripper, req *types.StopRecording_Task) (*types.StopRecording_TaskResponse, error)
	StopReplaying_Task(ctx context.Context, r soap.RoundTripper, req *types.StopReplaying_Task) (*types.StopReplaying_TaskResponse, error)
	StopService(ctx context.Context, r soap.RoundTripper, req *types.StopService) (*types.StopServiceResponse, error)
	SuspendVApp_Task(ctx context.Context, r soap.RoundTripper, req *types.SuspendVApp_Task) (*types.SuspendVApp_TaskResponse, error)
	SuspendVM_Task(ctx context.Context, r soap.RoundTripper, req *types.SuspendVM_Task) (*types.SuspendVM_TaskResponse, error)
	TerminateFaultTolerantVM_Task(ctx context.Context, r soap.RoundTripper, req *types.TerminateFaultTolerantVM_Task) (*types.TerminateFaultTolerantVM_TaskResponse, error)
	TerminateProcessInGuest(ctx context.Context, r soap.RoundTripper, req *types.TerminateProcessInGuest) (*types.TerminateProcessInGuestResponse, error)
	TerminateSession(ctx context.Context, r soap.RoundTripper, req *types.TerminateSession) (*types.TerminateSessionResponse, error)
	TerminateVM(ctx context.Context, r soap.RoundTripper, req *types.TerminateVM) (*types.TerminateVMResponse, error)
	TurnDiskLocatorLedOff_Task(ctx context.Context, r soap.RoundTripper, req *types.TurnDiskLocatorLedOff_Task) (*types.TurnDiskLocatorLedOff_TaskResponse, error)
	TurnDiskLocatorLedOn_Task(ctx context.Context, r soap.RoundTripper, req *types.TurnDiskLocatorLedOn_Task) (*types.TurnDiskLocatorLedOn_TaskResponse, error)
	TurnOffFaultToleranceForVM_Task(ctx context.Context, r soap.RoundTripper, req *types.TurnOffFaultToleranceForVM_Task) (*types.TurnOffFaultToleranceForVM_TaskResponse, error)
	UnassignUserFromGroup(ctx context.Context, r soap.RoundTripper, req *types.UnassignUserFromGroup) (*types.UnassignUserFromGroupResponse, error)
	UnbindVnic(ctx context.Context, r soap.RoundTripper, req *types.UnbindVnic) (*types.UnbindVnicResponse, error)
	UninstallHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.UninstallHostPatch_Task) (*types.UninstallHostPatch_TaskResponse, error)
	UninstallIoFilter_Task(ctx context.Context, r soap.RoundTripper, req *types.UninstallIoFilter_Task) (*types.UninstallIoFilter_TaskResponse, error)
	UninstallService(ctx context.Context, r soap.RoundTripper, req *types.UninstallService) (*types.UninstallServiceResponse, error)
	UnmapVmfsVolumeEx_Task(ctx context.Context, r soap.RoundTripper, req *types.UnmapVmfsVolumeEx_Task) (*types.UnmapVmfsVolumeEx_TaskResponse, error)
	UnmountDiskMapping_Task(ctx context.Context, r soap.RoundTripper, req *types.UnmountDiskMapping_Task) (*types.UnmountDiskMapping_TaskResponse, error)
	UnmountForceMountedVmfsVolume(ctx context.Context, r soap.RoundTripper, req *types.UnmountForceMountedVmfsVolume) (*types.UnmountForceMountedVmfsVolumeResponse, error)
	UnmountToolsInstaller(ctx context.Context, r soap.RoundTripper, req *types.UnmountToolsInstaller) (*types.UnmountToolsInstallerResponse, error)
	UnmountVffsVolume(ctx context.Context, r soap.RoundTripper, req *types.UnmountVffsVolume) (*types.UnmountVffsVolumeResponse, error)
	UnmountVmfsVolume(ctx context.Context, r soap.RoundTripper, req *types.UnmountVmfsVolume) (*types.UnmountVmfsVolumeResponse, error)
	UnmountVmfsVolumeEx_Task(ctx context.Context, r soap.RoundTripper, req *types.UnmountVmfsVolumeEx_Task) (*types.UnmountVmfsVolumeEx_TaskResponse, error)
	UnregisterAndDestroy_Task(ctx context.Context, r soap.RoundTripper, req *types.UnregisterAndDestroy_Task) (*types.UnregisterAndDestroy_TaskResponse, error)
	UnregisterExtension(ctx context.Context, r soap.RoundTripper, req *types.UnregisterExtension) (*types.UnregisterExtensionResponse, error)
	UnregisterHealthUpdateProvider(ctx context.Context, r soap.RoundTripper, req *types.UnregisterHealthUpdateProvider) (*types.UnregisterHealthUpdateProviderResponse, error)
	UnregisterVM(ctx context.Context, r soap.RoundTripper, req *types.UnregisterVM) (*types.UnregisterVMResponse, error)
	UpdateAnswerFile_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateAnswerFile_Task) (*types.UpdateAnswerFile_TaskResponse, error)
	UpdateAssignedLicense(ctx context.Context, r soap.RoundTripper, req *types.UpdateAssignedLicense) (*types.UpdateAssignedLicenseResponse, error)
	UpdateAuthorizationRole(ctx context.Context, r soap.RoundTripper, req *types.UpdateAuthorizationRole) (*types.UpdateAuthorizationRoleResponse, error)
	UpdateBootDevice(ctx context.Context, r soap.RoundTripper, req *types.UpdateBootDevice) (*types.UpdateBootDeviceResponse, error)
	UpdateChildResourceConfiguration(ctx context.Context, r soap.RoundTripper, req *types.UpdateChildResourceConfiguration) (*types.UpdateChildResourceConfigurationResponse, error)
	UpdateClusterProfile(ctx context.Context, r soap.RoundTripper, req *types.UpdateClusterProfile) (*types.UpdateClusterProfileResponse, error)
	UpdateConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateConfig) (*types.UpdateConfigResponse, error)
	UpdateConsoleIpRouteConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateConsoleIpRouteConfig) (*types.UpdateConsoleIpRouteConfigResponse, error)
	UpdateCounterLevelMapping(ctx context.Context, r soap.RoundTripper, req *types.UpdateCounterLevelMapping) (*types.UpdateCounterLevelMappingResponse, error)
	UpdateDVSHealthCheckConfig_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateDVSHealthCheckConfig_Task) (*types.UpdateDVSHealthCheckConfig_TaskResponse, error)
	UpdateDVSLacpGroupConfig_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateDVSLacpGroupConfig_Task) (*types.UpdateDVSLacpGroupConfig_TaskResponse, error)
	UpdateDateTime(ctx context.Context, r soap.RoundTripper, req *types.UpdateDateTime) (*types.UpdateDateTimeResponse, error)
	UpdateDateTimeConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateDateTimeConfig) (*types.UpdateDateTimeConfigResponse, error)
	UpdateDefaultPolicy(ctx context.Context, r soap.RoundTripper, req *types.UpdateDefaultPolicy) (*types.UpdateDefaultPolicyResponse, error)
	UpdateDiskPartitions(ctx context.Context, r soap.RoundTripper, req *types.UpdateDiskPartitions) (*types.UpdateDiskPartitionsResponse, error)
	UpdateDnsConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateDnsConfig) (*types.UpdateDnsConfigResponse, error)
	UpdateDvsCapability(ctx context.Context, r soap.RoundTripper, req *types.UpdateDvsCapability) (*types.UpdateDvsCapabilityResponse, error)
	UpdateExtension(ctx context.Context, r soap.RoundTripper, req *types.UpdateExtension) (*types.UpdateExtensionResponse, error)
	UpdateFlags(ctx context.Context, r soap.RoundTripper, req *types.UpdateFlags) (*types.UpdateFlagsResponse, error)
	UpdateGraphicsConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateGraphicsConfig) (*types.UpdateGraphicsConfigResponse, error)
	UpdateHostCustomizations_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostCustomizations_Task) (*types.UpdateHostCustomizations_TaskResponse, error)
	UpdateHostImageAcceptanceLevel(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostImageAcceptanceLevel) (*types.UpdateHostImageAcceptanceLevelResponse, error)
	UpdateHostProfile(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostProfile) (*types.UpdateHostProfileResponse, error)
	UpdateHostSpecification(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostSpecification) (*types.UpdateHostSpecificationResponse, error)
	UpdateHostSubSpecification(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostSubSpecification) (*types.UpdateHostSubSpecificationResponse, error)
	UpdateInternetScsiAdvancedOptions(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiAdvancedOptions) (*types.UpdateInternetScsiAdvancedOptionsResponse, error)
	UpdateInternetScsiAlias(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiAlias) (*types.UpdateInternetScsiAliasResponse, error)
	UpdateInternetScsiAuthenticationProperties(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiAuthenticationProperties) (*types.UpdateInternetScsiAuthenticationPropertiesResponse, error)
	UpdateInternetScsiDigestProperties(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiDigestProperties) (*types.UpdateInternetScsiDigestPropertiesResponse, error)
	UpdateInternetScsiDiscoveryProperties(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiDiscoveryProperties) (*types.UpdateInternetScsiDiscoveryPropertiesResponse, error)
	UpdateInternetScsiIPProperties(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiIPProperties) (*types.UpdateInternetScsiIPPropertiesResponse, error)
	UpdateInternetScsiName(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiName) (*types.UpdateInternetScsiNameResponse, error)
	UpdateIpConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpConfig) (*types.UpdateIpConfigResponse, error)
	UpdateIpPool(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpPool) (*types.UpdateIpPoolResponse, error)
	UpdateIpRouteConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpRouteConfig) (*types.UpdateIpRouteConfigResponse, error)
	UpdateIpRouteTableConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpRouteTableConfig) (*types.UpdateIpRouteTableConfigResponse, error)
	UpdateIpmi(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpmi) (*types.UpdateIpmiResponse, error)
	UpdateKmipServer(ctx context.Context, r soap.RoundTripper, req *types.UpdateKmipServer) (*types.UpdateKmipServerResponse, error)
	UpdateKmsSignedCsrClientCert(ctx context.Context, r soap.RoundTripper, req *types.UpdateKmsSignedCsrClientCert) (*types.UpdateKmsSignedCsrClientCertResponse, error)
	UpdateLicense(ctx context.Context, r soap.RoundTripper, req *types.UpdateLicense) (*types.UpdateLicenseResponse, error)
	UpdateLicenseLabel(ctx context.Context, r soap.RoundTripper, req *types.UpdateLicenseLabel) (*types.UpdateLicenseLabelResponse, error)
	UpdateLinkedChildren(ctx context.Context, r soap.RoundTripper, req *types.UpdateLinkedChildren) (*types.UpdateLinkedChildrenResponse, error)
	UpdateLocalSwapDatastore(ctx context.Context, r soap.RoundTripper, req *types.UpdateLocalSwapDatastore) (*types.UpdateLocalSwapDatastoreResponse, error)
	UpdateLockdownExceptions(ctx context.Context, r soap.RoundTripper, req *types.UpdateLockdownExceptions) (*types.UpdateLockdownExceptionsResponse, error)
	UpdateModuleOptionString(ctx context.Context, r soap.RoundTripper, req *types.UpdateModuleOptionString) (*types.UpdateModuleOptionStringResponse, error)
	UpdateNetworkConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateNetworkConfig) (*types.UpdateNetworkConfigResponse, error)
	UpdateNetworkResourcePool(ctx context.Context, r soap.RoundTripper, req *types.UpdateNetworkResourcePool) (*types.UpdateNetworkResourcePoolResponse, error)
	UpdateOptions(ctx context.Context, r soap.RoundTripper, req *types.UpdateOptions) (*types.UpdateOptionsResponse, error)
	UpdatePassthruConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdatePassthruConfig) (*types.UpdatePassthruConfigResponse, error)
	UpdatePerfInterval(ctx context.Context, r soap.RoundTripper, req *types.UpdatePerfInterval) (*types.UpdatePerfIntervalResponse, error)
	UpdatePhysicalNicLinkSpeed(ctx context.Context, r soap.RoundTripper, req *types.UpdatePhysicalNicLinkSpeed) (*types.UpdatePhysicalNicLinkSpeedResponse, error)
	UpdatePortGroup(ctx context.Context, r soap.RoundTripper, req *types.UpdatePortGroup) (*types.UpdatePortGroupResponse, error)
	UpdateProgress(ctx context.Context, r soap.RoundTripper, req *types.UpdateProgress) (*types.UpdateProgressResponse, error)
	UpdateReferenceHost(ctx context.Context, r soap.RoundTripper, req *types.UpdateReferenceHost) (*types.UpdateReferenceHostResponse, error)
	UpdateRuleset(ctx context.Context, r soap.RoundTripper, req *types.UpdateRuleset) (*types.UpdateRulesetResponse, error)
	UpdateScsiLunDisplayName(ctx context.Context, r soap.RoundTripper, req *types.UpdateScsiLunDisplayName) (*types.UpdateScsiLunDisplayNameResponse, error)
	UpdateSelfSignedClientCert(ctx context.Context, r soap.RoundTripper, req *types.UpdateSelfSignedClientCert) (*types.UpdateSelfSignedClientCertResponse, error)
	UpdateServiceConsoleVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.UpdateServiceConsoleVirtualNic) (*types.UpdateServiceConsoleVirtualNicResponse, error)
	UpdateServiceMessage(ctx context.Context, r soap.RoundTripper, req *types.UpdateServiceMessage) (*types.UpdateServiceMessageResponse, error)
	UpdateServicePolicy(ctx context.Context, r soap.RoundTripper, req *types.UpdateServicePolicy) (*types.UpdateServicePolicyResponse, error)
	UpdateSoftwareInternetScsiEnabled(ctx context.Context, r soap.RoundTripper, req *types.UpdateSoftwareInternetScsiEnabled) (*types.UpdateSoftwareInternetScsiEnabledResponse, error)
	UpdateSystemResources(ctx context.Context, r soap.RoundTripper, req *types.UpdateSystemResources) (*types.UpdateSystemResourcesResponse, error)
	UpdateSystemSwapConfiguration(ctx context.Context, r soap.RoundTripper, req *types.UpdateSystemSwapConfiguration) (*types.UpdateSystemSwapConfigurationResponse, error)
	UpdateSystemUsers(ctx context.Context, r soap.RoundTripper, req *types.UpdateSystemUsers) (*types.UpdateSystemUsersResponse, error)
	UpdateUser(ctx context.Context, r soap.RoundTripper, req *types.UpdateUser) (*types.UpdateUserResponse, error)
	UpdateVAppConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateVAppConfig) (*types.UpdateVAppConfigResponse, error)
	UpdateVVolVirtualMachineFiles_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateVVolVirtualMachineFiles_Task) (*types.UpdateVVolVirtualMachineFiles_TaskResponse, error)
	UpdateVirtualMachineFiles_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateVirtualMachineFiles_Task) (*types.UpdateVirtualMachineFiles_TaskResponse, error)
	UpdateVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.UpdateVirtualNic) (*types.UpdateVirtualNicResponse, error)
	UpdateVirtualSwitch(ctx context.Context, r soap.RoundTripper, req *types.UpdateVirtualSwitch) (*types.UpdateVirtualSwitchResponse, error)
	UpdateVmfsUnmapPriority(ctx context.Context, r soap.RoundTripper, req *types.UpdateVmfsUnmapPriority) (*types.UpdateVmfsUnmapPriorityResponse, error)
	UpdateVsan_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateVsan_Task) (*types.UpdateVsan_TaskResponse, error)
	UpgradeIoFilter_Task(ctx context.Context, r soap.RoundTripper, req *types.UpgradeIoFilter_Task) (*types.UpgradeIoFilter_TaskResponse, error)
	UpgradeTools_Task(ctx context.Context, r soap.RoundTripper, req *types.UpgradeTools_Task) (*types.UpgradeTools_TaskResponse, error)
	UpgradeVM_Task(ctx context.Context, r soap.RoundTripper, req *types.UpgradeVM_Task) (*types.UpgradeVM_TaskResponse, error)
	UpgradeVmLayout(ctx context.Context, r soap.RoundTripper, req *types.UpgradeVmLayout) (*types.UpgradeVmLayoutResponse, error)
	UpgradeVmfs(ctx context.Context, r soap.RoundTripper, req *types.UpgradeVmfs) (*types.UpgradeVmfsResponse, error)
	UpgradeVsanObjects(ctx context.Context, r soap.RoundTripper, req *types.UpgradeVsanObjects) (*types.UpgradeVsanObjectsResponse, error)
	UploadClientCert(ctx context.Context, r soap.RoundTripper, req *types.UploadClientCert) (*types.UploadClientCertResponse, error)
	UploadKmipServerCert(ctx context.Context, r soap.RoundTripper, req *types.UploadKmipServerCert) (*types.UploadKmipServerCertResponse, error)
	ValidateCredentialsInGuest(ctx context.Context, r soap.RoundTripper, req *types.ValidateCredentialsInGuest) (*types.ValidateCredentialsInGuestResponse, error)
	ValidateHost(ctx context.Context, r soap.RoundTripper, req *types.ValidateHost) (*types.ValidateHostResponse, error)
	ValidateMigration(ctx context.Context, r soap.RoundTripper, req *types.ValidateMigration) (*types.ValidateMigrationResponse, error)
	WaitForUpdates(ctx context.Context, r soap.RoundTripper, req *types.WaitForUpdates) (*types.WaitForUpdatesResponse, error)
	WaitForUpdatesEx(ctx context.Context, r soap.RoundTripper, req *types.WaitForUpdatesEx) (*types.WaitForUpdatesExResponse, error)
	XmlToCustomizationSpecItem(ctx context.Context, r soap.RoundTripper, req *types.XmlToCustomizationSpecItem) (*types.XmlToCustomizationSpecItemResponse, error)
	ZeroFillVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.ZeroFillVirtualDisk_Task) (*types.ZeroFillVirtualDisk_TaskResponse, error)
	GetServiceContent(ctx context.Context, r soap.RoundTripper) (types.ServiceContent, error)
	GetCurrentTime(ctx context.Context, r soap.RoundTripper) (*time.Time, error)
}

type ImplContext struct{}
func (_ *ImplContext) AbdicateDomOwnership(ctx context.Context, r soap.RoundTripper, req *types.AbdicateDomOwnership) (*types.AbdicateDomOwnershipResponse, error) {
	return methods.AbdicateDomOwnership(ctx, r, req)
}

func (_ *ImplContext) AcknowledgeAlarm(ctx context.Context, r soap.RoundTripper, req *types.AcknowledgeAlarm) (*types.AcknowledgeAlarmResponse, error) {
	return methods.AcknowledgeAlarm(ctx, r, req)
}

func (_ *ImplContext) AcquireCimServicesTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireCimServicesTicket) (*types.AcquireCimServicesTicketResponse, error) {
	return methods.AcquireCimServicesTicket(ctx, r, req)
}

func (_ *ImplContext) AcquireCloneTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireCloneTicket) (*types.AcquireCloneTicketResponse, error) {
	return methods.AcquireCloneTicket(ctx, r, req)
}

func (_ *ImplContext) AcquireCredentialsInGuest(ctx context.Context, r soap.RoundTripper, req *types.AcquireCredentialsInGuest) (*types.AcquireCredentialsInGuestResponse, error) {
	return methods.AcquireCredentialsInGuest(ctx, r, req)
}

func (_ *ImplContext) AcquireGenericServiceTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireGenericServiceTicket) (*types.AcquireGenericServiceTicketResponse, error) {
	return methods.AcquireGenericServiceTicket(ctx, r, req)
}

func (_ *ImplContext) AcquireLocalTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireLocalTicket) (*types.AcquireLocalTicketResponse, error) {
	return methods.AcquireLocalTicket(ctx, r, req)
}

func (_ *ImplContext) AcquireMksTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireMksTicket) (*types.AcquireMksTicketResponse, error) {
	return methods.AcquireMksTicket(ctx, r, req)
}

func (_ *ImplContext) AcquireTicket(ctx context.Context, r soap.RoundTripper, req *types.AcquireTicket) (*types.AcquireTicketResponse, error) {
	return methods.AcquireTicket(ctx, r, req)
}

func (_ *ImplContext) AddAuthorizationRole(ctx context.Context, r soap.RoundTripper, req *types.AddAuthorizationRole) (*types.AddAuthorizationRoleResponse, error) {
	return methods.AddAuthorizationRole(ctx, r, req)
}

func (_ *ImplContext) AddCustomFieldDef(ctx context.Context, r soap.RoundTripper, req *types.AddCustomFieldDef) (*types.AddCustomFieldDefResponse, error) {
	return methods.AddCustomFieldDef(ctx, r, req)
}

func (_ *ImplContext) AddDVPortgroup_Task(ctx context.Context, r soap.RoundTripper, req *types.AddDVPortgroup_Task) (*types.AddDVPortgroup_TaskResponse, error) {
	return methods.AddDVPortgroup_Task(ctx, r, req)
}

func (_ *ImplContext) AddDisks_Task(ctx context.Context, r soap.RoundTripper, req *types.AddDisks_Task) (*types.AddDisks_TaskResponse, error) {
	return methods.AddDisks_Task(ctx, r, req)
}

func (_ *ImplContext) AddFilter(ctx context.Context, r soap.RoundTripper, req *types.AddFilter) (*types.AddFilterResponse, error) {
	return methods.AddFilter(ctx, r, req)
}

func (_ *ImplContext) AddFilterEntities(ctx context.Context, r soap.RoundTripper, req *types.AddFilterEntities) (*types.AddFilterEntitiesResponse, error) {
	return methods.AddFilterEntities(ctx, r, req)
}

func (_ *ImplContext) AddGuestAlias(ctx context.Context, r soap.RoundTripper, req *types.AddGuestAlias) (*types.AddGuestAliasResponse, error) {
	return methods.AddGuestAlias(ctx, r, req)
}

func (_ *ImplContext) AddHost_Task(ctx context.Context, r soap.RoundTripper, req *types.AddHost_Task) (*types.AddHost_TaskResponse, error) {
	return methods.AddHost_Task(ctx, r, req)
}

func (_ *ImplContext) AddInternetScsiSendTargets(ctx context.Context, r soap.RoundTripper, req *types.AddInternetScsiSendTargets) (*types.AddInternetScsiSendTargetsResponse, error) {
	return methods.AddInternetScsiSendTargets(ctx, r, req)
}

func (_ *ImplContext) AddInternetScsiStaticTargets(ctx context.Context, r soap.RoundTripper, req *types.AddInternetScsiStaticTargets) (*types.AddInternetScsiStaticTargetsResponse, error) {
	return methods.AddInternetScsiStaticTargets(ctx, r, req)
}

func (_ *ImplContext) AddKey(ctx context.Context, r soap.RoundTripper, req *types.AddKey) (*types.AddKeyResponse, error) {
	return methods.AddKey(ctx, r, req)
}

func (_ *ImplContext) AddKeys(ctx context.Context, r soap.RoundTripper, req *types.AddKeys) (*types.AddKeysResponse, error) {
	return methods.AddKeys(ctx, r, req)
}

func (_ *ImplContext) AddLicense(ctx context.Context, r soap.RoundTripper, req *types.AddLicense) (*types.AddLicenseResponse, error) {
	return methods.AddLicense(ctx, r, req)
}

func (_ *ImplContext) AddMonitoredEntities(ctx context.Context, r soap.RoundTripper, req *types.AddMonitoredEntities) (*types.AddMonitoredEntitiesResponse, error) {
	return methods.AddMonitoredEntities(ctx, r, req)
}

func (_ *ImplContext) AddNetworkResourcePool(ctx context.Context, r soap.RoundTripper, req *types.AddNetworkResourcePool) (*types.AddNetworkResourcePoolResponse, error) {
	return methods.AddNetworkResourcePool(ctx, r, req)
}

func (_ *ImplContext) AddPortGroup(ctx context.Context, r soap.RoundTripper, req *types.AddPortGroup) (*types.AddPortGroupResponse, error) {
	return methods.AddPortGroup(ctx, r, req)
}

func (_ *ImplContext) AddServiceConsoleVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.AddServiceConsoleVirtualNic) (*types.AddServiceConsoleVirtualNicResponse, error) {
	return methods.AddServiceConsoleVirtualNic(ctx, r, req)
}

func (_ *ImplContext) AddStandaloneHost_Task(ctx context.Context, r soap.RoundTripper, req *types.AddStandaloneHost_Task) (*types.AddStandaloneHost_TaskResponse, error) {
	return methods.AddStandaloneHost_Task(ctx, r, req)
}

func (_ *ImplContext) AddVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.AddVirtualNic) (*types.AddVirtualNicResponse, error) {
	return methods.AddVirtualNic(ctx, r, req)
}

func (_ *ImplContext) AddVirtualSwitch(ctx context.Context, r soap.RoundTripper, req *types.AddVirtualSwitch) (*types.AddVirtualSwitchResponse, error) {
	return methods.AddVirtualSwitch(ctx, r, req)
}

func (_ *ImplContext) AllocateIpv4Address(ctx context.Context, r soap.RoundTripper, req *types.AllocateIpv4Address) (*types.AllocateIpv4AddressResponse, error) {
	return methods.AllocateIpv4Address(ctx, r, req)
}

func (_ *ImplContext) AllocateIpv6Address(ctx context.Context, r soap.RoundTripper, req *types.AllocateIpv6Address) (*types.AllocateIpv6AddressResponse, error) {
	return methods.AllocateIpv6Address(ctx, r, req)
}

func (_ *ImplContext) AnswerVM(ctx context.Context, r soap.RoundTripper, req *types.AnswerVM) (*types.AnswerVMResponse, error) {
	return methods.AnswerVM(ctx, r, req)
}

func (_ *ImplContext) ApplyEntitiesConfig_Task(ctx context.Context, r soap.RoundTripper, req *types.ApplyEntitiesConfig_Task) (*types.ApplyEntitiesConfig_TaskResponse, error) {
	return methods.ApplyEntitiesConfig_Task(ctx, r, req)
}

func (_ *ImplContext) ApplyHostConfig_Task(ctx context.Context, r soap.RoundTripper, req *types.ApplyHostConfig_Task) (*types.ApplyHostConfig_TaskResponse, error) {
	return methods.ApplyHostConfig_Task(ctx, r, req)
}

func (_ *ImplContext) ApplyRecommendation(ctx context.Context, r soap.RoundTripper, req *types.ApplyRecommendation) (*types.ApplyRecommendationResponse, error) {
	return methods.ApplyRecommendation(ctx, r, req)
}

func (_ *ImplContext) ApplyStorageDrsRecommendationToPod_Task(ctx context.Context, r soap.RoundTripper, req *types.ApplyStorageDrsRecommendationToPod_Task) (*types.ApplyStorageDrsRecommendationToPod_TaskResponse, error) {
	return methods.ApplyStorageDrsRecommendationToPod_Task(ctx, r, req)
}

func (_ *ImplContext) ApplyStorageDrsRecommendation_Task(ctx context.Context, r soap.RoundTripper, req *types.ApplyStorageDrsRecommendation_Task) (*types.ApplyStorageDrsRecommendation_TaskResponse, error) {
	return methods.ApplyStorageDrsRecommendation_Task(ctx, r, req)
}

func (_ *ImplContext) AreAlarmActionsEnabled(ctx context.Context, r soap.RoundTripper, req *types.AreAlarmActionsEnabled) (*types.AreAlarmActionsEnabledResponse, error) {
	return methods.AreAlarmActionsEnabled(ctx, r, req)
}

func (_ *ImplContext) AssignUserToGroup(ctx context.Context, r soap.RoundTripper, req *types.AssignUserToGroup) (*types.AssignUserToGroupResponse, error) {
	return methods.AssignUserToGroup(ctx, r, req)
}

func (_ *ImplContext) AssociateProfile(ctx context.Context, r soap.RoundTripper, req *types.AssociateProfile) (*types.AssociateProfileResponse, error) {
	return methods.AssociateProfile(ctx, r, req)
}

func (_ *ImplContext) AttachDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.AttachDisk_Task) (*types.AttachDisk_TaskResponse, error) {
	return methods.AttachDisk_Task(ctx, r, req)
}

func (_ *ImplContext) AttachScsiLun(ctx context.Context, r soap.RoundTripper, req *types.AttachScsiLun) (*types.AttachScsiLunResponse, error) {
	return methods.AttachScsiLun(ctx, r, req)
}

func (_ *ImplContext) AttachScsiLunEx_Task(ctx context.Context, r soap.RoundTripper, req *types.AttachScsiLunEx_Task) (*types.AttachScsiLunEx_TaskResponse, error) {
	return methods.AttachScsiLunEx_Task(ctx, r, req)
}

func (_ *ImplContext) AttachTagToVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.AttachTagToVStorageObject) (*types.AttachTagToVStorageObjectResponse, error) {
	return methods.AttachTagToVStorageObject(ctx, r, req)
}

func (_ *ImplContext) AttachVmfsExtent(ctx context.Context, r soap.RoundTripper, req *types.AttachVmfsExtent) (*types.AttachVmfsExtentResponse, error) {
	return methods.AttachVmfsExtent(ctx, r, req)
}

func (_ *ImplContext) AutoStartPowerOff(ctx context.Context, r soap.RoundTripper, req *types.AutoStartPowerOff) (*types.AutoStartPowerOffResponse, error) {
	return methods.AutoStartPowerOff(ctx, r, req)
}

func (_ *ImplContext) AutoStartPowerOn(ctx context.Context, r soap.RoundTripper, req *types.AutoStartPowerOn) (*types.AutoStartPowerOnResponse, error) {
	return methods.AutoStartPowerOn(ctx, r, req)
}

func (_ *ImplContext) BackupFirmwareConfiguration(ctx context.Context, r soap.RoundTripper, req *types.BackupFirmwareConfiguration) (*types.BackupFirmwareConfigurationResponse, error) {
	return methods.BackupFirmwareConfiguration(ctx, r, req)
}

func (_ *ImplContext) BindVnic(ctx context.Context, r soap.RoundTripper, req *types.BindVnic) (*types.BindVnicResponse, error) {
	return methods.BindVnic(ctx, r, req)
}

func (_ *ImplContext) BrowseDiagnosticLog(ctx context.Context, r soap.RoundTripper, req *types.BrowseDiagnosticLog) (*types.BrowseDiagnosticLogResponse, error) {
	return methods.BrowseDiagnosticLog(ctx, r, req)
}

func (_ *ImplContext) CanProvisionObjects(ctx context.Context, r soap.RoundTripper, req *types.CanProvisionObjects) (*types.CanProvisionObjectsResponse, error) {
	return methods.CanProvisionObjects(ctx, r, req)
}

func (_ *ImplContext) CancelRecommendation(ctx context.Context, r soap.RoundTripper, req *types.CancelRecommendation) (*types.CancelRecommendationResponse, error) {
	return methods.CancelRecommendation(ctx, r, req)
}

func (_ *ImplContext) CancelRetrievePropertiesEx(ctx context.Context, r soap.RoundTripper, req *types.CancelRetrievePropertiesEx) (*types.CancelRetrievePropertiesExResponse, error) {
	return methods.CancelRetrievePropertiesEx(ctx, r, req)
}

func (_ *ImplContext) CancelStorageDrsRecommendation(ctx context.Context, r soap.RoundTripper, req *types.CancelStorageDrsRecommendation) (*types.CancelStorageDrsRecommendationResponse, error) {
	return methods.CancelStorageDrsRecommendation(ctx, r, req)
}

func (_ *ImplContext) CancelTask(ctx context.Context, r soap.RoundTripper, req *types.CancelTask) (*types.CancelTaskResponse, error) {
	return methods.CancelTask(ctx, r, req)
}

func (_ *ImplContext) CancelWaitForUpdates(ctx context.Context, r soap.RoundTripper, req *types.CancelWaitForUpdates) (*types.CancelWaitForUpdatesResponse, error) {
	return methods.CancelWaitForUpdates(ctx, r, req)
}

func (_ *ImplContext) CertMgrRefreshCACertificatesAndCRLs_Task(ctx context.Context, r soap.RoundTripper, req *types.CertMgrRefreshCACertificatesAndCRLs_Task) (*types.CertMgrRefreshCACertificatesAndCRLs_TaskResponse, error) {
	return methods.CertMgrRefreshCACertificatesAndCRLs_Task(ctx, r, req)
}

func (_ *ImplContext) CertMgrRefreshCertificates_Task(ctx context.Context, r soap.RoundTripper, req *types.CertMgrRefreshCertificates_Task) (*types.CertMgrRefreshCertificates_TaskResponse, error) {
	return methods.CertMgrRefreshCertificates_Task(ctx, r, req)
}

func (_ *ImplContext) CertMgrRevokeCertificates_Task(ctx context.Context, r soap.RoundTripper, req *types.CertMgrRevokeCertificates_Task) (*types.CertMgrRevokeCertificates_TaskResponse, error) {
	return methods.CertMgrRevokeCertificates_Task(ctx, r, req)
}

func (_ *ImplContext) ChangeAccessMode(ctx context.Context, r soap.RoundTripper, req *types.ChangeAccessMode) (*types.ChangeAccessModeResponse, error) {
	return methods.ChangeAccessMode(ctx, r, req)
}

func (_ *ImplContext) ChangeFileAttributesInGuest(ctx context.Context, r soap.RoundTripper, req *types.ChangeFileAttributesInGuest) (*types.ChangeFileAttributesInGuestResponse, error) {
	return methods.ChangeFileAttributesInGuest(ctx, r, req)
}

func (_ *ImplContext) ChangeLockdownMode(ctx context.Context, r soap.RoundTripper, req *types.ChangeLockdownMode) (*types.ChangeLockdownModeResponse, error) {
	return methods.ChangeLockdownMode(ctx, r, req)
}

func (_ *ImplContext) ChangeNFSUserPassword(ctx context.Context, r soap.RoundTripper, req *types.ChangeNFSUserPassword) (*types.ChangeNFSUserPasswordResponse, error) {
	return methods.ChangeNFSUserPassword(ctx, r, req)
}

func (_ *ImplContext) ChangeOwner(ctx context.Context, r soap.RoundTripper, req *types.ChangeOwner) (*types.ChangeOwnerResponse, error) {
	return methods.ChangeOwner(ctx, r, req)
}

func (_ *ImplContext) CheckAddHostEvc_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckAddHostEvc_Task) (*types.CheckAddHostEvc_TaskResponse, error) {
	return methods.CheckAddHostEvc_Task(ctx, r, req)
}

func (_ *ImplContext) CheckAnswerFileStatus_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckAnswerFileStatus_Task) (*types.CheckAnswerFileStatus_TaskResponse, error) {
	return methods.CheckAnswerFileStatus_Task(ctx, r, req)
}

func (_ *ImplContext) CheckCompatibility_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckCompatibility_Task) (*types.CheckCompatibility_TaskResponse, error) {
	return methods.CheckCompatibility_Task(ctx, r, req)
}

func (_ *ImplContext) CheckCompliance_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckCompliance_Task) (*types.CheckCompliance_TaskResponse, error) {
	return methods.CheckCompliance_Task(ctx, r, req)
}

func (_ *ImplContext) CheckConfigureEvcMode_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckConfigureEvcMode_Task) (*types.CheckConfigureEvcMode_TaskResponse, error) {
	return methods.CheckConfigureEvcMode_Task(ctx, r, req)
}

func (_ *ImplContext) CheckCustomizationResources(ctx context.Context, r soap.RoundTripper, req *types.CheckCustomizationResources) (*types.CheckCustomizationResourcesResponse, error) {
	return methods.CheckCustomizationResources(ctx, r, req)
}

func (_ *ImplContext) CheckCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.CheckCustomizationSpec) (*types.CheckCustomizationSpecResponse, error) {
	return methods.CheckCustomizationSpec(ctx, r, req)
}

func (_ *ImplContext) CheckForUpdates(ctx context.Context, r soap.RoundTripper, req *types.CheckForUpdates) (*types.CheckForUpdatesResponse, error) {
	return methods.CheckForUpdates(ctx, r, req)
}

func (_ *ImplContext) CheckHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckHostPatch_Task) (*types.CheckHostPatch_TaskResponse, error) {
	return methods.CheckHostPatch_Task(ctx, r, req)
}

func (_ *ImplContext) CheckLicenseFeature(ctx context.Context, r soap.RoundTripper, req *types.CheckLicenseFeature) (*types.CheckLicenseFeatureResponse, error) {
	return methods.CheckLicenseFeature(ctx, r, req)
}

func (_ *ImplContext) CheckMigrate_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckMigrate_Task) (*types.CheckMigrate_TaskResponse, error) {
	return methods.CheckMigrate_Task(ctx, r, req)
}

func (_ *ImplContext) CheckProfileCompliance_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckProfileCompliance_Task) (*types.CheckProfileCompliance_TaskResponse, error) {
	return methods.CheckProfileCompliance_Task(ctx, r, req)
}

func (_ *ImplContext) CheckRelocate_Task(ctx context.Context, r soap.RoundTripper, req *types.CheckRelocate_Task) (*types.CheckRelocate_TaskResponse, error) {
	return methods.CheckRelocate_Task(ctx, r, req)
}

func (_ *ImplContext) ClearComplianceStatus(ctx context.Context, r soap.RoundTripper, req *types.ClearComplianceStatus) (*types.ClearComplianceStatusResponse, error) {
	return methods.ClearComplianceStatus(ctx, r, req)
}

func (_ *ImplContext) ClearNFSUser(ctx context.Context, r soap.RoundTripper, req *types.ClearNFSUser) (*types.ClearNFSUserResponse, error) {
	return methods.ClearNFSUser(ctx, r, req)
}

func (_ *ImplContext) ClearSystemEventLog(ctx context.Context, r soap.RoundTripper, req *types.ClearSystemEventLog) (*types.ClearSystemEventLogResponse, error) {
	return methods.ClearSystemEventLog(ctx, r, req)
}

func (_ *ImplContext) CloneSession(ctx context.Context, r soap.RoundTripper, req *types.CloneSession) (*types.CloneSessionResponse, error) {
	return methods.CloneSession(ctx, r, req)
}

func (_ *ImplContext) CloneVApp_Task(ctx context.Context, r soap.RoundTripper, req *types.CloneVApp_Task) (*types.CloneVApp_TaskResponse, error) {
	return methods.CloneVApp_Task(ctx, r, req)
}

func (_ *ImplContext) CloneVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CloneVM_Task) (*types.CloneVM_TaskResponse, error) {
	return methods.CloneVM_Task(ctx, r, req)
}

func (_ *ImplContext) CloneVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.CloneVStorageObject_Task) (*types.CloneVStorageObject_TaskResponse, error) {
	return methods.CloneVStorageObject_Task(ctx, r, req)
}

func (_ *ImplContext) CloseInventoryViewFolder(ctx context.Context, r soap.RoundTripper, req *types.CloseInventoryViewFolder) (*types.CloseInventoryViewFolderResponse, error) {
	return methods.CloseInventoryViewFolder(ctx, r, req)
}

func (_ *ImplContext) ClusterEnterMaintenanceMode(ctx context.Context, r soap.RoundTripper, req *types.ClusterEnterMaintenanceMode) (*types.ClusterEnterMaintenanceModeResponse, error) {
	return methods.ClusterEnterMaintenanceMode(ctx, r, req)
}

func (_ *ImplContext) ComputeDiskPartitionInfo(ctx context.Context, r soap.RoundTripper, req *types.ComputeDiskPartitionInfo) (*types.ComputeDiskPartitionInfoResponse, error) {
	return methods.ComputeDiskPartitionInfo(ctx, r, req)
}

func (_ *ImplContext) ComputeDiskPartitionInfoForResize(ctx context.Context, r soap.RoundTripper, req *types.ComputeDiskPartitionInfoForResize) (*types.ComputeDiskPartitionInfoForResizeResponse, error) {
	return methods.ComputeDiskPartitionInfoForResize(ctx, r, req)
}

func (_ *ImplContext) ConfigureCryptoKey(ctx context.Context, r soap.RoundTripper, req *types.ConfigureCryptoKey) (*types.ConfigureCryptoKeyResponse, error) {
	return methods.ConfigureCryptoKey(ctx, r, req)
}

func (_ *ImplContext) ConfigureDatastoreIORM_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureDatastoreIORM_Task) (*types.ConfigureDatastoreIORM_TaskResponse, error) {
	return methods.ConfigureDatastoreIORM_Task(ctx, r, req)
}

func (_ *ImplContext) ConfigureDatastorePrincipal(ctx context.Context, r soap.RoundTripper, req *types.ConfigureDatastorePrincipal) (*types.ConfigureDatastorePrincipalResponse, error) {
	return methods.ConfigureDatastorePrincipal(ctx, r, req)
}

func (_ *ImplContext) ConfigureEvcMode_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureEvcMode_Task) (*types.ConfigureEvcMode_TaskResponse, error) {
	return methods.ConfigureEvcMode_Task(ctx, r, req)
}

func (_ *ImplContext) ConfigureHostCache_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureHostCache_Task) (*types.ConfigureHostCache_TaskResponse, error) {
	return methods.ConfigureHostCache_Task(ctx, r, req)
}

func (_ *ImplContext) ConfigureLicenseSource(ctx context.Context, r soap.RoundTripper, req *types.ConfigureLicenseSource) (*types.ConfigureLicenseSourceResponse, error) {
	return methods.ConfigureLicenseSource(ctx, r, req)
}

func (_ *ImplContext) ConfigurePowerPolicy(ctx context.Context, r soap.RoundTripper, req *types.ConfigurePowerPolicy) (*types.ConfigurePowerPolicyResponse, error) {
	return methods.ConfigurePowerPolicy(ctx, r, req)
}

func (_ *ImplContext) ConfigureStorageDrsForPod_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureStorageDrsForPod_Task) (*types.ConfigureStorageDrsForPod_TaskResponse, error) {
	return methods.ConfigureStorageDrsForPod_Task(ctx, r, req)
}

func (_ *ImplContext) ConfigureVFlashResourceEx_Task(ctx context.Context, r soap.RoundTripper, req *types.ConfigureVFlashResourceEx_Task) (*types.ConfigureVFlashResourceEx_TaskResponse, error) {
	return methods.ConfigureVFlashResourceEx_Task(ctx, r, req)
}

func (_ *ImplContext) ConsolidateVMDisks_Task(ctx context.Context, r soap.RoundTripper, req *types.ConsolidateVMDisks_Task) (*types.ConsolidateVMDisks_TaskResponse, error) {
	return methods.ConsolidateVMDisks_Task(ctx, r, req)
}

func (_ *ImplContext) ContinueRetrievePropertiesEx(ctx context.Context, r soap.RoundTripper, req *types.ContinueRetrievePropertiesEx) (*types.ContinueRetrievePropertiesExResponse, error) {
	return methods.ContinueRetrievePropertiesEx(ctx, r, req)
}

func (_ *ImplContext) ConvertNamespacePathToUuidPath(ctx context.Context, r soap.RoundTripper, req *types.ConvertNamespacePathToUuidPath) (*types.ConvertNamespacePathToUuidPathResponse, error) {
	return methods.ConvertNamespacePathToUuidPath(ctx, r, req)
}

func (_ *ImplContext) CopyDatastoreFile_Task(ctx context.Context, r soap.RoundTripper, req *types.CopyDatastoreFile_Task) (*types.CopyDatastoreFile_TaskResponse, error) {
	return methods.CopyDatastoreFile_Task(ctx, r, req)
}

func (_ *ImplContext) CopyVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.CopyVirtualDisk_Task) (*types.CopyVirtualDisk_TaskResponse, error) {
	return methods.CopyVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) CreateAlarm(ctx context.Context, r soap.RoundTripper, req *types.CreateAlarm) (*types.CreateAlarmResponse, error) {
	return methods.CreateAlarm(ctx, r, req)
}

func (_ *ImplContext) CreateChildVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateChildVM_Task) (*types.CreateChildVM_TaskResponse, error) {
	return methods.CreateChildVM_Task(ctx, r, req)
}

func (_ *ImplContext) CreateCluster(ctx context.Context, r soap.RoundTripper, req *types.CreateCluster) (*types.CreateClusterResponse, error) {
	return methods.CreateCluster(ctx, r, req)
}

func (_ *ImplContext) CreateClusterEx(ctx context.Context, r soap.RoundTripper, req *types.CreateClusterEx) (*types.CreateClusterExResponse, error) {
	return methods.CreateClusterEx(ctx, r, req)
}

func (_ *ImplContext) CreateCollectorForEvents(ctx context.Context, r soap.RoundTripper, req *types.CreateCollectorForEvents) (*types.CreateCollectorForEventsResponse, error) {
	return methods.CreateCollectorForEvents(ctx, r, req)
}

func (_ *ImplContext) CreateCollectorForTasks(ctx context.Context, r soap.RoundTripper, req *types.CreateCollectorForTasks) (*types.CreateCollectorForTasksResponse, error) {
	return methods.CreateCollectorForTasks(ctx, r, req)
}

func (_ *ImplContext) CreateContainerView(ctx context.Context, r soap.RoundTripper, req *types.CreateContainerView) (*types.CreateContainerViewResponse, error) {
	return methods.CreateContainerView(ctx, r, req)
}

func (_ *ImplContext) CreateCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.CreateCustomizationSpec) (*types.CreateCustomizationSpecResponse, error) {
	return methods.CreateCustomizationSpec(ctx, r, req)
}

func (_ *ImplContext) CreateDVPortgroup_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateDVPortgroup_Task) (*types.CreateDVPortgroup_TaskResponse, error) {
	return methods.CreateDVPortgroup_Task(ctx, r, req)
}

func (_ *ImplContext) CreateDVS_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateDVS_Task) (*types.CreateDVS_TaskResponse, error) {
	return methods.CreateDVS_Task(ctx, r, req)
}

func (_ *ImplContext) CreateDatacenter(ctx context.Context, r soap.RoundTripper, req *types.CreateDatacenter) (*types.CreateDatacenterResponse, error) {
	return methods.CreateDatacenter(ctx, r, req)
}

func (_ *ImplContext) CreateDefaultProfile(ctx context.Context, r soap.RoundTripper, req *types.CreateDefaultProfile) (*types.CreateDefaultProfileResponse, error) {
	return methods.CreateDefaultProfile(ctx, r, req)
}

func (_ *ImplContext) CreateDescriptor(ctx context.Context, r soap.RoundTripper, req *types.CreateDescriptor) (*types.CreateDescriptorResponse, error) {
	return methods.CreateDescriptor(ctx, r, req)
}

func (_ *ImplContext) CreateDiagnosticPartition(ctx context.Context, r soap.RoundTripper, req *types.CreateDiagnosticPartition) (*types.CreateDiagnosticPartitionResponse, error) {
	return methods.CreateDiagnosticPartition(ctx, r, req)
}

func (_ *ImplContext) CreateDirectory(ctx context.Context, r soap.RoundTripper, req *types.CreateDirectory) (*types.CreateDirectoryResponse, error) {
	return methods.CreateDirectory(ctx, r, req)
}

func (_ *ImplContext) CreateDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateDisk_Task) (*types.CreateDisk_TaskResponse, error) {
	return methods.CreateDisk_Task(ctx, r, req)
}

func (_ *ImplContext) CreateFilter(ctx context.Context, r soap.RoundTripper, req *types.CreateFilter) (*types.CreateFilterResponse, error) {
	return methods.CreateFilter(ctx, r, req)
}

func (_ *ImplContext) CreateFolder(ctx context.Context, r soap.RoundTripper, req *types.CreateFolder) (*types.CreateFolderResponse, error) {
	return methods.CreateFolder(ctx, r, req)
}

func (_ *ImplContext) CreateGroup(ctx context.Context, r soap.RoundTripper, req *types.CreateGroup) (*types.CreateGroupResponse, error) {
	return methods.CreateGroup(ctx, r, req)
}

func (_ *ImplContext) CreateImportSpec(ctx context.Context, r soap.RoundTripper, req *types.CreateImportSpec) (*types.CreateImportSpecResponse, error) {
	return methods.CreateImportSpec(ctx, r, req)
}

func (_ *ImplContext) CreateInventoryView(ctx context.Context, r soap.RoundTripper, req *types.CreateInventoryView) (*types.CreateInventoryViewResponse, error) {
	return methods.CreateInventoryView(ctx, r, req)
}

func (_ *ImplContext) CreateIpPool(ctx context.Context, r soap.RoundTripper, req *types.CreateIpPool) (*types.CreateIpPoolResponse, error) {
	return methods.CreateIpPool(ctx, r, req)
}

func (_ *ImplContext) CreateListView(ctx context.Context, r soap.RoundTripper, req *types.CreateListView) (*types.CreateListViewResponse, error) {
	return methods.CreateListView(ctx, r, req)
}

func (_ *ImplContext) CreateListViewFromView(ctx context.Context, r soap.RoundTripper, req *types.CreateListViewFromView) (*types.CreateListViewFromViewResponse, error) {
	return methods.CreateListViewFromView(ctx, r, req)
}

func (_ *ImplContext) CreateLocalDatastore(ctx context.Context, r soap.RoundTripper, req *types.CreateLocalDatastore) (*types.CreateLocalDatastoreResponse, error) {
	return methods.CreateLocalDatastore(ctx, r, req)
}

func (_ *ImplContext) CreateNasDatastore(ctx context.Context, r soap.RoundTripper, req *types.CreateNasDatastore) (*types.CreateNasDatastoreResponse, error) {
	return methods.CreateNasDatastore(ctx, r, req)
}

func (_ *ImplContext) CreateObjectScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.CreateObjectScheduledTask) (*types.CreateObjectScheduledTaskResponse, error) {
	return methods.CreateObjectScheduledTask(ctx, r, req)
}

func (_ *ImplContext) CreatePerfInterval(ctx context.Context, r soap.RoundTripper, req *types.CreatePerfInterval) (*types.CreatePerfIntervalResponse, error) {
	return methods.CreatePerfInterval(ctx, r, req)
}

func (_ *ImplContext) CreateProfile(ctx context.Context, r soap.RoundTripper, req *types.CreateProfile) (*types.CreateProfileResponse, error) {
	return methods.CreateProfile(ctx, r, req)
}

func (_ *ImplContext) CreatePropertyCollector(ctx context.Context, r soap.RoundTripper, req *types.CreatePropertyCollector) (*types.CreatePropertyCollectorResponse, error) {
	return methods.CreatePropertyCollector(ctx, r, req)
}

func (_ *ImplContext) CreateRegistryKeyInGuest(ctx context.Context, r soap.RoundTripper, req *types.CreateRegistryKeyInGuest) (*types.CreateRegistryKeyInGuestResponse, error) {
	return methods.CreateRegistryKeyInGuest(ctx, r, req)
}

func (_ *ImplContext) CreateResourcePool(ctx context.Context, r soap.RoundTripper, req *types.CreateResourcePool) (*types.CreateResourcePoolResponse, error) {
	return methods.CreateResourcePool(ctx, r, req)
}

func (_ *ImplContext) CreateScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.CreateScheduledTask) (*types.CreateScheduledTaskResponse, error) {
	return methods.CreateScheduledTask(ctx, r, req)
}

func (_ *ImplContext) CreateScreenshot_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateScreenshot_Task) (*types.CreateScreenshot_TaskResponse, error) {
	return methods.CreateScreenshot_Task(ctx, r, req)
}

func (_ *ImplContext) CreateSecondaryVMEx_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateSecondaryVMEx_Task) (*types.CreateSecondaryVMEx_TaskResponse, error) {
	return methods.CreateSecondaryVMEx_Task(ctx, r, req)
}

func (_ *ImplContext) CreateSecondaryVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateSecondaryVM_Task) (*types.CreateSecondaryVM_TaskResponse, error) {
	return methods.CreateSecondaryVM_Task(ctx, r, req)
}

func (_ *ImplContext) CreateSnapshotEx_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateSnapshotEx_Task) (*types.CreateSnapshotEx_TaskResponse, error) {
	return methods.CreateSnapshotEx_Task(ctx, r, req)
}

func (_ *ImplContext) CreateSnapshot_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateSnapshot_Task) (*types.CreateSnapshot_TaskResponse, error) {
	return methods.CreateSnapshot_Task(ctx, r, req)
}

func (_ *ImplContext) CreateStoragePod(ctx context.Context, r soap.RoundTripper, req *types.CreateStoragePod) (*types.CreateStoragePodResponse, error) {
	return methods.CreateStoragePod(ctx, r, req)
}

func (_ *ImplContext) CreateTask(ctx context.Context, r soap.RoundTripper, req *types.CreateTask) (*types.CreateTaskResponse, error) {
	return methods.CreateTask(ctx, r, req)
}

func (_ *ImplContext) CreateTemporaryDirectoryInGuest(ctx context.Context, r soap.RoundTripper, req *types.CreateTemporaryDirectoryInGuest) (*types.CreateTemporaryDirectoryInGuestResponse, error) {
	return methods.CreateTemporaryDirectoryInGuest(ctx, r, req)
}

func (_ *ImplContext) CreateTemporaryFileInGuest(ctx context.Context, r soap.RoundTripper, req *types.CreateTemporaryFileInGuest) (*types.CreateTemporaryFileInGuestResponse, error) {
	return methods.CreateTemporaryFileInGuest(ctx, r, req)
}

func (_ *ImplContext) CreateUser(ctx context.Context, r soap.RoundTripper, req *types.CreateUser) (*types.CreateUserResponse, error) {
	return methods.CreateUser(ctx, r, req)
}

func (_ *ImplContext) CreateVApp(ctx context.Context, r soap.RoundTripper, req *types.CreateVApp) (*types.CreateVAppResponse, error) {
	return methods.CreateVApp(ctx, r, req)
}

func (_ *ImplContext) CreateVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateVM_Task) (*types.CreateVM_TaskResponse, error) {
	return methods.CreateVM_Task(ctx, r, req)
}

func (_ *ImplContext) CreateVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.CreateVirtualDisk_Task) (*types.CreateVirtualDisk_TaskResponse, error) {
	return methods.CreateVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) CreateVmfsDatastore(ctx context.Context, r soap.RoundTripper, req *types.CreateVmfsDatastore) (*types.CreateVmfsDatastoreResponse, error) {
	return methods.CreateVmfsDatastore(ctx, r, req)
}

func (_ *ImplContext) CreateVvolDatastore(ctx context.Context, r soap.RoundTripper, req *types.CreateVvolDatastore) (*types.CreateVvolDatastoreResponse, error) {
	return methods.CreateVvolDatastore(ctx, r, req)
}

func (_ *ImplContext) CurrentTime(ctx context.Context, r soap.RoundTripper, req *types.CurrentTime) (*types.CurrentTimeResponse, error) {
	return methods.CurrentTime(ctx, r, req)
}

func (_ *ImplContext) CustomizationSpecItemToXml(ctx context.Context, r soap.RoundTripper, req *types.CustomizationSpecItemToXml) (*types.CustomizationSpecItemToXmlResponse, error) {
	return methods.CustomizationSpecItemToXml(ctx, r, req)
}

func (_ *ImplContext) CustomizeVM_Task(ctx context.Context, r soap.RoundTripper, req *types.CustomizeVM_Task) (*types.CustomizeVM_TaskResponse, error) {
	return methods.CustomizeVM_Task(ctx, r, req)
}

func (_ *ImplContext) DVPortgroupRollback_Task(ctx context.Context, r soap.RoundTripper, req *types.DVPortgroupRollback_Task) (*types.DVPortgroupRollback_TaskResponse, error) {
	return methods.DVPortgroupRollback_Task(ctx, r, req)
}

func (_ *ImplContext) DVSManagerExportEntity_Task(ctx context.Context, r soap.RoundTripper, req *types.DVSManagerExportEntity_Task) (*types.DVSManagerExportEntity_TaskResponse, error) {
	return methods.DVSManagerExportEntity_Task(ctx, r, req)
}

func (_ *ImplContext) DVSManagerImportEntity_Task(ctx context.Context, r soap.RoundTripper, req *types.DVSManagerImportEntity_Task) (*types.DVSManagerImportEntity_TaskResponse, error) {
	return methods.DVSManagerImportEntity_Task(ctx, r, req)
}

func (_ *ImplContext) DVSManagerLookupDvPortGroup(ctx context.Context, r soap.RoundTripper, req *types.DVSManagerLookupDvPortGroup) (*types.DVSManagerLookupDvPortGroupResponse, error) {
	return methods.DVSManagerLookupDvPortGroup(ctx, r, req)
}

func (_ *ImplContext) DVSRollback_Task(ctx context.Context, r soap.RoundTripper, req *types.DVSRollback_Task) (*types.DVSRollback_TaskResponse, error) {
	return methods.DVSRollback_Task(ctx, r, req)
}

func (_ *ImplContext) DatastoreEnterMaintenanceMode(ctx context.Context, r soap.RoundTripper, req *types.DatastoreEnterMaintenanceMode) (*types.DatastoreEnterMaintenanceModeResponse, error) {
	return methods.DatastoreEnterMaintenanceMode(ctx, r, req)
}

func (_ *ImplContext) DatastoreExitMaintenanceMode_Task(ctx context.Context, r soap.RoundTripper, req *types.DatastoreExitMaintenanceMode_Task) (*types.DatastoreExitMaintenanceMode_TaskResponse, error) {
	return methods.DatastoreExitMaintenanceMode_Task(ctx, r, req)
}

func (_ *ImplContext) DecodeLicense(ctx context.Context, r soap.RoundTripper, req *types.DecodeLicense) (*types.DecodeLicenseResponse, error) {
	return methods.DecodeLicense(ctx, r, req)
}

func (_ *ImplContext) DefragmentAllDisks(ctx context.Context, r soap.RoundTripper, req *types.DefragmentAllDisks) (*types.DefragmentAllDisksResponse, error) {
	return methods.DefragmentAllDisks(ctx, r, req)
}

func (_ *ImplContext) DefragmentVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.DefragmentVirtualDisk_Task) (*types.DefragmentVirtualDisk_TaskResponse, error) {
	return methods.DefragmentVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) DeleteCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.DeleteCustomizationSpec) (*types.DeleteCustomizationSpecResponse, error) {
	return methods.DeleteCustomizationSpec(ctx, r, req)
}

func (_ *ImplContext) DeleteDatastoreFile_Task(ctx context.Context, r soap.RoundTripper, req *types.DeleteDatastoreFile_Task) (*types.DeleteDatastoreFile_TaskResponse, error) {
	return methods.DeleteDatastoreFile_Task(ctx, r, req)
}

func (_ *ImplContext) DeleteDirectory(ctx context.Context, r soap.RoundTripper, req *types.DeleteDirectory) (*types.DeleteDirectoryResponse, error) {
	return methods.DeleteDirectory(ctx, r, req)
}

func (_ *ImplContext) DeleteDirectoryInGuest(ctx context.Context, r soap.RoundTripper, req *types.DeleteDirectoryInGuest) (*types.DeleteDirectoryInGuestResponse, error) {
	return methods.DeleteDirectoryInGuest(ctx, r, req)
}

func (_ *ImplContext) DeleteFile(ctx context.Context, r soap.RoundTripper, req *types.DeleteFile) (*types.DeleteFileResponse, error) {
	return methods.DeleteFile(ctx, r, req)
}

func (_ *ImplContext) DeleteFileInGuest(ctx context.Context, r soap.RoundTripper, req *types.DeleteFileInGuest) (*types.DeleteFileInGuestResponse, error) {
	return methods.DeleteFileInGuest(ctx, r, req)
}

func (_ *ImplContext) DeleteHostSpecification(ctx context.Context, r soap.RoundTripper, req *types.DeleteHostSpecification) (*types.DeleteHostSpecificationResponse, error) {
	return methods.DeleteHostSpecification(ctx, r, req)
}

func (_ *ImplContext) DeleteHostSubSpecification(ctx context.Context, r soap.RoundTripper, req *types.DeleteHostSubSpecification) (*types.DeleteHostSubSpecificationResponse, error) {
	return methods.DeleteHostSubSpecification(ctx, r, req)
}

func (_ *ImplContext) DeleteRegistryKeyInGuest(ctx context.Context, r soap.RoundTripper, req *types.DeleteRegistryKeyInGuest) (*types.DeleteRegistryKeyInGuestResponse, error) {
	return methods.DeleteRegistryKeyInGuest(ctx, r, req)
}

func (_ *ImplContext) DeleteRegistryValueInGuest(ctx context.Context, r soap.RoundTripper, req *types.DeleteRegistryValueInGuest) (*types.DeleteRegistryValueInGuestResponse, error) {
	return methods.DeleteRegistryValueInGuest(ctx, r, req)
}

func (_ *ImplContext) DeleteScsiLunState(ctx context.Context, r soap.RoundTripper, req *types.DeleteScsiLunState) (*types.DeleteScsiLunStateResponse, error) {
	return methods.DeleteScsiLunState(ctx, r, req)
}

func (_ *ImplContext) DeleteVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.DeleteVStorageObject_Task) (*types.DeleteVStorageObject_TaskResponse, error) {
	return methods.DeleteVStorageObject_Task(ctx, r, req)
}

func (_ *ImplContext) DeleteVffsVolumeState(ctx context.Context, r soap.RoundTripper, req *types.DeleteVffsVolumeState) (*types.DeleteVffsVolumeStateResponse, error) {
	return methods.DeleteVffsVolumeState(ctx, r, req)
}

func (_ *ImplContext) DeleteVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.DeleteVirtualDisk_Task) (*types.DeleteVirtualDisk_TaskResponse, error) {
	return methods.DeleteVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) DeleteVmfsVolumeState(ctx context.Context, r soap.RoundTripper, req *types.DeleteVmfsVolumeState) (*types.DeleteVmfsVolumeStateResponse, error) {
	return methods.DeleteVmfsVolumeState(ctx, r, req)
}

func (_ *ImplContext) DeleteVsanObjects(ctx context.Context, r soap.RoundTripper, req *types.DeleteVsanObjects) (*types.DeleteVsanObjectsResponse, error) {
	return methods.DeleteVsanObjects(ctx, r, req)
}

func (_ *ImplContext) DeselectVnic(ctx context.Context, r soap.RoundTripper, req *types.DeselectVnic) (*types.DeselectVnicResponse, error) {
	return methods.DeselectVnic(ctx, r, req)
}

func (_ *ImplContext) DeselectVnicForNicType(ctx context.Context, r soap.RoundTripper, req *types.DeselectVnicForNicType) (*types.DeselectVnicForNicTypeResponse, error) {
	return methods.DeselectVnicForNicType(ctx, r, req)
}

func (_ *ImplContext) DestroyChildren(ctx context.Context, r soap.RoundTripper, req *types.DestroyChildren) (*types.DestroyChildrenResponse, error) {
	return methods.DestroyChildren(ctx, r, req)
}

func (_ *ImplContext) DestroyCollector(ctx context.Context, r soap.RoundTripper, req *types.DestroyCollector) (*types.DestroyCollectorResponse, error) {
	return methods.DestroyCollector(ctx, r, req)
}

func (_ *ImplContext) DestroyDatastore(ctx context.Context, r soap.RoundTripper, req *types.DestroyDatastore) (*types.DestroyDatastoreResponse, error) {
	return methods.DestroyDatastore(ctx, r, req)
}

func (_ *ImplContext) DestroyIpPool(ctx context.Context, r soap.RoundTripper, req *types.DestroyIpPool) (*types.DestroyIpPoolResponse, error) {
	return methods.DestroyIpPool(ctx, r, req)
}

func (_ *ImplContext) DestroyNetwork(ctx context.Context, r soap.RoundTripper, req *types.DestroyNetwork) (*types.DestroyNetworkResponse, error) {
	return methods.DestroyNetwork(ctx, r, req)
}

func (_ *ImplContext) DestroyProfile(ctx context.Context, r soap.RoundTripper, req *types.DestroyProfile) (*types.DestroyProfileResponse, error) {
	return methods.DestroyProfile(ctx, r, req)
}

func (_ *ImplContext) DestroyPropertyCollector(ctx context.Context, r soap.RoundTripper, req *types.DestroyPropertyCollector) (*types.DestroyPropertyCollectorResponse, error) {
	return methods.DestroyPropertyCollector(ctx, r, req)
}

func (_ *ImplContext) DestroyPropertyFilter(ctx context.Context, r soap.RoundTripper, req *types.DestroyPropertyFilter) (*types.DestroyPropertyFilterResponse, error) {
	return methods.DestroyPropertyFilter(ctx, r, req)
}

func (_ *ImplContext) DestroyVffs(ctx context.Context, r soap.RoundTripper, req *types.DestroyVffs) (*types.DestroyVffsResponse, error) {
	return methods.DestroyVffs(ctx, r, req)
}

func (_ *ImplContext) DestroyView(ctx context.Context, r soap.RoundTripper, req *types.DestroyView) (*types.DestroyViewResponse, error) {
	return methods.DestroyView(ctx, r, req)
}

func (_ *ImplContext) Destroy_Task(ctx context.Context, r soap.RoundTripper, req *types.Destroy_Task) (*types.Destroy_TaskResponse, error) {
	return methods.Destroy_Task(ctx, r, req)
}

func (_ *ImplContext) DetachDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.DetachDisk_Task) (*types.DetachDisk_TaskResponse, error) {
	return methods.DetachDisk_Task(ctx, r, req)
}

func (_ *ImplContext) DetachScsiLun(ctx context.Context, r soap.RoundTripper, req *types.DetachScsiLun) (*types.DetachScsiLunResponse, error) {
	return methods.DetachScsiLun(ctx, r, req)
}

func (_ *ImplContext) DetachScsiLunEx_Task(ctx context.Context, r soap.RoundTripper, req *types.DetachScsiLunEx_Task) (*types.DetachScsiLunEx_TaskResponse, error) {
	return methods.DetachScsiLunEx_Task(ctx, r, req)
}

func (_ *ImplContext) DetachTagFromVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.DetachTagFromVStorageObject) (*types.DetachTagFromVStorageObjectResponse, error) {
	return methods.DetachTagFromVStorageObject(ctx, r, req)
}

func (_ *ImplContext) DisableEvcMode_Task(ctx context.Context, r soap.RoundTripper, req *types.DisableEvcMode_Task) (*types.DisableEvcMode_TaskResponse, error) {
	return methods.DisableEvcMode_Task(ctx, r, req)
}

func (_ *ImplContext) DisableFeature(ctx context.Context, r soap.RoundTripper, req *types.DisableFeature) (*types.DisableFeatureResponse, error) {
	return methods.DisableFeature(ctx, r, req)
}

func (_ *ImplContext) DisableHyperThreading(ctx context.Context, r soap.RoundTripper, req *types.DisableHyperThreading) (*types.DisableHyperThreadingResponse, error) {
	return methods.DisableHyperThreading(ctx, r, req)
}

func (_ *ImplContext) DisableMultipathPath(ctx context.Context, r soap.RoundTripper, req *types.DisableMultipathPath) (*types.DisableMultipathPathResponse, error) {
	return methods.DisableMultipathPath(ctx, r, req)
}

func (_ *ImplContext) DisableRuleset(ctx context.Context, r soap.RoundTripper, req *types.DisableRuleset) (*types.DisableRulesetResponse, error) {
	return methods.DisableRuleset(ctx, r, req)
}

func (_ *ImplContext) DisableSecondaryVM_Task(ctx context.Context, r soap.RoundTripper, req *types.DisableSecondaryVM_Task) (*types.DisableSecondaryVM_TaskResponse, error) {
	return methods.DisableSecondaryVM_Task(ctx, r, req)
}

func (_ *ImplContext) DisableSmartCardAuthentication(ctx context.Context, r soap.RoundTripper, req *types.DisableSmartCardAuthentication) (*types.DisableSmartCardAuthenticationResponse, error) {
	return methods.DisableSmartCardAuthentication(ctx, r, req)
}

func (_ *ImplContext) DisconnectHost_Task(ctx context.Context, r soap.RoundTripper, req *types.DisconnectHost_Task) (*types.DisconnectHost_TaskResponse, error) {
	return methods.DisconnectHost_Task(ctx, r, req)
}

func (_ *ImplContext) DiscoverFcoeHbas(ctx context.Context, r soap.RoundTripper, req *types.DiscoverFcoeHbas) (*types.DiscoverFcoeHbasResponse, error) {
	return methods.DiscoverFcoeHbas(ctx, r, req)
}

func (_ *ImplContext) DissociateProfile(ctx context.Context, r soap.RoundTripper, req *types.DissociateProfile) (*types.DissociateProfileResponse, error) {
	return methods.DissociateProfile(ctx, r, req)
}

func (_ *ImplContext) DoesCustomizationSpecExist(ctx context.Context, r soap.RoundTripper, req *types.DoesCustomizationSpecExist) (*types.DoesCustomizationSpecExistResponse, error) {
	return methods.DoesCustomizationSpecExist(ctx, r, req)
}

func (_ *ImplContext) DuplicateCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.DuplicateCustomizationSpec) (*types.DuplicateCustomizationSpecResponse, error) {
	return methods.DuplicateCustomizationSpec(ctx, r, req)
}

func (_ *ImplContext) DvsReconfigureVmVnicNetworkResourcePool_Task(ctx context.Context, r soap.RoundTripper, req *types.DvsReconfigureVmVnicNetworkResourcePool_Task) (*types.DvsReconfigureVmVnicNetworkResourcePool_TaskResponse, error) {
	return methods.DvsReconfigureVmVnicNetworkResourcePool_Task(ctx, r, req)
}

func (_ *ImplContext) EagerZeroVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.EagerZeroVirtualDisk_Task) (*types.EagerZeroVirtualDisk_TaskResponse, error) {
	return methods.EagerZeroVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) EnableAlarmActions(ctx context.Context, r soap.RoundTripper, req *types.EnableAlarmActions) (*types.EnableAlarmActionsResponse, error) {
	return methods.EnableAlarmActions(ctx, r, req)
}

func (_ *ImplContext) EnableCrypto(ctx context.Context, r soap.RoundTripper, req *types.EnableCrypto) (*types.EnableCryptoResponse, error) {
	return methods.EnableCrypto(ctx, r, req)
}

func (_ *ImplContext) EnableFeature(ctx context.Context, r soap.RoundTripper, req *types.EnableFeature) (*types.EnableFeatureResponse, error) {
	return methods.EnableFeature(ctx, r, req)
}

func (_ *ImplContext) EnableHyperThreading(ctx context.Context, r soap.RoundTripper, req *types.EnableHyperThreading) (*types.EnableHyperThreadingResponse, error) {
	return methods.EnableHyperThreading(ctx, r, req)
}

func (_ *ImplContext) EnableMultipathPath(ctx context.Context, r soap.RoundTripper, req *types.EnableMultipathPath) (*types.EnableMultipathPathResponse, error) {
	return methods.EnableMultipathPath(ctx, r, req)
}

func (_ *ImplContext) EnableNetworkResourceManagement(ctx context.Context, r soap.RoundTripper, req *types.EnableNetworkResourceManagement) (*types.EnableNetworkResourceManagementResponse, error) {
	return methods.EnableNetworkResourceManagement(ctx, r, req)
}

func (_ *ImplContext) EnableRuleset(ctx context.Context, r soap.RoundTripper, req *types.EnableRuleset) (*types.EnableRulesetResponse, error) {
	return methods.EnableRuleset(ctx, r, req)
}

func (_ *ImplContext) EnableSecondaryVM_Task(ctx context.Context, r soap.RoundTripper, req *types.EnableSecondaryVM_Task) (*types.EnableSecondaryVM_TaskResponse, error) {
	return methods.EnableSecondaryVM_Task(ctx, r, req)
}

func (_ *ImplContext) EnableSmartCardAuthentication(ctx context.Context, r soap.RoundTripper, req *types.EnableSmartCardAuthentication) (*types.EnableSmartCardAuthenticationResponse, error) {
	return methods.EnableSmartCardAuthentication(ctx, r, req)
}

func (_ *ImplContext) EnterLockdownMode(ctx context.Context, r soap.RoundTripper, req *types.EnterLockdownMode) (*types.EnterLockdownModeResponse, error) {
	return methods.EnterLockdownMode(ctx, r, req)
}

func (_ *ImplContext) EnterMaintenanceMode_Task(ctx context.Context, r soap.RoundTripper, req *types.EnterMaintenanceMode_Task) (*types.EnterMaintenanceMode_TaskResponse, error) {
	return methods.EnterMaintenanceMode_Task(ctx, r, req)
}

func (_ *ImplContext) EstimateDatabaseSize(ctx context.Context, r soap.RoundTripper, req *types.EstimateDatabaseSize) (*types.EstimateDatabaseSizeResponse, error) {
	return methods.EstimateDatabaseSize(ctx, r, req)
}

func (_ *ImplContext) EstimateStorageForConsolidateSnapshots_Task(ctx context.Context, r soap.RoundTripper, req *types.EstimateStorageForConsolidateSnapshots_Task) (*types.EstimateStorageForConsolidateSnapshots_TaskResponse, error) {
	return methods.EstimateStorageForConsolidateSnapshots_Task(ctx, r, req)
}

func (_ *ImplContext) EsxAgentHostManagerUpdateConfig(ctx context.Context, r soap.RoundTripper, req *types.EsxAgentHostManagerUpdateConfig) (*types.EsxAgentHostManagerUpdateConfigResponse, error) {
	return methods.EsxAgentHostManagerUpdateConfig(ctx, r, req)
}

func (_ *ImplContext) EvacuateVsanNode_Task(ctx context.Context, r soap.RoundTripper, req *types.EvacuateVsanNode_Task) (*types.EvacuateVsanNode_TaskResponse, error) {
	return methods.EvacuateVsanNode_Task(ctx, r, req)
}

func (_ *ImplContext) EvcManager(ctx context.Context, r soap.RoundTripper, req *types.EvcManager) (*types.EvcManagerResponse, error) {
	return methods.EvcManager(ctx, r, req)
}

func (_ *ImplContext) ExecuteHostProfile(ctx context.Context, r soap.RoundTripper, req *types.ExecuteHostProfile) (*types.ExecuteHostProfileResponse, error) {
	return methods.ExecuteHostProfile(ctx, r, req)
}

func (_ *ImplContext) ExecuteSimpleCommand(ctx context.Context, r soap.RoundTripper, req *types.ExecuteSimpleCommand) (*types.ExecuteSimpleCommandResponse, error) {
	return methods.ExecuteSimpleCommand(ctx, r, req)
}

func (_ *ImplContext) ExitLockdownMode(ctx context.Context, r soap.RoundTripper, req *types.ExitLockdownMode) (*types.ExitLockdownModeResponse, error) {
	return methods.ExitLockdownMode(ctx, r, req)
}

func (_ *ImplContext) ExitMaintenanceMode_Task(ctx context.Context, r soap.RoundTripper, req *types.ExitMaintenanceMode_Task) (*types.ExitMaintenanceMode_TaskResponse, error) {
	return methods.ExitMaintenanceMode_Task(ctx, r, req)
}

func (_ *ImplContext) ExpandVmfsDatastore(ctx context.Context, r soap.RoundTripper, req *types.ExpandVmfsDatastore) (*types.ExpandVmfsDatastoreResponse, error) {
	return methods.ExpandVmfsDatastore(ctx, r, req)
}

func (_ *ImplContext) ExpandVmfsExtent(ctx context.Context, r soap.RoundTripper, req *types.ExpandVmfsExtent) (*types.ExpandVmfsExtentResponse, error) {
	return methods.ExpandVmfsExtent(ctx, r, req)
}

func (_ *ImplContext) ExportAnswerFile_Task(ctx context.Context, r soap.RoundTripper, req *types.ExportAnswerFile_Task) (*types.ExportAnswerFile_TaskResponse, error) {
	return methods.ExportAnswerFile_Task(ctx, r, req)
}

func (_ *ImplContext) ExportProfile(ctx context.Context, r soap.RoundTripper, req *types.ExportProfile) (*types.ExportProfileResponse, error) {
	return methods.ExportProfile(ctx, r, req)
}

func (_ *ImplContext) ExportSnapshot(ctx context.Context, r soap.RoundTripper, req *types.ExportSnapshot) (*types.ExportSnapshotResponse, error) {
	return methods.ExportSnapshot(ctx, r, req)
}

func (_ *ImplContext) ExportVApp(ctx context.Context, r soap.RoundTripper, req *types.ExportVApp) (*types.ExportVAppResponse, error) {
	return methods.ExportVApp(ctx, r, req)
}

func (_ *ImplContext) ExportVm(ctx context.Context, r soap.RoundTripper, req *types.ExportVm) (*types.ExportVmResponse, error) {
	return methods.ExportVm(ctx, r, req)
}

func (_ *ImplContext) ExtendDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.ExtendDisk_Task) (*types.ExtendDisk_TaskResponse, error) {
	return methods.ExtendDisk_Task(ctx, r, req)
}

func (_ *ImplContext) ExtendVffs(ctx context.Context, r soap.RoundTripper, req *types.ExtendVffs) (*types.ExtendVffsResponse, error) {
	return methods.ExtendVffs(ctx, r, req)
}

func (_ *ImplContext) ExtendVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.ExtendVirtualDisk_Task) (*types.ExtendVirtualDisk_TaskResponse, error) {
	return methods.ExtendVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) ExtendVmfsDatastore(ctx context.Context, r soap.RoundTripper, req *types.ExtendVmfsDatastore) (*types.ExtendVmfsDatastoreResponse, error) {
	return methods.ExtendVmfsDatastore(ctx, r, req)
}

func (_ *ImplContext) ExtractOvfEnvironment(ctx context.Context, r soap.RoundTripper, req *types.ExtractOvfEnvironment) (*types.ExtractOvfEnvironmentResponse, error) {
	return methods.ExtractOvfEnvironment(ctx, r, req)
}

func (_ *ImplContext) FetchDVPortKeys(ctx context.Context, r soap.RoundTripper, req *types.FetchDVPortKeys) (*types.FetchDVPortKeysResponse, error) {
	return methods.FetchDVPortKeys(ctx, r, req)
}

func (_ *ImplContext) FetchDVPorts(ctx context.Context, r soap.RoundTripper, req *types.FetchDVPorts) (*types.FetchDVPortsResponse, error) {
	return methods.FetchDVPorts(ctx, r, req)
}

func (_ *ImplContext) FetchSystemEventLog(ctx context.Context, r soap.RoundTripper, req *types.FetchSystemEventLog) (*types.FetchSystemEventLogResponse, error) {
	return methods.FetchSystemEventLog(ctx, r, req)
}

func (_ *ImplContext) FetchUserPrivilegeOnEntities(ctx context.Context, r soap.RoundTripper, req *types.FetchUserPrivilegeOnEntities) (*types.FetchUserPrivilegeOnEntitiesResponse, error) {
	return methods.FetchUserPrivilegeOnEntities(ctx, r, req)
}

func (_ *ImplContext) FindAllByDnsName(ctx context.Context, r soap.RoundTripper, req *types.FindAllByDnsName) (*types.FindAllByDnsNameResponse, error) {
	return methods.FindAllByDnsName(ctx, r, req)
}

func (_ *ImplContext) FindAllByIp(ctx context.Context, r soap.RoundTripper, req *types.FindAllByIp) (*types.FindAllByIpResponse, error) {
	return methods.FindAllByIp(ctx, r, req)
}

func (_ *ImplContext) FindAllByUuid(ctx context.Context, r soap.RoundTripper, req *types.FindAllByUuid) (*types.FindAllByUuidResponse, error) {
	return methods.FindAllByUuid(ctx, r, req)
}

func (_ *ImplContext) FindAssociatedProfile(ctx context.Context, r soap.RoundTripper, req *types.FindAssociatedProfile) (*types.FindAssociatedProfileResponse, error) {
	return methods.FindAssociatedProfile(ctx, r, req)
}

func (_ *ImplContext) FindByDatastorePath(ctx context.Context, r soap.RoundTripper, req *types.FindByDatastorePath) (*types.FindByDatastorePathResponse, error) {
	return methods.FindByDatastorePath(ctx, r, req)
}

func (_ *ImplContext) FindByDnsName(ctx context.Context, r soap.RoundTripper, req *types.FindByDnsName) (*types.FindByDnsNameResponse, error) {
	return methods.FindByDnsName(ctx, r, req)
}

func (_ *ImplContext) FindByInventoryPath(ctx context.Context, r soap.RoundTripper, req *types.FindByInventoryPath) (*types.FindByInventoryPathResponse, error) {
	return methods.FindByInventoryPath(ctx, r, req)
}

func (_ *ImplContext) FindByIp(ctx context.Context, r soap.RoundTripper, req *types.FindByIp) (*types.FindByIpResponse, error) {
	return methods.FindByIp(ctx, r, req)
}

func (_ *ImplContext) FindByUuid(ctx context.Context, r soap.RoundTripper, req *types.FindByUuid) (*types.FindByUuidResponse, error) {
	return methods.FindByUuid(ctx, r, req)
}

func (_ *ImplContext) FindChild(ctx context.Context, r soap.RoundTripper, req *types.FindChild) (*types.FindChildResponse, error) {
	return methods.FindChild(ctx, r, req)
}

func (_ *ImplContext) FindExtension(ctx context.Context, r soap.RoundTripper, req *types.FindExtension) (*types.FindExtensionResponse, error) {
	return methods.FindExtension(ctx, r, req)
}

func (_ *ImplContext) FindRulesForVm(ctx context.Context, r soap.RoundTripper, req *types.FindRulesForVm) (*types.FindRulesForVmResponse, error) {
	return methods.FindRulesForVm(ctx, r, req)
}

func (_ *ImplContext) FormatVffs(ctx context.Context, r soap.RoundTripper, req *types.FormatVffs) (*types.FormatVffsResponse, error) {
	return methods.FormatVffs(ctx, r, req)
}

func (_ *ImplContext) FormatVmfs(ctx context.Context, r soap.RoundTripper, req *types.FormatVmfs) (*types.FormatVmfsResponse, error) {
	return methods.FormatVmfs(ctx, r, req)
}

func (_ *ImplContext) GenerateCertificateSigningRequest(ctx context.Context, r soap.RoundTripper, req *types.GenerateCertificateSigningRequest) (*types.GenerateCertificateSigningRequestResponse, error) {
	return methods.GenerateCertificateSigningRequest(ctx, r, req)
}

func (_ *ImplContext) GenerateCertificateSigningRequestByDn(ctx context.Context, r soap.RoundTripper, req *types.GenerateCertificateSigningRequestByDn) (*types.GenerateCertificateSigningRequestByDnResponse, error) {
	return methods.GenerateCertificateSigningRequestByDn(ctx, r, req)
}

func (_ *ImplContext) GenerateClientCsr(ctx context.Context, r soap.RoundTripper, req *types.GenerateClientCsr) (*types.GenerateClientCsrResponse, error) {
	return methods.GenerateClientCsr(ctx, r, req)
}

func (_ *ImplContext) GenerateConfigTaskList(ctx context.Context, r soap.RoundTripper, req *types.GenerateConfigTaskList) (*types.GenerateConfigTaskListResponse, error) {
	return methods.GenerateConfigTaskList(ctx, r, req)
}

func (_ *ImplContext) GenerateHostConfigTaskSpec_Task(ctx context.Context, r soap.RoundTripper, req *types.GenerateHostConfigTaskSpec_Task) (*types.GenerateHostConfigTaskSpec_TaskResponse, error) {
	return methods.GenerateHostConfigTaskSpec_Task(ctx, r, req)
}

func (_ *ImplContext) GenerateHostProfileTaskList_Task(ctx context.Context, r soap.RoundTripper, req *types.GenerateHostProfileTaskList_Task) (*types.GenerateHostProfileTaskList_TaskResponse, error) {
	return methods.GenerateHostProfileTaskList_Task(ctx, r, req)
}

func (_ *ImplContext) GenerateKey(ctx context.Context, r soap.RoundTripper, req *types.GenerateKey) (*types.GenerateKeyResponse, error) {
	return methods.GenerateKey(ctx, r, req)
}

func (_ *ImplContext) GenerateLogBundles_Task(ctx context.Context, r soap.RoundTripper, req *types.GenerateLogBundles_Task) (*types.GenerateLogBundles_TaskResponse, error) {
	return methods.GenerateLogBundles_Task(ctx, r, req)
}

func (_ *ImplContext) GenerateSelfSignedClientCert(ctx context.Context, r soap.RoundTripper, req *types.GenerateSelfSignedClientCert) (*types.GenerateSelfSignedClientCertResponse, error) {
	return methods.GenerateSelfSignedClientCert(ctx, r, req)
}

func (_ *ImplContext) GetAlarm(ctx context.Context, r soap.RoundTripper, req *types.GetAlarm) (*types.GetAlarmResponse, error) {
	return methods.GetAlarm(ctx, r, req)
}

func (_ *ImplContext) GetAlarmState(ctx context.Context, r soap.RoundTripper, req *types.GetAlarmState) (*types.GetAlarmStateResponse, error) {
	return methods.GetAlarmState(ctx, r, req)
}

func (_ *ImplContext) GetCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.GetCustomizationSpec) (*types.GetCustomizationSpecResponse, error) {
	return methods.GetCustomizationSpec(ctx, r, req)
}

func (_ *ImplContext) GetPublicKey(ctx context.Context, r soap.RoundTripper, req *types.GetPublicKey) (*types.GetPublicKeyResponse, error) {
	return methods.GetPublicKey(ctx, r, req)
}

func (_ *ImplContext) GetResourceUsage(ctx context.Context, r soap.RoundTripper, req *types.GetResourceUsage) (*types.GetResourceUsageResponse, error) {
	return methods.GetResourceUsage(ctx, r, req)
}

func (_ *ImplContext) GetVchaClusterHealth(ctx context.Context, r soap.RoundTripper, req *types.GetVchaClusterHealth) (*types.GetVchaClusterHealthResponse, error) {
	return methods.GetVchaClusterHealth(ctx, r, req)
}

func (_ *ImplContext) GetVsanObjExtAttrs(ctx context.Context, r soap.RoundTripper, req *types.GetVsanObjExtAttrs) (*types.GetVsanObjExtAttrsResponse, error) {
	return methods.GetVsanObjExtAttrs(ctx, r, req)
}

func (_ *ImplContext) HasMonitoredEntity(ctx context.Context, r soap.RoundTripper, req *types.HasMonitoredEntity) (*types.HasMonitoredEntityResponse, error) {
	return methods.HasMonitoredEntity(ctx, r, req)
}

func (_ *ImplContext) HasPrivilegeOnEntities(ctx context.Context, r soap.RoundTripper, req *types.HasPrivilegeOnEntities) (*types.HasPrivilegeOnEntitiesResponse, error) {
	return methods.HasPrivilegeOnEntities(ctx, r, req)
}

func (_ *ImplContext) HasPrivilegeOnEntity(ctx context.Context, r soap.RoundTripper, req *types.HasPrivilegeOnEntity) (*types.HasPrivilegeOnEntityResponse, error) {
	return methods.HasPrivilegeOnEntity(ctx, r, req)
}

func (_ *ImplContext) HasProvider(ctx context.Context, r soap.RoundTripper, req *types.HasProvider) (*types.HasProviderResponse, error) {
	return methods.HasProvider(ctx, r, req)
}

func (_ *ImplContext) HasUserPrivilegeOnEntities(ctx context.Context, r soap.RoundTripper, req *types.HasUserPrivilegeOnEntities) (*types.HasUserPrivilegeOnEntitiesResponse, error) {
	return methods.HasUserPrivilegeOnEntities(ctx, r, req)
}

func (_ *ImplContext) HostCloneVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.HostCloneVStorageObject_Task) (*types.HostCloneVStorageObject_TaskResponse, error) {
	return methods.HostCloneVStorageObject_Task(ctx, r, req)
}

func (_ *ImplContext) HostConfigVFlashCache(ctx context.Context, r soap.RoundTripper, req *types.HostConfigVFlashCache) (*types.HostConfigVFlashCacheResponse, error) {
	return methods.HostConfigVFlashCache(ctx, r, req)
}

func (_ *ImplContext) HostConfigureVFlashResource(ctx context.Context, r soap.RoundTripper, req *types.HostConfigureVFlashResource) (*types.HostConfigureVFlashResourceResponse, error) {
	return methods.HostConfigureVFlashResource(ctx, r, req)
}

func (_ *ImplContext) HostCreateDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.HostCreateDisk_Task) (*types.HostCreateDisk_TaskResponse, error) {
	return methods.HostCreateDisk_Task(ctx, r, req)
}

func (_ *ImplContext) HostDeleteVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.HostDeleteVStorageObject_Task) (*types.HostDeleteVStorageObject_TaskResponse, error) {
	return methods.HostDeleteVStorageObject_Task(ctx, r, req)
}

func (_ *ImplContext) HostExtendDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.HostExtendDisk_Task) (*types.HostExtendDisk_TaskResponse, error) {
	return methods.HostExtendDisk_Task(ctx, r, req)
}

func (_ *ImplContext) HostGetVFlashModuleDefaultConfig(ctx context.Context, r soap.RoundTripper, req *types.HostGetVFlashModuleDefaultConfig) (*types.HostGetVFlashModuleDefaultConfigResponse, error) {
	return methods.HostGetVFlashModuleDefaultConfig(ctx, r, req)
}

func (_ *ImplContext) HostImageConfigGetAcceptance(ctx context.Context, r soap.RoundTripper, req *types.HostImageConfigGetAcceptance) (*types.HostImageConfigGetAcceptanceResponse, error) {
	return methods.HostImageConfigGetAcceptance(ctx, r, req)
}

func (_ *ImplContext) HostImageConfigGetProfile(ctx context.Context, r soap.RoundTripper, req *types.HostImageConfigGetProfile) (*types.HostImageConfigGetProfileResponse, error) {
	return methods.HostImageConfigGetProfile(ctx, r, req)
}

func (_ *ImplContext) HostInflateDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.HostInflateDisk_Task) (*types.HostInflateDisk_TaskResponse, error) {
	return methods.HostInflateDisk_Task(ctx, r, req)
}

func (_ *ImplContext) HostListVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.HostListVStorageObject) (*types.HostListVStorageObjectResponse, error) {
	return methods.HostListVStorageObject(ctx, r, req)
}

func (_ *ImplContext) HostReconcileDatastoreInventory_Task(ctx context.Context, r soap.RoundTripper, req *types.HostReconcileDatastoreInventory_Task) (*types.HostReconcileDatastoreInventory_TaskResponse, error) {
	return methods.HostReconcileDatastoreInventory_Task(ctx, r, req)
}

func (_ *ImplContext) HostRegisterDisk(ctx context.Context, r soap.RoundTripper, req *types.HostRegisterDisk) (*types.HostRegisterDiskResponse, error) {
	return methods.HostRegisterDisk(ctx, r, req)
}

func (_ *ImplContext) HostRelocateVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.HostRelocateVStorageObject_Task) (*types.HostRelocateVStorageObject_TaskResponse, error) {
	return methods.HostRelocateVStorageObject_Task(ctx, r, req)
}

func (_ *ImplContext) HostRemoveVFlashResource(ctx context.Context, r soap.RoundTripper, req *types.HostRemoveVFlashResource) (*types.HostRemoveVFlashResourceResponse, error) {
	return methods.HostRemoveVFlashResource(ctx, r, req)
}

func (_ *ImplContext) HostRenameVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.HostRenameVStorageObject) (*types.HostRenameVStorageObjectResponse, error) {
	return methods.HostRenameVStorageObject(ctx, r, req)
}

func (_ *ImplContext) HostRetrieveVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.HostRetrieveVStorageObject) (*types.HostRetrieveVStorageObjectResponse, error) {
	return methods.HostRetrieveVStorageObject(ctx, r, req)
}

func (_ *ImplContext) HostRetrieveVStorageObjectState(ctx context.Context, r soap.RoundTripper, req *types.HostRetrieveVStorageObjectState) (*types.HostRetrieveVStorageObjectStateResponse, error) {
	return methods.HostRetrieveVStorageObjectState(ctx, r, req)
}

func (_ *ImplContext) HostScheduleReconcileDatastoreInventory(ctx context.Context, r soap.RoundTripper, req *types.HostScheduleReconcileDatastoreInventory) (*types.HostScheduleReconcileDatastoreInventoryResponse, error) {
	return methods.HostScheduleReconcileDatastoreInventory(ctx, r, req)
}

func (_ *ImplContext) HostSpecGetUpdatedHosts(ctx context.Context, r soap.RoundTripper, req *types.HostSpecGetUpdatedHosts) (*types.HostSpecGetUpdatedHostsResponse, error) {
	return methods.HostSpecGetUpdatedHosts(ctx, r, req)
}

func (_ *ImplContext) HttpNfcLeaseAbort(ctx context.Context, r soap.RoundTripper, req *types.HttpNfcLeaseAbort) (*types.HttpNfcLeaseAbortResponse, error) {
	return methods.HttpNfcLeaseAbort(ctx, r, req)
}

func (_ *ImplContext) HttpNfcLeaseComplete(ctx context.Context, r soap.RoundTripper, req *types.HttpNfcLeaseComplete) (*types.HttpNfcLeaseCompleteResponse, error) {
	return methods.HttpNfcLeaseComplete(ctx, r, req)
}

func (_ *ImplContext) HttpNfcLeaseGetManifest(ctx context.Context, r soap.RoundTripper, req *types.HttpNfcLeaseGetManifest) (*types.HttpNfcLeaseGetManifestResponse, error) {
	return methods.HttpNfcLeaseGetManifest(ctx, r, req)
}

func (_ *ImplContext) HttpNfcLeaseProgress(ctx context.Context, r soap.RoundTripper, req *types.HttpNfcLeaseProgress) (*types.HttpNfcLeaseProgressResponse, error) {
	return methods.HttpNfcLeaseProgress(ctx, r, req)
}

func (_ *ImplContext) ImpersonateUser(ctx context.Context, r soap.RoundTripper, req *types.ImpersonateUser) (*types.ImpersonateUserResponse, error) {
	return methods.ImpersonateUser(ctx, r, req)
}

func (_ *ImplContext) ImportCertificateForCAM_Task(ctx context.Context, r soap.RoundTripper, req *types.ImportCertificateForCAM_Task) (*types.ImportCertificateForCAM_TaskResponse, error) {
	return methods.ImportCertificateForCAM_Task(ctx, r, req)
}

func (_ *ImplContext) ImportUnmanagedSnapshot(ctx context.Context, r soap.RoundTripper, req *types.ImportUnmanagedSnapshot) (*types.ImportUnmanagedSnapshotResponse, error) {
	return methods.ImportUnmanagedSnapshot(ctx, r, req)
}

func (_ *ImplContext) ImportVApp(ctx context.Context, r soap.RoundTripper, req *types.ImportVApp) (*types.ImportVAppResponse, error) {
	return methods.ImportVApp(ctx, r, req)
}

func (_ *ImplContext) InflateDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.InflateDisk_Task) (*types.InflateDisk_TaskResponse, error) {
	return methods.InflateDisk_Task(ctx, r, req)
}

func (_ *ImplContext) InflateVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.InflateVirtualDisk_Task) (*types.InflateVirtualDisk_TaskResponse, error) {
	return methods.InflateVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) InitializeDisks_Task(ctx context.Context, r soap.RoundTripper, req *types.InitializeDisks_Task) (*types.InitializeDisks_TaskResponse, error) {
	return methods.InitializeDisks_Task(ctx, r, req)
}

func (_ *ImplContext) InitiateFileTransferFromGuest(ctx context.Context, r soap.RoundTripper, req *types.InitiateFileTransferFromGuest) (*types.InitiateFileTransferFromGuestResponse, error) {
	return methods.InitiateFileTransferFromGuest(ctx, r, req)
}

func (_ *ImplContext) InitiateFileTransferToGuest(ctx context.Context, r soap.RoundTripper, req *types.InitiateFileTransferToGuest) (*types.InitiateFileTransferToGuestResponse, error) {
	return methods.InitiateFileTransferToGuest(ctx, r, req)
}

func (_ *ImplContext) InstallHostPatchV2_Task(ctx context.Context, r soap.RoundTripper, req *types.InstallHostPatchV2_Task) (*types.InstallHostPatchV2_TaskResponse, error) {
	return methods.InstallHostPatchV2_Task(ctx, r, req)
}

func (_ *ImplContext) InstallHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.InstallHostPatch_Task) (*types.InstallHostPatch_TaskResponse, error) {
	return methods.InstallHostPatch_Task(ctx, r, req)
}

func (_ *ImplContext) InstallIoFilter_Task(ctx context.Context, r soap.RoundTripper, req *types.InstallIoFilter_Task) (*types.InstallIoFilter_TaskResponse, error) {
	return methods.InstallIoFilter_Task(ctx, r, req)
}

func (_ *ImplContext) InstallServerCertificate(ctx context.Context, r soap.RoundTripper, req *types.InstallServerCertificate) (*types.InstallServerCertificateResponse, error) {
	return methods.InstallServerCertificate(ctx, r, req)
}

func (_ *ImplContext) InstallSmartCardTrustAnchor(ctx context.Context, r soap.RoundTripper, req *types.InstallSmartCardTrustAnchor) (*types.InstallSmartCardTrustAnchorResponse, error) {
	return methods.InstallSmartCardTrustAnchor(ctx, r, req)
}

func (_ *ImplContext) IsSharedGraphicsActive(ctx context.Context, r soap.RoundTripper, req *types.IsSharedGraphicsActive) (*types.IsSharedGraphicsActiveResponse, error) {
	return methods.IsSharedGraphicsActive(ctx, r, req)
}

func (_ *ImplContext) JoinDomainWithCAM_Task(ctx context.Context, r soap.RoundTripper, req *types.JoinDomainWithCAM_Task) (*types.JoinDomainWithCAM_TaskResponse, error) {
	return methods.JoinDomainWithCAM_Task(ctx, r, req)
}

func (_ *ImplContext) JoinDomain_Task(ctx context.Context, r soap.RoundTripper, req *types.JoinDomain_Task) (*types.JoinDomain_TaskResponse, error) {
	return methods.JoinDomain_Task(ctx, r, req)
}

func (_ *ImplContext) LeaveCurrentDomain_Task(ctx context.Context, r soap.RoundTripper, req *types.LeaveCurrentDomain_Task) (*types.LeaveCurrentDomain_TaskResponse, error) {
	return methods.LeaveCurrentDomain_Task(ctx, r, req)
}

func (_ *ImplContext) ListCACertificateRevocationLists(ctx context.Context, r soap.RoundTripper, req *types.ListCACertificateRevocationLists) (*types.ListCACertificateRevocationListsResponse, error) {
	return methods.ListCACertificateRevocationLists(ctx, r, req)
}

func (_ *ImplContext) ListCACertificates(ctx context.Context, r soap.RoundTripper, req *types.ListCACertificates) (*types.ListCACertificatesResponse, error) {
	return methods.ListCACertificates(ctx, r, req)
}

func (_ *ImplContext) ListFilesInGuest(ctx context.Context, r soap.RoundTripper, req *types.ListFilesInGuest) (*types.ListFilesInGuestResponse, error) {
	return methods.ListFilesInGuest(ctx, r, req)
}

func (_ *ImplContext) ListGuestAliases(ctx context.Context, r soap.RoundTripper, req *types.ListGuestAliases) (*types.ListGuestAliasesResponse, error) {
	return methods.ListGuestAliases(ctx, r, req)
}

func (_ *ImplContext) ListGuestMappedAliases(ctx context.Context, r soap.RoundTripper, req *types.ListGuestMappedAliases) (*types.ListGuestMappedAliasesResponse, error) {
	return methods.ListGuestMappedAliases(ctx, r, req)
}

func (_ *ImplContext) ListKeys(ctx context.Context, r soap.RoundTripper, req *types.ListKeys) (*types.ListKeysResponse, error) {
	return methods.ListKeys(ctx, r, req)
}

func (_ *ImplContext) ListKmipServers(ctx context.Context, r soap.RoundTripper, req *types.ListKmipServers) (*types.ListKmipServersResponse, error) {
	return methods.ListKmipServers(ctx, r, req)
}

func (_ *ImplContext) ListProcessesInGuest(ctx context.Context, r soap.RoundTripper, req *types.ListProcessesInGuest) (*types.ListProcessesInGuestResponse, error) {
	return methods.ListProcessesInGuest(ctx, r, req)
}

func (_ *ImplContext) ListRegistryKeysInGuest(ctx context.Context, r soap.RoundTripper, req *types.ListRegistryKeysInGuest) (*types.ListRegistryKeysInGuestResponse, error) {
	return methods.ListRegistryKeysInGuest(ctx, r, req)
}

func (_ *ImplContext) ListRegistryValuesInGuest(ctx context.Context, r soap.RoundTripper, req *types.ListRegistryValuesInGuest) (*types.ListRegistryValuesInGuestResponse, error) {
	return methods.ListRegistryValuesInGuest(ctx, r, req)
}

func (_ *ImplContext) ListSmartCardTrustAnchors(ctx context.Context, r soap.RoundTripper, req *types.ListSmartCardTrustAnchors) (*types.ListSmartCardTrustAnchorsResponse, error) {
	return methods.ListSmartCardTrustAnchors(ctx, r, req)
}

func (_ *ImplContext) ListTagsAttachedToVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.ListTagsAttachedToVStorageObject) (*types.ListTagsAttachedToVStorageObjectResponse, error) {
	return methods.ListTagsAttachedToVStorageObject(ctx, r, req)
}

func (_ *ImplContext) ListVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.ListVStorageObject) (*types.ListVStorageObjectResponse, error) {
	return methods.ListVStorageObject(ctx, r, req)
}

func (_ *ImplContext) ListVStorageObjectsAttachedToTag(ctx context.Context, r soap.RoundTripper, req *types.ListVStorageObjectsAttachedToTag) (*types.ListVStorageObjectsAttachedToTagResponse, error) {
	return methods.ListVStorageObjectsAttachedToTag(ctx, r, req)
}

func (_ *ImplContext) LogUserEvent(ctx context.Context, r soap.RoundTripper, req *types.LogUserEvent) (*types.LogUserEventResponse, error) {
	return methods.LogUserEvent(ctx, r, req)
}

func (_ *ImplContext) Login(ctx context.Context, r soap.RoundTripper, req *types.Login) (*types.LoginResponse, error) {
	return methods.Login(ctx, r, req)
}

func (_ *ImplContext) LoginBySSPI(ctx context.Context, r soap.RoundTripper, req *types.LoginBySSPI) (*types.LoginBySSPIResponse, error) {
	return methods.LoginBySSPI(ctx, r, req)
}

func (_ *ImplContext) LoginByToken(ctx context.Context, r soap.RoundTripper, req *types.LoginByToken) (*types.LoginByTokenResponse, error) {
	return methods.LoginByToken(ctx, r, req)
}

func (_ *ImplContext) LoginExtensionByCertificate(ctx context.Context, r soap.RoundTripper, req *types.LoginExtensionByCertificate) (*types.LoginExtensionByCertificateResponse, error) {
	return methods.LoginExtensionByCertificate(ctx, r, req)
}

func (_ *ImplContext) LoginExtensionBySubjectName(ctx context.Context, r soap.RoundTripper, req *types.LoginExtensionBySubjectName) (*types.LoginExtensionBySubjectNameResponse, error) {
	return methods.LoginExtensionBySubjectName(ctx, r, req)
}

func (_ *ImplContext) Logout(ctx context.Context, r soap.RoundTripper, req *types.Logout) (*types.LogoutResponse, error) {
	return methods.Logout(ctx, r, req)
}

func (_ *ImplContext) LookupDvPortGroup(ctx context.Context, r soap.RoundTripper, req *types.LookupDvPortGroup) (*types.LookupDvPortGroupResponse, error) {
	return methods.LookupDvPortGroup(ctx, r, req)
}

func (_ *ImplContext) LookupVmOverheadMemory(ctx context.Context, r soap.RoundTripper, req *types.LookupVmOverheadMemory) (*types.LookupVmOverheadMemoryResponse, error) {
	return methods.LookupVmOverheadMemory(ctx, r, req)
}

func (_ *ImplContext) MakeDirectory(ctx context.Context, r soap.RoundTripper, req *types.MakeDirectory) (*types.MakeDirectoryResponse, error) {
	return methods.MakeDirectory(ctx, r, req)
}

func (_ *ImplContext) MakeDirectoryInGuest(ctx context.Context, r soap.RoundTripper, req *types.MakeDirectoryInGuest) (*types.MakeDirectoryInGuestResponse, error) {
	return methods.MakeDirectoryInGuest(ctx, r, req)
}

func (_ *ImplContext) MakePrimaryVM_Task(ctx context.Context, r soap.RoundTripper, req *types.MakePrimaryVM_Task) (*types.MakePrimaryVM_TaskResponse, error) {
	return methods.MakePrimaryVM_Task(ctx, r, req)
}

func (_ *ImplContext) MarkAsLocal_Task(ctx context.Context, r soap.RoundTripper, req *types.MarkAsLocal_Task) (*types.MarkAsLocal_TaskResponse, error) {
	return methods.MarkAsLocal_Task(ctx, r, req)
}

func (_ *ImplContext) MarkAsNonLocal_Task(ctx context.Context, r soap.RoundTripper, req *types.MarkAsNonLocal_Task) (*types.MarkAsNonLocal_TaskResponse, error) {
	return methods.MarkAsNonLocal_Task(ctx, r, req)
}

func (_ *ImplContext) MarkAsNonSsd_Task(ctx context.Context, r soap.RoundTripper, req *types.MarkAsNonSsd_Task) (*types.MarkAsNonSsd_TaskResponse, error) {
	return methods.MarkAsNonSsd_Task(ctx, r, req)
}

func (_ *ImplContext) MarkAsSsd_Task(ctx context.Context, r soap.RoundTripper, req *types.MarkAsSsd_Task) (*types.MarkAsSsd_TaskResponse, error) {
	return methods.MarkAsSsd_Task(ctx, r, req)
}

func (_ *ImplContext) MarkAsTemplate(ctx context.Context, r soap.RoundTripper, req *types.MarkAsTemplate) (*types.MarkAsTemplateResponse, error) {
	return methods.MarkAsTemplate(ctx, r, req)
}

func (_ *ImplContext) MarkAsVirtualMachine(ctx context.Context, r soap.RoundTripper, req *types.MarkAsVirtualMachine) (*types.MarkAsVirtualMachineResponse, error) {
	return methods.MarkAsVirtualMachine(ctx, r, req)
}

func (_ *ImplContext) MarkDefault(ctx context.Context, r soap.RoundTripper, req *types.MarkDefault) (*types.MarkDefaultResponse, error) {
	return methods.MarkDefault(ctx, r, req)
}

func (_ *ImplContext) MarkForRemoval(ctx context.Context, r soap.RoundTripper, req *types.MarkForRemoval) (*types.MarkForRemovalResponse, error) {
	return methods.MarkForRemoval(ctx, r, req)
}

func (_ *ImplContext) MergeDvs_Task(ctx context.Context, r soap.RoundTripper, req *types.MergeDvs_Task) (*types.MergeDvs_TaskResponse, error) {
	return methods.MergeDvs_Task(ctx, r, req)
}

func (_ *ImplContext) MergePermissions(ctx context.Context, r soap.RoundTripper, req *types.MergePermissions) (*types.MergePermissionsResponse, error) {
	return methods.MergePermissions(ctx, r, req)
}

func (_ *ImplContext) MigrateVM_Task(ctx context.Context, r soap.RoundTripper, req *types.MigrateVM_Task) (*types.MigrateVM_TaskResponse, error) {
	return methods.MigrateVM_Task(ctx, r, req)
}

func (_ *ImplContext) ModifyListView(ctx context.Context, r soap.RoundTripper, req *types.ModifyListView) (*types.ModifyListViewResponse, error) {
	return methods.ModifyListView(ctx, r, req)
}

func (_ *ImplContext) MountToolsInstaller(ctx context.Context, r soap.RoundTripper, req *types.MountToolsInstaller) (*types.MountToolsInstallerResponse, error) {
	return methods.MountToolsInstaller(ctx, r, req)
}

func (_ *ImplContext) MountVffsVolume(ctx context.Context, r soap.RoundTripper, req *types.MountVffsVolume) (*types.MountVffsVolumeResponse, error) {
	return methods.MountVffsVolume(ctx, r, req)
}

func (_ *ImplContext) MountVmfsVolume(ctx context.Context, r soap.RoundTripper, req *types.MountVmfsVolume) (*types.MountVmfsVolumeResponse, error) {
	return methods.MountVmfsVolume(ctx, r, req)
}

func (_ *ImplContext) MountVmfsVolumeEx_Task(ctx context.Context, r soap.RoundTripper, req *types.MountVmfsVolumeEx_Task) (*types.MountVmfsVolumeEx_TaskResponse, error) {
	return methods.MountVmfsVolumeEx_Task(ctx, r, req)
}

func (_ *ImplContext) MoveDVPort_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveDVPort_Task) (*types.MoveDVPort_TaskResponse, error) {
	return methods.MoveDVPort_Task(ctx, r, req)
}

func (_ *ImplContext) MoveDatastoreFile_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveDatastoreFile_Task) (*types.MoveDatastoreFile_TaskResponse, error) {
	return methods.MoveDatastoreFile_Task(ctx, r, req)
}

func (_ *ImplContext) MoveDirectoryInGuest(ctx context.Context, r soap.RoundTripper, req *types.MoveDirectoryInGuest) (*types.MoveDirectoryInGuestResponse, error) {
	return methods.MoveDirectoryInGuest(ctx, r, req)
}

func (_ *ImplContext) MoveFileInGuest(ctx context.Context, r soap.RoundTripper, req *types.MoveFileInGuest) (*types.MoveFileInGuestResponse, error) {
	return methods.MoveFileInGuest(ctx, r, req)
}

func (_ *ImplContext) MoveHostInto_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveHostInto_Task) (*types.MoveHostInto_TaskResponse, error) {
	return methods.MoveHostInto_Task(ctx, r, req)
}

func (_ *ImplContext) MoveIntoFolder_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveIntoFolder_Task) (*types.MoveIntoFolder_TaskResponse, error) {
	return methods.MoveIntoFolder_Task(ctx, r, req)
}

func (_ *ImplContext) MoveIntoResourcePool(ctx context.Context, r soap.RoundTripper, req *types.MoveIntoResourcePool) (*types.MoveIntoResourcePoolResponse, error) {
	return methods.MoveIntoResourcePool(ctx, r, req)
}

func (_ *ImplContext) MoveInto_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveInto_Task) (*types.MoveInto_TaskResponse, error) {
	return methods.MoveInto_Task(ctx, r, req)
}

func (_ *ImplContext) MoveVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.MoveVirtualDisk_Task) (*types.MoveVirtualDisk_TaskResponse, error) {
	return methods.MoveVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) OpenInventoryViewFolder(ctx context.Context, r soap.RoundTripper, req *types.OpenInventoryViewFolder) (*types.OpenInventoryViewFolderResponse, error) {
	return methods.OpenInventoryViewFolder(ctx, r, req)
}

func (_ *ImplContext) OverwriteCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.OverwriteCustomizationSpec) (*types.OverwriteCustomizationSpecResponse, error) {
	return methods.OverwriteCustomizationSpec(ctx, r, req)
}

func (_ *ImplContext) ParseDescriptor(ctx context.Context, r soap.RoundTripper, req *types.ParseDescriptor) (*types.ParseDescriptorResponse, error) {
	return methods.ParseDescriptor(ctx, r, req)
}

func (_ *ImplContext) PerformDvsProductSpecOperation_Task(ctx context.Context, r soap.RoundTripper, req *types.PerformDvsProductSpecOperation_Task) (*types.PerformDvsProductSpecOperation_TaskResponse, error) {
	return methods.PerformDvsProductSpecOperation_Task(ctx, r, req)
}

func (_ *ImplContext) PerformVsanUpgradePreflightCheck(ctx context.Context, r soap.RoundTripper, req *types.PerformVsanUpgradePreflightCheck) (*types.PerformVsanUpgradePreflightCheckResponse, error) {
	return methods.PerformVsanUpgradePreflightCheck(ctx, r, req)
}

func (_ *ImplContext) PerformVsanUpgrade_Task(ctx context.Context, r soap.RoundTripper, req *types.PerformVsanUpgrade_Task) (*types.PerformVsanUpgrade_TaskResponse, error) {
	return methods.PerformVsanUpgrade_Task(ctx, r, req)
}

func (_ *ImplContext) PlaceVm(ctx context.Context, r soap.RoundTripper, req *types.PlaceVm) (*types.PlaceVmResponse, error) {
	return methods.PlaceVm(ctx, r, req)
}

func (_ *ImplContext) PostEvent(ctx context.Context, r soap.RoundTripper, req *types.PostEvent) (*types.PostEventResponse, error) {
	return methods.PostEvent(ctx, r, req)
}

func (_ *ImplContext) PostHealthUpdates(ctx context.Context, r soap.RoundTripper, req *types.PostHealthUpdates) (*types.PostHealthUpdatesResponse, error) {
	return methods.PostHealthUpdates(ctx, r, req)
}

func (_ *ImplContext) PowerDownHostToStandBy_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerDownHostToStandBy_Task) (*types.PowerDownHostToStandBy_TaskResponse, error) {
	return methods.PowerDownHostToStandBy_Task(ctx, r, req)
}

func (_ *ImplContext) PowerOffVApp_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOffVApp_Task) (*types.PowerOffVApp_TaskResponse, error) {
	return methods.PowerOffVApp_Task(ctx, r, req)
}

func (_ *ImplContext) PowerOffVM_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOffVM_Task) (*types.PowerOffVM_TaskResponse, error) {
	return methods.PowerOffVM_Task(ctx, r, req)
}

func (_ *ImplContext) PowerOnMultiVM_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOnMultiVM_Task) (*types.PowerOnMultiVM_TaskResponse, error) {
	return methods.PowerOnMultiVM_Task(ctx, r, req)
}

func (_ *ImplContext) PowerOnVApp_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOnVApp_Task) (*types.PowerOnVApp_TaskResponse, error) {
	return methods.PowerOnVApp_Task(ctx, r, req)
}

func (_ *ImplContext) PowerOnVM_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerOnVM_Task) (*types.PowerOnVM_TaskResponse, error) {
	return methods.PowerOnVM_Task(ctx, r, req)
}

func (_ *ImplContext) PowerUpHostFromStandBy_Task(ctx context.Context, r soap.RoundTripper, req *types.PowerUpHostFromStandBy_Task) (*types.PowerUpHostFromStandBy_TaskResponse, error) {
	return methods.PowerUpHostFromStandBy_Task(ctx, r, req)
}

func (_ *ImplContext) PrepareCrypto(ctx context.Context, r soap.RoundTripper, req *types.PrepareCrypto) (*types.PrepareCryptoResponse, error) {
	return methods.PrepareCrypto(ctx, r, req)
}

func (_ *ImplContext) PromoteDisks_Task(ctx context.Context, r soap.RoundTripper, req *types.PromoteDisks_Task) (*types.PromoteDisks_TaskResponse, error) {
	return methods.PromoteDisks_Task(ctx, r, req)
}

func (_ *ImplContext) PutUsbScanCodes(ctx context.Context, r soap.RoundTripper, req *types.PutUsbScanCodes) (*types.PutUsbScanCodesResponse, error) {
	return methods.PutUsbScanCodes(ctx, r, req)
}

func (_ *ImplContext) QueryAnswerFileStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryAnswerFileStatus) (*types.QueryAnswerFileStatusResponse, error) {
	return methods.QueryAnswerFileStatus(ctx, r, req)
}

func (_ *ImplContext) QueryAssignedLicenses(ctx context.Context, r soap.RoundTripper, req *types.QueryAssignedLicenses) (*types.QueryAssignedLicensesResponse, error) {
	return methods.QueryAssignedLicenses(ctx, r, req)
}

func (_ *ImplContext) QueryAvailableDisksForVmfs(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailableDisksForVmfs) (*types.QueryAvailableDisksForVmfsResponse, error) {
	return methods.QueryAvailableDisksForVmfs(ctx, r, req)
}

func (_ *ImplContext) QueryAvailableDvsSpec(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailableDvsSpec) (*types.QueryAvailableDvsSpecResponse, error) {
	return methods.QueryAvailableDvsSpec(ctx, r, req)
}

func (_ *ImplContext) QueryAvailablePartition(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailablePartition) (*types.QueryAvailablePartitionResponse, error) {
	return methods.QueryAvailablePartition(ctx, r, req)
}

func (_ *ImplContext) QueryAvailablePerfMetric(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailablePerfMetric) (*types.QueryAvailablePerfMetricResponse, error) {
	return methods.QueryAvailablePerfMetric(ctx, r, req)
}

func (_ *ImplContext) QueryAvailableSsds(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailableSsds) (*types.QueryAvailableSsdsResponse, error) {
	return methods.QueryAvailableSsds(ctx, r, req)
}

func (_ *ImplContext) QueryAvailableTimeZones(ctx context.Context, r soap.RoundTripper, req *types.QueryAvailableTimeZones) (*types.QueryAvailableTimeZonesResponse, error) {
	return methods.QueryAvailableTimeZones(ctx, r, req)
}

func (_ *ImplContext) QueryBootDevices(ctx context.Context, r soap.RoundTripper, req *types.QueryBootDevices) (*types.QueryBootDevicesResponse, error) {
	return methods.QueryBootDevices(ctx, r, req)
}

func (_ *ImplContext) QueryBoundVnics(ctx context.Context, r soap.RoundTripper, req *types.QueryBoundVnics) (*types.QueryBoundVnicsResponse, error) {
	return methods.QueryBoundVnics(ctx, r, req)
}

func (_ *ImplContext) QueryCandidateNics(ctx context.Context, r soap.RoundTripper, req *types.QueryCandidateNics) (*types.QueryCandidateNicsResponse, error) {
	return methods.QueryCandidateNics(ctx, r, req)
}

func (_ *ImplContext) QueryChangedDiskAreas(ctx context.Context, r soap.RoundTripper, req *types.QueryChangedDiskAreas) (*types.QueryChangedDiskAreasResponse, error) {
	return methods.QueryChangedDiskAreas(ctx, r, req)
}

func (_ *ImplContext) QueryCmmds(ctx context.Context, r soap.RoundTripper, req *types.QueryCmmds) (*types.QueryCmmdsResponse, error) {
	return methods.QueryCmmds(ctx, r, req)
}

func (_ *ImplContext) QueryCompatibleHostForExistingDvs(ctx context.Context, r soap.RoundTripper, req *types.QueryCompatibleHostForExistingDvs) (*types.QueryCompatibleHostForExistingDvsResponse, error) {
	return methods.QueryCompatibleHostForExistingDvs(ctx, r, req)
}

func (_ *ImplContext) QueryCompatibleHostForNewDvs(ctx context.Context, r soap.RoundTripper, req *types.QueryCompatibleHostForNewDvs) (*types.QueryCompatibleHostForNewDvsResponse, error) {
	return methods.QueryCompatibleHostForNewDvs(ctx, r, req)
}

func (_ *ImplContext) QueryComplianceStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryComplianceStatus) (*types.QueryComplianceStatusResponse, error) {
	return methods.QueryComplianceStatus(ctx, r, req)
}

func (_ *ImplContext) QueryConfigOption(ctx context.Context, r soap.RoundTripper, req *types.QueryConfigOption) (*types.QueryConfigOptionResponse, error) {
	return methods.QueryConfigOption(ctx, r, req)
}

func (_ *ImplContext) QueryConfigOptionDescriptor(ctx context.Context, r soap.RoundTripper, req *types.QueryConfigOptionDescriptor) (*types.QueryConfigOptionDescriptorResponse, error) {
	return methods.QueryConfigOptionDescriptor(ctx, r, req)
}

func (_ *ImplContext) QueryConfigOptionEx(ctx context.Context, r soap.RoundTripper, req *types.QueryConfigOptionEx) (*types.QueryConfigOptionExResponse, error) {
	return methods.QueryConfigOptionEx(ctx, r, req)
}

func (_ *ImplContext) QueryConfigTarget(ctx context.Context, r soap.RoundTripper, req *types.QueryConfigTarget) (*types.QueryConfigTargetResponse, error) {
	return methods.QueryConfigTarget(ctx, r, req)
}

func (_ *ImplContext) QueryConfiguredModuleOptionString(ctx context.Context, r soap.RoundTripper, req *types.QueryConfiguredModuleOptionString) (*types.QueryConfiguredModuleOptionStringResponse, error) {
	return methods.QueryConfiguredModuleOptionString(ctx, r, req)
}

func (_ *ImplContext) QueryConnectionInfo(ctx context.Context, r soap.RoundTripper, req *types.QueryConnectionInfo) (*types.QueryConnectionInfoResponse, error) {
	return methods.QueryConnectionInfo(ctx, r, req)
}

func (_ *ImplContext) QueryConnectionInfoViaSpec(ctx context.Context, r soap.RoundTripper, req *types.QueryConnectionInfoViaSpec) (*types.QueryConnectionInfoViaSpecResponse, error) {
	return methods.QueryConnectionInfoViaSpec(ctx, r, req)
}

func (_ *ImplContext) QueryDatastorePerformanceSummary(ctx context.Context, r soap.RoundTripper, req *types.QueryDatastorePerformanceSummary) (*types.QueryDatastorePerformanceSummaryResponse, error) {
	return methods.QueryDatastorePerformanceSummary(ctx, r, req)
}

func (_ *ImplContext) QueryDateTime(ctx context.Context, r soap.RoundTripper, req *types.QueryDateTime) (*types.QueryDateTimeResponse, error) {
	return methods.QueryDateTime(ctx, r, req)
}

func (_ *ImplContext) QueryDescriptions(ctx context.Context, r soap.RoundTripper, req *types.QueryDescriptions) (*types.QueryDescriptionsResponse, error) {
	return methods.QueryDescriptions(ctx, r, req)
}

func (_ *ImplContext) QueryDisksForVsan(ctx context.Context, r soap.RoundTripper, req *types.QueryDisksForVsan) (*types.QueryDisksForVsanResponse, error) {
	return methods.QueryDisksForVsan(ctx, r, req)
}

func (_ *ImplContext) QueryDisksUsingFilter(ctx context.Context, r soap.RoundTripper, req *types.QueryDisksUsingFilter) (*types.QueryDisksUsingFilterResponse, error) {
	return methods.QueryDisksUsingFilter(ctx, r, req)
}

func (_ *ImplContext) QueryDvsByUuid(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsByUuid) (*types.QueryDvsByUuidResponse, error) {
	return methods.QueryDvsByUuid(ctx, r, req)
}

func (_ *ImplContext) QueryDvsCheckCompatibility(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsCheckCompatibility) (*types.QueryDvsCheckCompatibilityResponse, error) {
	return methods.QueryDvsCheckCompatibility(ctx, r, req)
}

func (_ *ImplContext) QueryDvsCompatibleHostSpec(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsCompatibleHostSpec) (*types.QueryDvsCompatibleHostSpecResponse, error) {
	return methods.QueryDvsCompatibleHostSpec(ctx, r, req)
}

func (_ *ImplContext) QueryDvsConfigTarget(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsConfigTarget) (*types.QueryDvsConfigTargetResponse, error) {
	return methods.QueryDvsConfigTarget(ctx, r, req)
}

func (_ *ImplContext) QueryDvsFeatureCapability(ctx context.Context, r soap.RoundTripper, req *types.QueryDvsFeatureCapability) (*types.QueryDvsFeatureCapabilityResponse, error) {
	return methods.QueryDvsFeatureCapability(ctx, r, req)
}

func (_ *ImplContext) QueryEvents(ctx context.Context, r soap.RoundTripper, req *types.QueryEvents) (*types.QueryEventsResponse, error) {
	return methods.QueryEvents(ctx, r, req)
}

func (_ *ImplContext) QueryExpressionMetadata(ctx context.Context, r soap.RoundTripper, req *types.QueryExpressionMetadata) (*types.QueryExpressionMetadataResponse, error) {
	return methods.QueryExpressionMetadata(ctx, r, req)
}

func (_ *ImplContext) QueryExtensionIpAllocationUsage(ctx context.Context, r soap.RoundTripper, req *types.QueryExtensionIpAllocationUsage) (*types.QueryExtensionIpAllocationUsageResponse, error) {
	return methods.QueryExtensionIpAllocationUsage(ctx, r, req)
}

func (_ *ImplContext) QueryFaultToleranceCompatibility(ctx context.Context, r soap.RoundTripper, req *types.QueryFaultToleranceCompatibility) (*types.QueryFaultToleranceCompatibilityResponse, error) {
	return methods.QueryFaultToleranceCompatibility(ctx, r, req)
}

func (_ *ImplContext) QueryFaultToleranceCompatibilityEx(ctx context.Context, r soap.RoundTripper, req *types.QueryFaultToleranceCompatibilityEx) (*types.QueryFaultToleranceCompatibilityExResponse, error) {
	return methods.QueryFaultToleranceCompatibilityEx(ctx, r, req)
}

func (_ *ImplContext) QueryFilterEntities(ctx context.Context, r soap.RoundTripper, req *types.QueryFilterEntities) (*types.QueryFilterEntitiesResponse, error) {
	return methods.QueryFilterEntities(ctx, r, req)
}

func (_ *ImplContext) QueryFilterInfoIds(ctx context.Context, r soap.RoundTripper, req *types.QueryFilterInfoIds) (*types.QueryFilterInfoIdsResponse, error) {
	return methods.QueryFilterInfoIds(ctx, r, req)
}

func (_ *ImplContext) QueryFilterList(ctx context.Context, r soap.RoundTripper, req *types.QueryFilterList) (*types.QueryFilterListResponse, error) {
	return methods.QueryFilterList(ctx, r, req)
}

func (_ *ImplContext) QueryFilterName(ctx context.Context, r soap.RoundTripper, req *types.QueryFilterName) (*types.QueryFilterNameResponse, error) {
	return methods.QueryFilterName(ctx, r, req)
}

func (_ *ImplContext) QueryFirmwareConfigUploadURL(ctx context.Context, r soap.RoundTripper, req *types.QueryFirmwareConfigUploadURL) (*types.QueryFirmwareConfigUploadURLResponse, error) {
	return methods.QueryFirmwareConfigUploadURL(ctx, r, req)
}

func (_ *ImplContext) QueryHealthUpdateInfos(ctx context.Context, r soap.RoundTripper, req *types.QueryHealthUpdateInfos) (*types.QueryHealthUpdateInfosResponse, error) {
	return methods.QueryHealthUpdateInfos(ctx, r, req)
}

func (_ *ImplContext) QueryHealthUpdates(ctx context.Context, r soap.RoundTripper, req *types.QueryHealthUpdates) (*types.QueryHealthUpdatesResponse, error) {
	return methods.QueryHealthUpdates(ctx, r, req)
}

func (_ *ImplContext) QueryHostConnectionInfo(ctx context.Context, r soap.RoundTripper, req *types.QueryHostConnectionInfo) (*types.QueryHostConnectionInfoResponse, error) {
	return methods.QueryHostConnectionInfo(ctx, r, req)
}

func (_ *ImplContext) QueryHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.QueryHostPatch_Task) (*types.QueryHostPatch_TaskResponse, error) {
	return methods.QueryHostPatch_Task(ctx, r, req)
}

func (_ *ImplContext) QueryHostProfileMetadata(ctx context.Context, r soap.RoundTripper, req *types.QueryHostProfileMetadata) (*types.QueryHostProfileMetadataResponse, error) {
	return methods.QueryHostProfileMetadata(ctx, r, req)
}

func (_ *ImplContext) QueryHostStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryHostStatus) (*types.QueryHostStatusResponse, error) {
	return methods.QueryHostStatus(ctx, r, req)
}

func (_ *ImplContext) QueryIORMConfigOption(ctx context.Context, r soap.RoundTripper, req *types.QueryIORMConfigOption) (*types.QueryIORMConfigOptionResponse, error) {
	return methods.QueryIORMConfigOption(ctx, r, req)
}

func (_ *ImplContext) QueryIPAllocations(ctx context.Context, r soap.RoundTripper, req *types.QueryIPAllocations) (*types.QueryIPAllocationsResponse, error) {
	return methods.QueryIPAllocations(ctx, r, req)
}

func (_ *ImplContext) QueryIoFilterInfo(ctx context.Context, r soap.RoundTripper, req *types.QueryIoFilterInfo) (*types.QueryIoFilterInfoResponse, error) {
	return methods.QueryIoFilterInfo(ctx, r, req)
}

func (_ *ImplContext) QueryIoFilterIssues(ctx context.Context, r soap.RoundTripper, req *types.QueryIoFilterIssues) (*types.QueryIoFilterIssuesResponse, error) {
	return methods.QueryIoFilterIssues(ctx, r, req)
}

func (_ *ImplContext) QueryIpPools(ctx context.Context, r soap.RoundTripper, req *types.QueryIpPools) (*types.QueryIpPoolsResponse, error) {
	return methods.QueryIpPools(ctx, r, req)
}

func (_ *ImplContext) QueryLicenseSourceAvailability(ctx context.Context, r soap.RoundTripper, req *types.QueryLicenseSourceAvailability) (*types.QueryLicenseSourceAvailabilityResponse, error) {
	return methods.QueryLicenseSourceAvailability(ctx, r, req)
}

func (_ *ImplContext) QueryLicenseUsage(ctx context.Context, r soap.RoundTripper, req *types.QueryLicenseUsage) (*types.QueryLicenseUsageResponse, error) {
	return methods.QueryLicenseUsage(ctx, r, req)
}

func (_ *ImplContext) QueryLockdownExceptions(ctx context.Context, r soap.RoundTripper, req *types.QueryLockdownExceptions) (*types.QueryLockdownExceptionsResponse, error) {
	return methods.QueryLockdownExceptions(ctx, r, req)
}

func (_ *ImplContext) QueryManagedBy(ctx context.Context, r soap.RoundTripper, req *types.QueryManagedBy) (*types.QueryManagedByResponse, error) {
	return methods.QueryManagedBy(ctx, r, req)
}

func (_ *ImplContext) QueryMemoryOverhead(ctx context.Context, r soap.RoundTripper, req *types.QueryMemoryOverhead) (*types.QueryMemoryOverheadResponse, error) {
	return methods.QueryMemoryOverhead(ctx, r, req)
}

func (_ *ImplContext) QueryMemoryOverheadEx(ctx context.Context, r soap.RoundTripper, req *types.QueryMemoryOverheadEx) (*types.QueryMemoryOverheadExResponse, error) {
	return methods.QueryMemoryOverheadEx(ctx, r, req)
}

func (_ *ImplContext) QueryMigrationDependencies(ctx context.Context, r soap.RoundTripper, req *types.QueryMigrationDependencies) (*types.QueryMigrationDependenciesResponse, error) {
	return methods.QueryMigrationDependencies(ctx, r, req)
}

func (_ *ImplContext) QueryModules(ctx context.Context, r soap.RoundTripper, req *types.QueryModules) (*types.QueryModulesResponse, error) {
	return methods.QueryModules(ctx, r, req)
}

func (_ *ImplContext) QueryMonitoredEntities(ctx context.Context, r soap.RoundTripper, req *types.QueryMonitoredEntities) (*types.QueryMonitoredEntitiesResponse, error) {
	return methods.QueryMonitoredEntities(ctx, r, req)
}

func (_ *ImplContext) QueryNFSUser(ctx context.Context, r soap.RoundTripper, req *types.QueryNFSUser) (*types.QueryNFSUserResponse, error) {
	return methods.QueryNFSUser(ctx, r, req)
}

func (_ *ImplContext) QueryNetConfig(ctx context.Context, r soap.RoundTripper, req *types.QueryNetConfig) (*types.QueryNetConfigResponse, error) {
	return methods.QueryNetConfig(ctx, r, req)
}

func (_ *ImplContext) QueryNetworkHint(ctx context.Context, r soap.RoundTripper, req *types.QueryNetworkHint) (*types.QueryNetworkHintResponse, error) {
	return methods.QueryNetworkHint(ctx, r, req)
}

func (_ *ImplContext) QueryObjectsOnPhysicalVsanDisk(ctx context.Context, r soap.RoundTripper, req *types.QueryObjectsOnPhysicalVsanDisk) (*types.QueryObjectsOnPhysicalVsanDiskResponse, error) {
	return methods.QueryObjectsOnPhysicalVsanDisk(ctx, r, req)
}

func (_ *ImplContext) QueryOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryOptions) (*types.QueryOptionsResponse, error) {
	return methods.QueryOptions(ctx, r, req)
}

func (_ *ImplContext) QueryPartitionCreateDesc(ctx context.Context, r soap.RoundTripper, req *types.QueryPartitionCreateDesc) (*types.QueryPartitionCreateDescResponse, error) {
	return methods.QueryPartitionCreateDesc(ctx, r, req)
}

func (_ *ImplContext) QueryPartitionCreateOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryPartitionCreateOptions) (*types.QueryPartitionCreateOptionsResponse, error) {
	return methods.QueryPartitionCreateOptions(ctx, r, req)
}

func (_ *ImplContext) QueryPathSelectionPolicyOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryPathSelectionPolicyOptions) (*types.QueryPathSelectionPolicyOptionsResponse, error) {
	return methods.QueryPathSelectionPolicyOptions(ctx, r, req)
}

func (_ *ImplContext) QueryPerf(ctx context.Context, r soap.RoundTripper, req *types.QueryPerf) (*types.QueryPerfResponse, error) {
	return methods.QueryPerf(ctx, r, req)
}

func (_ *ImplContext) QueryPerfComposite(ctx context.Context, r soap.RoundTripper, req *types.QueryPerfComposite) (*types.QueryPerfCompositeResponse, error) {
	return methods.QueryPerfComposite(ctx, r, req)
}

func (_ *ImplContext) QueryPerfCounter(ctx context.Context, r soap.RoundTripper, req *types.QueryPerfCounter) (*types.QueryPerfCounterResponse, error) {
	return methods.QueryPerfCounter(ctx, r, req)
}

func (_ *ImplContext) QueryPerfCounterByLevel(ctx context.Context, r soap.RoundTripper, req *types.QueryPerfCounterByLevel) (*types.QueryPerfCounterByLevelResponse, error) {
	return methods.QueryPerfCounterByLevel(ctx, r, req)
}

func (_ *ImplContext) QueryPerfProviderSummary(ctx context.Context, r soap.RoundTripper, req *types.QueryPerfProviderSummary) (*types.QueryPerfProviderSummaryResponse, error) {
	return methods.QueryPerfProviderSummary(ctx, r, req)
}

func (_ *ImplContext) QueryPhysicalVsanDisks(ctx context.Context, r soap.RoundTripper, req *types.QueryPhysicalVsanDisks) (*types.QueryPhysicalVsanDisksResponse, error) {
	return methods.QueryPhysicalVsanDisks(ctx, r, req)
}

func (_ *ImplContext) QueryPnicStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryPnicStatus) (*types.QueryPnicStatusResponse, error) {
	return methods.QueryPnicStatus(ctx, r, req)
}

func (_ *ImplContext) QueryPolicyMetadata(ctx context.Context, r soap.RoundTripper, req *types.QueryPolicyMetadata) (*types.QueryPolicyMetadataResponse, error) {
	return methods.QueryPolicyMetadata(ctx, r, req)
}

func (_ *ImplContext) QueryProfileStructure(ctx context.Context, r soap.RoundTripper, req *types.QueryProfileStructure) (*types.QueryProfileStructureResponse, error) {
	return methods.QueryProfileStructure(ctx, r, req)
}

func (_ *ImplContext) QueryProviderList(ctx context.Context, r soap.RoundTripper, req *types.QueryProviderList) (*types.QueryProviderListResponse, error) {
	return methods.QueryProviderList(ctx, r, req)
}

func (_ *ImplContext) QueryProviderName(ctx context.Context, r soap.RoundTripper, req *types.QueryProviderName) (*types.QueryProviderNameResponse, error) {
	return methods.QueryProviderName(ctx, r, req)
}

func (_ *ImplContext) QueryResourceConfigOption(ctx context.Context, r soap.RoundTripper, req *types.QueryResourceConfigOption) (*types.QueryResourceConfigOptionResponse, error) {
	return methods.QueryResourceConfigOption(ctx, r, req)
}

func (_ *ImplContext) QueryServiceList(ctx context.Context, r soap.RoundTripper, req *types.QueryServiceList) (*types.QueryServiceListResponse, error) {
	return methods.QueryServiceList(ctx, r, req)
}

func (_ *ImplContext) QueryStorageArrayTypePolicyOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryStorageArrayTypePolicyOptions) (*types.QueryStorageArrayTypePolicyOptionsResponse, error) {
	return methods.QueryStorageArrayTypePolicyOptions(ctx, r, req)
}

func (_ *ImplContext) QuerySupportedFeatures(ctx context.Context, r soap.RoundTripper, req *types.QuerySupportedFeatures) (*types.QuerySupportedFeaturesResponse, error) {
	return methods.QuerySupportedFeatures(ctx, r, req)
}

func (_ *ImplContext) QuerySyncingVsanObjects(ctx context.Context, r soap.RoundTripper, req *types.QuerySyncingVsanObjects) (*types.QuerySyncingVsanObjectsResponse, error) {
	return methods.QuerySyncingVsanObjects(ctx, r, req)
}

func (_ *ImplContext) QuerySystemUsers(ctx context.Context, r soap.RoundTripper, req *types.QuerySystemUsers) (*types.QuerySystemUsersResponse, error) {
	return methods.QuerySystemUsers(ctx, r, req)
}

func (_ *ImplContext) QueryTargetCapabilities(ctx context.Context, r soap.RoundTripper, req *types.QueryTargetCapabilities) (*types.QueryTargetCapabilitiesResponse, error) {
	return methods.QueryTargetCapabilities(ctx, r, req)
}

func (_ *ImplContext) QueryTpmAttestationReport(ctx context.Context, r soap.RoundTripper, req *types.QueryTpmAttestationReport) (*types.QueryTpmAttestationReportResponse, error) {
	return methods.QueryTpmAttestationReport(ctx, r, req)
}

func (_ *ImplContext) QueryUnmonitoredHosts(ctx context.Context, r soap.RoundTripper, req *types.QueryUnmonitoredHosts) (*types.QueryUnmonitoredHostsResponse, error) {
	return methods.QueryUnmonitoredHosts(ctx, r, req)
}

func (_ *ImplContext) QueryUnownedFiles(ctx context.Context, r soap.RoundTripper, req *types.QueryUnownedFiles) (*types.QueryUnownedFilesResponse, error) {
	return methods.QueryUnownedFiles(ctx, r, req)
}

func (_ *ImplContext) QueryUnresolvedVmfsVolume(ctx context.Context, r soap.RoundTripper, req *types.QueryUnresolvedVmfsVolume) (*types.QueryUnresolvedVmfsVolumeResponse, error) {
	return methods.QueryUnresolvedVmfsVolume(ctx, r, req)
}

func (_ *ImplContext) QueryUnresolvedVmfsVolumes(ctx context.Context, r soap.RoundTripper, req *types.QueryUnresolvedVmfsVolumes) (*types.QueryUnresolvedVmfsVolumesResponse, error) {
	return methods.QueryUnresolvedVmfsVolumes(ctx, r, req)
}

func (_ *ImplContext) QueryUsedVlanIdInDvs(ctx context.Context, r soap.RoundTripper, req *types.QueryUsedVlanIdInDvs) (*types.QueryUsedVlanIdInDvsResponse, error) {
	return methods.QueryUsedVlanIdInDvs(ctx, r, req)
}

func (_ *ImplContext) QueryVMotionCompatibility(ctx context.Context, r soap.RoundTripper, req *types.QueryVMotionCompatibility) (*types.QueryVMotionCompatibilityResponse, error) {
	return methods.QueryVMotionCompatibility(ctx, r, req)
}

func (_ *ImplContext) QueryVMotionCompatibilityEx_Task(ctx context.Context, r soap.RoundTripper, req *types.QueryVMotionCompatibilityEx_Task) (*types.QueryVMotionCompatibilityEx_TaskResponse, error) {
	return methods.QueryVMotionCompatibilityEx_Task(ctx, r, req)
}

func (_ *ImplContext) QueryVirtualDiskFragmentation(ctx context.Context, r soap.RoundTripper, req *types.QueryVirtualDiskFragmentation) (*types.QueryVirtualDiskFragmentationResponse, error) {
	return methods.QueryVirtualDiskFragmentation(ctx, r, req)
}

func (_ *ImplContext) QueryVirtualDiskGeometry(ctx context.Context, r soap.RoundTripper, req *types.QueryVirtualDiskGeometry) (*types.QueryVirtualDiskGeometryResponse, error) {
	return methods.QueryVirtualDiskGeometry(ctx, r, req)
}

func (_ *ImplContext) QueryVirtualDiskUuid(ctx context.Context, r soap.RoundTripper, req *types.QueryVirtualDiskUuid) (*types.QueryVirtualDiskUuidResponse, error) {
	return methods.QueryVirtualDiskUuid(ctx, r, req)
}

func (_ *ImplContext) QueryVmfsConfigOption(ctx context.Context, r soap.RoundTripper, req *types.QueryVmfsConfigOption) (*types.QueryVmfsConfigOptionResponse, error) {
	return methods.QueryVmfsConfigOption(ctx, r, req)
}

func (_ *ImplContext) QueryVmfsDatastoreCreateOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryVmfsDatastoreCreateOptions) (*types.QueryVmfsDatastoreCreateOptionsResponse, error) {
	return methods.QueryVmfsDatastoreCreateOptions(ctx, r, req)
}

func (_ *ImplContext) QueryVmfsDatastoreExpandOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryVmfsDatastoreExpandOptions) (*types.QueryVmfsDatastoreExpandOptionsResponse, error) {
	return methods.QueryVmfsDatastoreExpandOptions(ctx, r, req)
}

func (_ *ImplContext) QueryVmfsDatastoreExtendOptions(ctx context.Context, r soap.RoundTripper, req *types.QueryVmfsDatastoreExtendOptions) (*types.QueryVmfsDatastoreExtendOptionsResponse, error) {
	return methods.QueryVmfsDatastoreExtendOptions(ctx, r, req)
}

func (_ *ImplContext) QueryVnicStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryVnicStatus) (*types.QueryVnicStatusResponse, error) {
	return methods.QueryVnicStatus(ctx, r, req)
}

func (_ *ImplContext) QueryVsanObjectUuidsByFilter(ctx context.Context, r soap.RoundTripper, req *types.QueryVsanObjectUuidsByFilter) (*types.QueryVsanObjectUuidsByFilterResponse, error) {
	return methods.QueryVsanObjectUuidsByFilter(ctx, r, req)
}

func (_ *ImplContext) QueryVsanObjects(ctx context.Context, r soap.RoundTripper, req *types.QueryVsanObjects) (*types.QueryVsanObjectsResponse, error) {
	return methods.QueryVsanObjects(ctx, r, req)
}

func (_ *ImplContext) QueryVsanStatistics(ctx context.Context, r soap.RoundTripper, req *types.QueryVsanStatistics) (*types.QueryVsanStatisticsResponse, error) {
	return methods.QueryVsanStatistics(ctx, r, req)
}

func (_ *ImplContext) QueryVsanUpgradeStatus(ctx context.Context, r soap.RoundTripper, req *types.QueryVsanUpgradeStatus) (*types.QueryVsanUpgradeStatusResponse, error) {
	return methods.QueryVsanUpgradeStatus(ctx, r, req)
}

func (_ *ImplContext) ReadEnvironmentVariableInGuest(ctx context.Context, r soap.RoundTripper, req *types.ReadEnvironmentVariableInGuest) (*types.ReadEnvironmentVariableInGuestResponse, error) {
	return methods.ReadEnvironmentVariableInGuest(ctx, r, req)
}

func (_ *ImplContext) ReadNextEvents(ctx context.Context, r soap.RoundTripper, req *types.ReadNextEvents) (*types.ReadNextEventsResponse, error) {
	return methods.ReadNextEvents(ctx, r, req)
}

func (_ *ImplContext) ReadNextTasks(ctx context.Context, r soap.RoundTripper, req *types.ReadNextTasks) (*types.ReadNextTasksResponse, error) {
	return methods.ReadNextTasks(ctx, r, req)
}

func (_ *ImplContext) ReadPreviousEvents(ctx context.Context, r soap.RoundTripper, req *types.ReadPreviousEvents) (*types.ReadPreviousEventsResponse, error) {
	return methods.ReadPreviousEvents(ctx, r, req)
}

func (_ *ImplContext) ReadPreviousTasks(ctx context.Context, r soap.RoundTripper, req *types.ReadPreviousTasks) (*types.ReadPreviousTasksResponse, error) {
	return methods.ReadPreviousTasks(ctx, r, req)
}

func (_ *ImplContext) RebootGuest(ctx context.Context, r soap.RoundTripper, req *types.RebootGuest) (*types.RebootGuestResponse, error) {
	return methods.RebootGuest(ctx, r, req)
}

func (_ *ImplContext) RebootHost_Task(ctx context.Context, r soap.RoundTripper, req *types.RebootHost_Task) (*types.RebootHost_TaskResponse, error) {
	return methods.RebootHost_Task(ctx, r, req)
}

func (_ *ImplContext) RecommendDatastores(ctx context.Context, r soap.RoundTripper, req *types.RecommendDatastores) (*types.RecommendDatastoresResponse, error) {
	return methods.RecommendDatastores(ctx, r, req)
}

func (_ *ImplContext) RecommendHostsForVm(ctx context.Context, r soap.RoundTripper, req *types.RecommendHostsForVm) (*types.RecommendHostsForVmResponse, error) {
	return methods.RecommendHostsForVm(ctx, r, req)
}

func (_ *ImplContext) RecommissionVsanNode_Task(ctx context.Context, r soap.RoundTripper, req *types.RecommissionVsanNode_Task) (*types.RecommissionVsanNode_TaskResponse, error) {
	return methods.RecommissionVsanNode_Task(ctx, r, req)
}

func (_ *ImplContext) ReconcileDatastoreInventory_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconcileDatastoreInventory_Task) (*types.ReconcileDatastoreInventory_TaskResponse, error) {
	return methods.ReconcileDatastoreInventory_Task(ctx, r, req)
}

func (_ *ImplContext) ReconfigVM_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigVM_Task) (*types.ReconfigVM_TaskResponse, error) {
	return methods.ReconfigVM_Task(ctx, r, req)
}

func (_ *ImplContext) ReconfigurationSatisfiable(ctx context.Context, r soap.RoundTripper, req *types.ReconfigurationSatisfiable) (*types.ReconfigurationSatisfiableResponse, error) {
	return methods.ReconfigurationSatisfiable(ctx, r, req)
}

func (_ *ImplContext) ReconfigureAlarm(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureAlarm) (*types.ReconfigureAlarmResponse, error) {
	return methods.ReconfigureAlarm(ctx, r, req)
}

func (_ *ImplContext) ReconfigureAutostart(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureAutostart) (*types.ReconfigureAutostartResponse, error) {
	return methods.ReconfigureAutostart(ctx, r, req)
}

func (_ *ImplContext) ReconfigureCluster_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureCluster_Task) (*types.ReconfigureCluster_TaskResponse, error) {
	return methods.ReconfigureCluster_Task(ctx, r, req)
}

func (_ *ImplContext) ReconfigureComputeResource_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureComputeResource_Task) (*types.ReconfigureComputeResource_TaskResponse, error) {
	return methods.ReconfigureComputeResource_Task(ctx, r, req)
}

func (_ *ImplContext) ReconfigureDVPort_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDVPort_Task) (*types.ReconfigureDVPort_TaskResponse, error) {
	return methods.ReconfigureDVPort_Task(ctx, r, req)
}

func (_ *ImplContext) ReconfigureDVPortgroup_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDVPortgroup_Task) (*types.ReconfigureDVPortgroup_TaskResponse, error) {
	return methods.ReconfigureDVPortgroup_Task(ctx, r, req)
}

func (_ *ImplContext) ReconfigureDatacenter_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDatacenter_Task) (*types.ReconfigureDatacenter_TaskResponse, error) {
	return methods.ReconfigureDatacenter_Task(ctx, r, req)
}

func (_ *ImplContext) ReconfigureDomObject(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDomObject) (*types.ReconfigureDomObjectResponse, error) {
	return methods.ReconfigureDomObject(ctx, r, req)
}

func (_ *ImplContext) ReconfigureDvs_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureDvs_Task) (*types.ReconfigureDvs_TaskResponse, error) {
	return methods.ReconfigureDvs_Task(ctx, r, req)
}

func (_ *ImplContext) ReconfigureHostForDAS_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureHostForDAS_Task) (*types.ReconfigureHostForDAS_TaskResponse, error) {
	return methods.ReconfigureHostForDAS_Task(ctx, r, req)
}

func (_ *ImplContext) ReconfigureScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureScheduledTask) (*types.ReconfigureScheduledTaskResponse, error) {
	return methods.ReconfigureScheduledTask(ctx, r, req)
}

func (_ *ImplContext) ReconfigureServiceConsoleReservation(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureServiceConsoleReservation) (*types.ReconfigureServiceConsoleReservationResponse, error) {
	return methods.ReconfigureServiceConsoleReservation(ctx, r, req)
}

func (_ *ImplContext) ReconfigureSnmpAgent(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureSnmpAgent) (*types.ReconfigureSnmpAgentResponse, error) {
	return methods.ReconfigureSnmpAgent(ctx, r, req)
}

func (_ *ImplContext) ReconfigureVirtualMachineReservation(ctx context.Context, r soap.RoundTripper, req *types.ReconfigureVirtualMachineReservation) (*types.ReconfigureVirtualMachineReservationResponse, error) {
	return methods.ReconfigureVirtualMachineReservation(ctx, r, req)
}

func (_ *ImplContext) ReconnectHost_Task(ctx context.Context, r soap.RoundTripper, req *types.ReconnectHost_Task) (*types.ReconnectHost_TaskResponse, error) {
	return methods.ReconnectHost_Task(ctx, r, req)
}

func (_ *ImplContext) RectifyDvsHost_Task(ctx context.Context, r soap.RoundTripper, req *types.RectifyDvsHost_Task) (*types.RectifyDvsHost_TaskResponse, error) {
	return methods.RectifyDvsHost_Task(ctx, r, req)
}

func (_ *ImplContext) RectifyDvsOnHost_Task(ctx context.Context, r soap.RoundTripper, req *types.RectifyDvsOnHost_Task) (*types.RectifyDvsOnHost_TaskResponse, error) {
	return methods.RectifyDvsOnHost_Task(ctx, r, req)
}

func (_ *ImplContext) Refresh(ctx context.Context, r soap.RoundTripper, req *types.Refresh) (*types.RefreshResponse, error) {
	return methods.Refresh(ctx, r, req)
}

func (_ *ImplContext) RefreshDVPortState(ctx context.Context, r soap.RoundTripper, req *types.RefreshDVPortState) (*types.RefreshDVPortStateResponse, error) {
	return methods.RefreshDVPortState(ctx, r, req)
}

func (_ *ImplContext) RefreshDatastore(ctx context.Context, r soap.RoundTripper, req *types.RefreshDatastore) (*types.RefreshDatastoreResponse, error) {
	return methods.RefreshDatastore(ctx, r, req)
}

func (_ *ImplContext) RefreshDatastoreStorageInfo(ctx context.Context, r soap.RoundTripper, req *types.RefreshDatastoreStorageInfo) (*types.RefreshDatastoreStorageInfoResponse, error) {
	return methods.RefreshDatastoreStorageInfo(ctx, r, req)
}

func (_ *ImplContext) RefreshDateTimeSystem(ctx context.Context, r soap.RoundTripper, req *types.RefreshDateTimeSystem) (*types.RefreshDateTimeSystemResponse, error) {
	return methods.RefreshDateTimeSystem(ctx, r, req)
}

func (_ *ImplContext) RefreshFirewall(ctx context.Context, r soap.RoundTripper, req *types.RefreshFirewall) (*types.RefreshFirewallResponse, error) {
	return methods.RefreshFirewall(ctx, r, req)
}

func (_ *ImplContext) RefreshGraphicsManager(ctx context.Context, r soap.RoundTripper, req *types.RefreshGraphicsManager) (*types.RefreshGraphicsManagerResponse, error) {
	return methods.RefreshGraphicsManager(ctx, r, req)
}

func (_ *ImplContext) RefreshHealthStatusSystem(ctx context.Context, r soap.RoundTripper, req *types.RefreshHealthStatusSystem) (*types.RefreshHealthStatusSystemResponse, error) {
	return methods.RefreshHealthStatusSystem(ctx, r, req)
}

func (_ *ImplContext) RefreshNetworkSystem(ctx context.Context, r soap.RoundTripper, req *types.RefreshNetworkSystem) (*types.RefreshNetworkSystemResponse, error) {
	return methods.RefreshNetworkSystem(ctx, r, req)
}

func (_ *ImplContext) RefreshRecommendation(ctx context.Context, r soap.RoundTripper, req *types.RefreshRecommendation) (*types.RefreshRecommendationResponse, error) {
	return methods.RefreshRecommendation(ctx, r, req)
}

func (_ *ImplContext) RefreshRuntime(ctx context.Context, r soap.RoundTripper, req *types.RefreshRuntime) (*types.RefreshRuntimeResponse, error) {
	return methods.RefreshRuntime(ctx, r, req)
}

func (_ *ImplContext) RefreshServices(ctx context.Context, r soap.RoundTripper, req *types.RefreshServices) (*types.RefreshServicesResponse, error) {
	return methods.RefreshServices(ctx, r, req)
}

func (_ *ImplContext) RefreshStorageDrsRecommendation(ctx context.Context, r soap.RoundTripper, req *types.RefreshStorageDrsRecommendation) (*types.RefreshStorageDrsRecommendationResponse, error) {
	return methods.RefreshStorageDrsRecommendation(ctx, r, req)
}

func (_ *ImplContext) RefreshStorageInfo(ctx context.Context, r soap.RoundTripper, req *types.RefreshStorageInfo) (*types.RefreshStorageInfoResponse, error) {
	return methods.RefreshStorageInfo(ctx, r, req)
}

func (_ *ImplContext) RefreshStorageSystem(ctx context.Context, r soap.RoundTripper, req *types.RefreshStorageSystem) (*types.RefreshStorageSystemResponse, error) {
	return methods.RefreshStorageSystem(ctx, r, req)
}

func (_ *ImplContext) RegisterChildVM_Task(ctx context.Context, r soap.RoundTripper, req *types.RegisterChildVM_Task) (*types.RegisterChildVM_TaskResponse, error) {
	return methods.RegisterChildVM_Task(ctx, r, req)
}

func (_ *ImplContext) RegisterDisk(ctx context.Context, r soap.RoundTripper, req *types.RegisterDisk) (*types.RegisterDiskResponse, error) {
	return methods.RegisterDisk(ctx, r, req)
}

func (_ *ImplContext) RegisterExtension(ctx context.Context, r soap.RoundTripper, req *types.RegisterExtension) (*types.RegisterExtensionResponse, error) {
	return methods.RegisterExtension(ctx, r, req)
}

func (_ *ImplContext) RegisterHealthUpdateProvider(ctx context.Context, r soap.RoundTripper, req *types.RegisterHealthUpdateProvider) (*types.RegisterHealthUpdateProviderResponse, error) {
	return methods.RegisterHealthUpdateProvider(ctx, r, req)
}

func (_ *ImplContext) RegisterKmipServer(ctx context.Context, r soap.RoundTripper, req *types.RegisterKmipServer) (*types.RegisterKmipServerResponse, error) {
	return methods.RegisterKmipServer(ctx, r, req)
}

func (_ *ImplContext) RegisterVM_Task(ctx context.Context, r soap.RoundTripper, req *types.RegisterVM_Task) (*types.RegisterVM_TaskResponse, error) {
	return methods.RegisterVM_Task(ctx, r, req)
}

func (_ *ImplContext) ReleaseCredentialsInGuest(ctx context.Context, r soap.RoundTripper, req *types.ReleaseCredentialsInGuest) (*types.ReleaseCredentialsInGuestResponse, error) {
	return methods.ReleaseCredentialsInGuest(ctx, r, req)
}

func (_ *ImplContext) ReleaseIpAllocation(ctx context.Context, r soap.RoundTripper, req *types.ReleaseIpAllocation) (*types.ReleaseIpAllocationResponse, error) {
	return methods.ReleaseIpAllocation(ctx, r, req)
}

func (_ *ImplContext) ReleaseManagedSnapshot(ctx context.Context, r soap.RoundTripper, req *types.ReleaseManagedSnapshot) (*types.ReleaseManagedSnapshotResponse, error) {
	return methods.ReleaseManagedSnapshot(ctx, r, req)
}

func (_ *ImplContext) Reload(ctx context.Context, r soap.RoundTripper, req *types.Reload) (*types.ReloadResponse, error) {
	return methods.Reload(ctx, r, req)
}

func (_ *ImplContext) RelocateVM_Task(ctx context.Context, r soap.RoundTripper, req *types.RelocateVM_Task) (*types.RelocateVM_TaskResponse, error) {
	return methods.RelocateVM_Task(ctx, r, req)
}

func (_ *ImplContext) RelocateVStorageObject_Task(ctx context.Context, r soap.RoundTripper, req *types.RelocateVStorageObject_Task) (*types.RelocateVStorageObject_TaskResponse, error) {
	return methods.RelocateVStorageObject_Task(ctx, r, req)
}

func (_ *ImplContext) RemoveAlarm(ctx context.Context, r soap.RoundTripper, req *types.RemoveAlarm) (*types.RemoveAlarmResponse, error) {
	return methods.RemoveAlarm(ctx, r, req)
}

func (_ *ImplContext) RemoveAllSnapshots_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveAllSnapshots_Task) (*types.RemoveAllSnapshots_TaskResponse, error) {
	return methods.RemoveAllSnapshots_Task(ctx, r, req)
}

func (_ *ImplContext) RemoveAssignedLicense(ctx context.Context, r soap.RoundTripper, req *types.RemoveAssignedLicense) (*types.RemoveAssignedLicenseResponse, error) {
	return methods.RemoveAssignedLicense(ctx, r, req)
}

func (_ *ImplContext) RemoveAuthorizationRole(ctx context.Context, r soap.RoundTripper, req *types.RemoveAuthorizationRole) (*types.RemoveAuthorizationRoleResponse, error) {
	return methods.RemoveAuthorizationRole(ctx, r, req)
}

func (_ *ImplContext) RemoveCustomFieldDef(ctx context.Context, r soap.RoundTripper, req *types.RemoveCustomFieldDef) (*types.RemoveCustomFieldDefResponse, error) {
	return methods.RemoveCustomFieldDef(ctx, r, req)
}

func (_ *ImplContext) RemoveDatastore(ctx context.Context, r soap.RoundTripper, req *types.RemoveDatastore) (*types.RemoveDatastoreResponse, error) {
	return methods.RemoveDatastore(ctx, r, req)
}

func (_ *ImplContext) RemoveDatastoreEx_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveDatastoreEx_Task) (*types.RemoveDatastoreEx_TaskResponse, error) {
	return methods.RemoveDatastoreEx_Task(ctx, r, req)
}

func (_ *ImplContext) RemoveDiskMapping_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveDiskMapping_Task) (*types.RemoveDiskMapping_TaskResponse, error) {
	return methods.RemoveDiskMapping_Task(ctx, r, req)
}

func (_ *ImplContext) RemoveDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveDisk_Task) (*types.RemoveDisk_TaskResponse, error) {
	return methods.RemoveDisk_Task(ctx, r, req)
}

func (_ *ImplContext) RemoveEntityPermission(ctx context.Context, r soap.RoundTripper, req *types.RemoveEntityPermission) (*types.RemoveEntityPermissionResponse, error) {
	return methods.RemoveEntityPermission(ctx, r, req)
}

func (_ *ImplContext) RemoveFilter(ctx context.Context, r soap.RoundTripper, req *types.RemoveFilter) (*types.RemoveFilterResponse, error) {
	return methods.RemoveFilter(ctx, r, req)
}

func (_ *ImplContext) RemoveFilterEntities(ctx context.Context, r soap.RoundTripper, req *types.RemoveFilterEntities) (*types.RemoveFilterEntitiesResponse, error) {
	return methods.RemoveFilterEntities(ctx, r, req)
}

func (_ *ImplContext) RemoveGroup(ctx context.Context, r soap.RoundTripper, req *types.RemoveGroup) (*types.RemoveGroupResponse, error) {
	return methods.RemoveGroup(ctx, r, req)
}

func (_ *ImplContext) RemoveGuestAlias(ctx context.Context, r soap.RoundTripper, req *types.RemoveGuestAlias) (*types.RemoveGuestAliasResponse, error) {
	return methods.RemoveGuestAlias(ctx, r, req)
}

func (_ *ImplContext) RemoveGuestAliasByCert(ctx context.Context, r soap.RoundTripper, req *types.RemoveGuestAliasByCert) (*types.RemoveGuestAliasByCertResponse, error) {
	return methods.RemoveGuestAliasByCert(ctx, r, req)
}

func (_ *ImplContext) RemoveInternetScsiSendTargets(ctx context.Context, r soap.RoundTripper, req *types.RemoveInternetScsiSendTargets) (*types.RemoveInternetScsiSendTargetsResponse, error) {
	return methods.RemoveInternetScsiSendTargets(ctx, r, req)
}

func (_ *ImplContext) RemoveInternetScsiStaticTargets(ctx context.Context, r soap.RoundTripper, req *types.RemoveInternetScsiStaticTargets) (*types.RemoveInternetScsiStaticTargetsResponse, error) {
	return methods.RemoveInternetScsiStaticTargets(ctx, r, req)
}

func (_ *ImplContext) RemoveKey(ctx context.Context, r soap.RoundTripper, req *types.RemoveKey) (*types.RemoveKeyResponse, error) {
	return methods.RemoveKey(ctx, r, req)
}

func (_ *ImplContext) RemoveKeys(ctx context.Context, r soap.RoundTripper, req *types.RemoveKeys) (*types.RemoveKeysResponse, error) {
	return methods.RemoveKeys(ctx, r, req)
}

func (_ *ImplContext) RemoveKmipServer(ctx context.Context, r soap.RoundTripper, req *types.RemoveKmipServer) (*types.RemoveKmipServerResponse, error) {
	return methods.RemoveKmipServer(ctx, r, req)
}

func (_ *ImplContext) RemoveLicense(ctx context.Context, r soap.RoundTripper, req *types.RemoveLicense) (*types.RemoveLicenseResponse, error) {
	return methods.RemoveLicense(ctx, r, req)
}

func (_ *ImplContext) RemoveLicenseLabel(ctx context.Context, r soap.RoundTripper, req *types.RemoveLicenseLabel) (*types.RemoveLicenseLabelResponse, error) {
	return methods.RemoveLicenseLabel(ctx, r, req)
}

func (_ *ImplContext) RemoveMonitoredEntities(ctx context.Context, r soap.RoundTripper, req *types.RemoveMonitoredEntities) (*types.RemoveMonitoredEntitiesResponse, error) {
	return methods.RemoveMonitoredEntities(ctx, r, req)
}

func (_ *ImplContext) RemoveNetworkResourcePool(ctx context.Context, r soap.RoundTripper, req *types.RemoveNetworkResourcePool) (*types.RemoveNetworkResourcePoolResponse, error) {
	return methods.RemoveNetworkResourcePool(ctx, r, req)
}

func (_ *ImplContext) RemovePerfInterval(ctx context.Context, r soap.RoundTripper, req *types.RemovePerfInterval) (*types.RemovePerfIntervalResponse, error) {
	return methods.RemovePerfInterval(ctx, r, req)
}

func (_ *ImplContext) RemovePortGroup(ctx context.Context, r soap.RoundTripper, req *types.RemovePortGroup) (*types.RemovePortGroupResponse, error) {
	return methods.RemovePortGroup(ctx, r, req)
}

func (_ *ImplContext) RemoveScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.RemoveScheduledTask) (*types.RemoveScheduledTaskResponse, error) {
	return methods.RemoveScheduledTask(ctx, r, req)
}

func (_ *ImplContext) RemoveServiceConsoleVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.RemoveServiceConsoleVirtualNic) (*types.RemoveServiceConsoleVirtualNicResponse, error) {
	return methods.RemoveServiceConsoleVirtualNic(ctx, r, req)
}

func (_ *ImplContext) RemoveSmartCardTrustAnchor(ctx context.Context, r soap.RoundTripper, req *types.RemoveSmartCardTrustAnchor) (*types.RemoveSmartCardTrustAnchorResponse, error) {
	return methods.RemoveSmartCardTrustAnchor(ctx, r, req)
}

func (_ *ImplContext) RemoveSmartCardTrustAnchorByFingerprint(ctx context.Context, r soap.RoundTripper, req *types.RemoveSmartCardTrustAnchorByFingerprint) (*types.RemoveSmartCardTrustAnchorByFingerprintResponse, error) {
	return methods.RemoveSmartCardTrustAnchorByFingerprint(ctx, r, req)
}

func (_ *ImplContext) RemoveSnapshot_Task(ctx context.Context, r soap.RoundTripper, req *types.RemoveSnapshot_Task) (*types.RemoveSnapshot_TaskResponse, error) {
	return methods.RemoveSnapshot_Task(ctx, r, req)
}

func (_ *ImplContext) RemoveUser(ctx context.Context, r soap.RoundTripper, req *types.RemoveUser) (*types.RemoveUserResponse, error) {
	return methods.RemoveUser(ctx, r, req)
}

func (_ *ImplContext) RemoveVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.RemoveVirtualNic) (*types.RemoveVirtualNicResponse, error) {
	return methods.RemoveVirtualNic(ctx, r, req)
}

func (_ *ImplContext) RemoveVirtualSwitch(ctx context.Context, r soap.RoundTripper, req *types.RemoveVirtualSwitch) (*types.RemoveVirtualSwitchResponse, error) {
	return methods.RemoveVirtualSwitch(ctx, r, req)
}

func (_ *ImplContext) RenameCustomFieldDef(ctx context.Context, r soap.RoundTripper, req *types.RenameCustomFieldDef) (*types.RenameCustomFieldDefResponse, error) {
	return methods.RenameCustomFieldDef(ctx, r, req)
}

func (_ *ImplContext) RenameCustomizationSpec(ctx context.Context, r soap.RoundTripper, req *types.RenameCustomizationSpec) (*types.RenameCustomizationSpecResponse, error) {
	return methods.RenameCustomizationSpec(ctx, r, req)
}

func (_ *ImplContext) RenameDatastore(ctx context.Context, r soap.RoundTripper, req *types.RenameDatastore) (*types.RenameDatastoreResponse, error) {
	return methods.RenameDatastore(ctx, r, req)
}

func (_ *ImplContext) RenameSnapshot(ctx context.Context, r soap.RoundTripper, req *types.RenameSnapshot) (*types.RenameSnapshotResponse, error) {
	return methods.RenameSnapshot(ctx, r, req)
}

func (_ *ImplContext) RenameVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.RenameVStorageObject) (*types.RenameVStorageObjectResponse, error) {
	return methods.RenameVStorageObject(ctx, r, req)
}

func (_ *ImplContext) Rename_Task(ctx context.Context, r soap.RoundTripper, req *types.Rename_Task) (*types.Rename_TaskResponse, error) {
	return methods.Rename_Task(ctx, r, req)
}

func (_ *ImplContext) ReplaceCACertificatesAndCRLs(ctx context.Context, r soap.RoundTripper, req *types.ReplaceCACertificatesAndCRLs) (*types.ReplaceCACertificatesAndCRLsResponse, error) {
	return methods.ReplaceCACertificatesAndCRLs(ctx, r, req)
}

func (_ *ImplContext) ReplaceSmartCardTrustAnchors(ctx context.Context, r soap.RoundTripper, req *types.ReplaceSmartCardTrustAnchors) (*types.ReplaceSmartCardTrustAnchorsResponse, error) {
	return methods.ReplaceSmartCardTrustAnchors(ctx, r, req)
}

func (_ *ImplContext) RescanAllHba(ctx context.Context, r soap.RoundTripper, req *types.RescanAllHba) (*types.RescanAllHbaResponse, error) {
	return methods.RescanAllHba(ctx, r, req)
}

func (_ *ImplContext) RescanHba(ctx context.Context, r soap.RoundTripper, req *types.RescanHba) (*types.RescanHbaResponse, error) {
	return methods.RescanHba(ctx, r, req)
}

func (_ *ImplContext) RescanVffs(ctx context.Context, r soap.RoundTripper, req *types.RescanVffs) (*types.RescanVffsResponse, error) {
	return methods.RescanVffs(ctx, r, req)
}

func (_ *ImplContext) RescanVmfs(ctx context.Context, r soap.RoundTripper, req *types.RescanVmfs) (*types.RescanVmfsResponse, error) {
	return methods.RescanVmfs(ctx, r, req)
}

func (_ *ImplContext) ResetCollector(ctx context.Context, r soap.RoundTripper, req *types.ResetCollector) (*types.ResetCollectorResponse, error) {
	return methods.ResetCollector(ctx, r, req)
}

func (_ *ImplContext) ResetCounterLevelMapping(ctx context.Context, r soap.RoundTripper, req *types.ResetCounterLevelMapping) (*types.ResetCounterLevelMappingResponse, error) {
	return methods.ResetCounterLevelMapping(ctx, r, req)
}

func (_ *ImplContext) ResetEntityPermissions(ctx context.Context, r soap.RoundTripper, req *types.ResetEntityPermissions) (*types.ResetEntityPermissionsResponse, error) {
	return methods.ResetEntityPermissions(ctx, r, req)
}

func (_ *ImplContext) ResetFirmwareToFactoryDefaults(ctx context.Context, r soap.RoundTripper, req *types.ResetFirmwareToFactoryDefaults) (*types.ResetFirmwareToFactoryDefaultsResponse, error) {
	return methods.ResetFirmwareToFactoryDefaults(ctx, r, req)
}

func (_ *ImplContext) ResetGuestInformation(ctx context.Context, r soap.RoundTripper, req *types.ResetGuestInformation) (*types.ResetGuestInformationResponse, error) {
	return methods.ResetGuestInformation(ctx, r, req)
}

func (_ *ImplContext) ResetListView(ctx context.Context, r soap.RoundTripper, req *types.ResetListView) (*types.ResetListViewResponse, error) {
	return methods.ResetListView(ctx, r, req)
}

func (_ *ImplContext) ResetListViewFromView(ctx context.Context, r soap.RoundTripper, req *types.ResetListViewFromView) (*types.ResetListViewFromViewResponse, error) {
	return methods.ResetListViewFromView(ctx, r, req)
}

func (_ *ImplContext) ResetSystemHealthInfo(ctx context.Context, r soap.RoundTripper, req *types.ResetSystemHealthInfo) (*types.ResetSystemHealthInfoResponse, error) {
	return methods.ResetSystemHealthInfo(ctx, r, req)
}

func (_ *ImplContext) ResetVM_Task(ctx context.Context, r soap.RoundTripper, req *types.ResetVM_Task) (*types.ResetVM_TaskResponse, error) {
	return methods.ResetVM_Task(ctx, r, req)
}

func (_ *ImplContext) ResignatureUnresolvedVmfsVolume_Task(ctx context.Context, r soap.RoundTripper, req *types.ResignatureUnresolvedVmfsVolume_Task) (*types.ResignatureUnresolvedVmfsVolume_TaskResponse, error) {
	return methods.ResignatureUnresolvedVmfsVolume_Task(ctx, r, req)
}

func (_ *ImplContext) ResolveInstallationErrorsOnCluster_Task(ctx context.Context, r soap.RoundTripper, req *types.ResolveInstallationErrorsOnCluster_Task) (*types.ResolveInstallationErrorsOnCluster_TaskResponse, error) {
	return methods.ResolveInstallationErrorsOnCluster_Task(ctx, r, req)
}

func (_ *ImplContext) ResolveInstallationErrorsOnHost_Task(ctx context.Context, r soap.RoundTripper, req *types.ResolveInstallationErrorsOnHost_Task) (*types.ResolveInstallationErrorsOnHost_TaskResponse, error) {
	return methods.ResolveInstallationErrorsOnHost_Task(ctx, r, req)
}

func (_ *ImplContext) ResolveMultipleUnresolvedVmfsVolumes(ctx context.Context, r soap.RoundTripper, req *types.ResolveMultipleUnresolvedVmfsVolumes) (*types.ResolveMultipleUnresolvedVmfsVolumesResponse, error) {
	return methods.ResolveMultipleUnresolvedVmfsVolumes(ctx, r, req)
}

func (_ *ImplContext) ResolveMultipleUnresolvedVmfsVolumesEx_Task(ctx context.Context, r soap.RoundTripper, req *types.ResolveMultipleUnresolvedVmfsVolumesEx_Task) (*types.ResolveMultipleUnresolvedVmfsVolumesEx_TaskResponse, error) {
	return methods.ResolveMultipleUnresolvedVmfsVolumesEx_Task(ctx, r, req)
}

func (_ *ImplContext) RestartService(ctx context.Context, r soap.RoundTripper, req *types.RestartService) (*types.RestartServiceResponse, error) {
	return methods.RestartService(ctx, r, req)
}

func (_ *ImplContext) RestartServiceConsoleVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.RestartServiceConsoleVirtualNic) (*types.RestartServiceConsoleVirtualNicResponse, error) {
	return methods.RestartServiceConsoleVirtualNic(ctx, r, req)
}

func (_ *ImplContext) RestoreFirmwareConfiguration(ctx context.Context, r soap.RoundTripper, req *types.RestoreFirmwareConfiguration) (*types.RestoreFirmwareConfigurationResponse, error) {
	return methods.RestoreFirmwareConfiguration(ctx, r, req)
}

func (_ *ImplContext) RetrieveAllPermissions(ctx context.Context, r soap.RoundTripper, req *types.RetrieveAllPermissions) (*types.RetrieveAllPermissionsResponse, error) {
	return methods.RetrieveAllPermissions(ctx, r, req)
}

func (_ *ImplContext) RetrieveAnswerFile(ctx context.Context, r soap.RoundTripper, req *types.RetrieveAnswerFile) (*types.RetrieveAnswerFileResponse, error) {
	return methods.RetrieveAnswerFile(ctx, r, req)
}

func (_ *ImplContext) RetrieveAnswerFileForProfile(ctx context.Context, r soap.RoundTripper, req *types.RetrieveAnswerFileForProfile) (*types.RetrieveAnswerFileForProfileResponse, error) {
	return methods.RetrieveAnswerFileForProfile(ctx, r, req)
}

func (_ *ImplContext) RetrieveArgumentDescription(ctx context.Context, r soap.RoundTripper, req *types.RetrieveArgumentDescription) (*types.RetrieveArgumentDescriptionResponse, error) {
	return methods.RetrieveArgumentDescription(ctx, r, req)
}

func (_ *ImplContext) RetrieveClientCert(ctx context.Context, r soap.RoundTripper, req *types.RetrieveClientCert) (*types.RetrieveClientCertResponse, error) {
	return methods.RetrieveClientCert(ctx, r, req)
}

func (_ *ImplContext) RetrieveClientCsr(ctx context.Context, r soap.RoundTripper, req *types.RetrieveClientCsr) (*types.RetrieveClientCsrResponse, error) {
	return methods.RetrieveClientCsr(ctx, r, req)
}

func (_ *ImplContext) RetrieveDasAdvancedRuntimeInfo(ctx context.Context, r soap.RoundTripper, req *types.RetrieveDasAdvancedRuntimeInfo) (*types.RetrieveDasAdvancedRuntimeInfoResponse, error) {
	return methods.RetrieveDasAdvancedRuntimeInfo(ctx, r, req)
}

func (_ *ImplContext) RetrieveDescription(ctx context.Context, r soap.RoundTripper, req *types.RetrieveDescription) (*types.RetrieveDescriptionResponse, error) {
	return methods.RetrieveDescription(ctx, r, req)
}

func (_ *ImplContext) RetrieveDiskPartitionInfo(ctx context.Context, r soap.RoundTripper, req *types.RetrieveDiskPartitionInfo) (*types.RetrieveDiskPartitionInfoResponse, error) {
	return methods.RetrieveDiskPartitionInfo(ctx, r, req)
}

func (_ *ImplContext) RetrieveEntityPermissions(ctx context.Context, r soap.RoundTripper, req *types.RetrieveEntityPermissions) (*types.RetrieveEntityPermissionsResponse, error) {
	return methods.RetrieveEntityPermissions(ctx, r, req)
}

func (_ *ImplContext) RetrieveEntityScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.RetrieveEntityScheduledTask) (*types.RetrieveEntityScheduledTaskResponse, error) {
	return methods.RetrieveEntityScheduledTask(ctx, r, req)
}

func (_ *ImplContext) RetrieveHardwareUptime(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHardwareUptime) (*types.RetrieveHardwareUptimeResponse, error) {
	return methods.RetrieveHardwareUptime(ctx, r, req)
}

func (_ *ImplContext) RetrieveHostAccessControlEntries(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHostAccessControlEntries) (*types.RetrieveHostAccessControlEntriesResponse, error) {
	return methods.RetrieveHostAccessControlEntries(ctx, r, req)
}

func (_ *ImplContext) RetrieveHostCustomizations(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHostCustomizations) (*types.RetrieveHostCustomizationsResponse, error) {
	return methods.RetrieveHostCustomizations(ctx, r, req)
}

func (_ *ImplContext) RetrieveHostCustomizationsForProfile(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHostCustomizationsForProfile) (*types.RetrieveHostCustomizationsForProfileResponse, error) {
	return methods.RetrieveHostCustomizationsForProfile(ctx, r, req)
}

func (_ *ImplContext) RetrieveHostSpecification(ctx context.Context, r soap.RoundTripper, req *types.RetrieveHostSpecification) (*types.RetrieveHostSpecificationResponse, error) {
	return methods.RetrieveHostSpecification(ctx, r, req)
}

func (_ *ImplContext) RetrieveKmipServerCert(ctx context.Context, r soap.RoundTripper, req *types.RetrieveKmipServerCert) (*types.RetrieveKmipServerCertResponse, error) {
	return methods.RetrieveKmipServerCert(ctx, r, req)
}

func (_ *ImplContext) RetrieveKmipServersStatus_Task(ctx context.Context, r soap.RoundTripper, req *types.RetrieveKmipServersStatus_Task) (*types.RetrieveKmipServersStatus_TaskResponse, error) {
	return methods.RetrieveKmipServersStatus_Task(ctx, r, req)
}

func (_ *ImplContext) RetrieveObjectScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.RetrieveObjectScheduledTask) (*types.RetrieveObjectScheduledTaskResponse, error) {
	return methods.RetrieveObjectScheduledTask(ctx, r, req)
}

func (_ *ImplContext) RetrieveProductComponents(ctx context.Context, r soap.RoundTripper, req *types.RetrieveProductComponents) (*types.RetrieveProductComponentsResponse, error) {
	return methods.RetrieveProductComponents(ctx, r, req)
}

func (_ *ImplContext) RetrieveProperties(ctx context.Context, r soap.RoundTripper, req *types.RetrieveProperties) (*types.RetrievePropertiesResponse, error) {
	return methods.RetrieveProperties(ctx, r, req)
}

func (_ *ImplContext) RetrievePropertiesEx(ctx context.Context, r soap.RoundTripper, req *types.RetrievePropertiesEx) (*types.RetrievePropertiesExResponse, error) {
	return methods.RetrievePropertiesEx(ctx, r, req)
}

func (_ *ImplContext) RetrieveRolePermissions(ctx context.Context, r soap.RoundTripper, req *types.RetrieveRolePermissions) (*types.RetrieveRolePermissionsResponse, error) {
	return methods.RetrieveRolePermissions(ctx, r, req)
}

func (_ *ImplContext) RetrieveSelfSignedClientCert(ctx context.Context, r soap.RoundTripper, req *types.RetrieveSelfSignedClientCert) (*types.RetrieveSelfSignedClientCertResponse, error) {
	return methods.RetrieveSelfSignedClientCert(ctx, r, req)
}

func (_ *ImplContext) RetrieveServiceContent(ctx context.Context, r soap.RoundTripper, req *types.RetrieveServiceContent) (*types.RetrieveServiceContentResponse, error) {
	return methods.RetrieveServiceContent(ctx, r, req)
}

func (_ *ImplContext) RetrieveUserGroups(ctx context.Context, r soap.RoundTripper, req *types.RetrieveUserGroups) (*types.RetrieveUserGroupsResponse, error) {
	return methods.RetrieveUserGroups(ctx, r, req)
}

func (_ *ImplContext) RetrieveVStorageObject(ctx context.Context, r soap.RoundTripper, req *types.RetrieveVStorageObject) (*types.RetrieveVStorageObjectResponse, error) {
	return methods.RetrieveVStorageObject(ctx, r, req)
}

func (_ *ImplContext) RetrieveVStorageObjectState(ctx context.Context, r soap.RoundTripper, req *types.RetrieveVStorageObjectState) (*types.RetrieveVStorageObjectStateResponse, error) {
	return methods.RetrieveVStorageObjectState(ctx, r, req)
}

func (_ *ImplContext) RevertToCurrentSnapshot_Task(ctx context.Context, r soap.RoundTripper, req *types.RevertToCurrentSnapshot_Task) (*types.RevertToCurrentSnapshot_TaskResponse, error) {
	return methods.RevertToCurrentSnapshot_Task(ctx, r, req)
}

func (_ *ImplContext) RevertToSnapshot_Task(ctx context.Context, r soap.RoundTripper, req *types.RevertToSnapshot_Task) (*types.RevertToSnapshot_TaskResponse, error) {
	return methods.RevertToSnapshot_Task(ctx, r, req)
}

func (_ *ImplContext) RewindCollector(ctx context.Context, r soap.RoundTripper, req *types.RewindCollector) (*types.RewindCollectorResponse, error) {
	return methods.RewindCollector(ctx, r, req)
}

func (_ *ImplContext) RunScheduledTask(ctx context.Context, r soap.RoundTripper, req *types.RunScheduledTask) (*types.RunScheduledTaskResponse, error) {
	return methods.RunScheduledTask(ctx, r, req)
}

func (_ *ImplContext) RunVsanPhysicalDiskDiagnostics(ctx context.Context, r soap.RoundTripper, req *types.RunVsanPhysicalDiskDiagnostics) (*types.RunVsanPhysicalDiskDiagnosticsResponse, error) {
	return methods.RunVsanPhysicalDiskDiagnostics(ctx, r, req)
}

func (_ *ImplContext) ScanHostPatchV2_Task(ctx context.Context, r soap.RoundTripper, req *types.ScanHostPatchV2_Task) (*types.ScanHostPatchV2_TaskResponse, error) {
	return methods.ScanHostPatchV2_Task(ctx, r, req)
}

func (_ *ImplContext) ScanHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.ScanHostPatch_Task) (*types.ScanHostPatch_TaskResponse, error) {
	return methods.ScanHostPatch_Task(ctx, r, req)
}

func (_ *ImplContext) ScheduleReconcileDatastoreInventory(ctx context.Context, r soap.RoundTripper, req *types.ScheduleReconcileDatastoreInventory) (*types.ScheduleReconcileDatastoreInventoryResponse, error) {
	return methods.ScheduleReconcileDatastoreInventory(ctx, r, req)
}

func (_ *ImplContext) SearchDatastoreSubFolders_Task(ctx context.Context, r soap.RoundTripper, req *types.SearchDatastoreSubFolders_Task) (*types.SearchDatastoreSubFolders_TaskResponse, error) {
	return methods.SearchDatastoreSubFolders_Task(ctx, r, req)
}

func (_ *ImplContext) SearchDatastore_Task(ctx context.Context, r soap.RoundTripper, req *types.SearchDatastore_Task) (*types.SearchDatastore_TaskResponse, error) {
	return methods.SearchDatastore_Task(ctx, r, req)
}

func (_ *ImplContext) SelectActivePartition(ctx context.Context, r soap.RoundTripper, req *types.SelectActivePartition) (*types.SelectActivePartitionResponse, error) {
	return methods.SelectActivePartition(ctx, r, req)
}

func (_ *ImplContext) SelectVnic(ctx context.Context, r soap.RoundTripper, req *types.SelectVnic) (*types.SelectVnicResponse, error) {
	return methods.SelectVnic(ctx, r, req)
}

func (_ *ImplContext) SelectVnicForNicType(ctx context.Context, r soap.RoundTripper, req *types.SelectVnicForNicType) (*types.SelectVnicForNicTypeResponse, error) {
	return methods.SelectVnicForNicType(ctx, r, req)
}

func (_ *ImplContext) SendNMI(ctx context.Context, r soap.RoundTripper, req *types.SendNMI) (*types.SendNMIResponse, error) {
	return methods.SendNMI(ctx, r, req)
}

func (_ *ImplContext) SendTestNotification(ctx context.Context, r soap.RoundTripper, req *types.SendTestNotification) (*types.SendTestNotificationResponse, error) {
	return methods.SendTestNotification(ctx, r, req)
}

func (_ *ImplContext) SessionIsActive(ctx context.Context, r soap.RoundTripper, req *types.SessionIsActive) (*types.SessionIsActiveResponse, error) {
	return methods.SessionIsActive(ctx, r, req)
}

func (_ *ImplContext) SetCollectorPageSize(ctx context.Context, r soap.RoundTripper, req *types.SetCollectorPageSize) (*types.SetCollectorPageSizeResponse, error) {
	return methods.SetCollectorPageSize(ctx, r, req)
}

func (_ *ImplContext) SetDisplayTopology(ctx context.Context, r soap.RoundTripper, req *types.SetDisplayTopology) (*types.SetDisplayTopologyResponse, error) {
	return methods.SetDisplayTopology(ctx, r, req)
}

func (_ *ImplContext) SetEntityPermissions(ctx context.Context, r soap.RoundTripper, req *types.SetEntityPermissions) (*types.SetEntityPermissionsResponse, error) {
	return methods.SetEntityPermissions(ctx, r, req)
}

func (_ *ImplContext) SetExtensionCertificate(ctx context.Context, r soap.RoundTripper, req *types.SetExtensionCertificate) (*types.SetExtensionCertificateResponse, error) {
	return methods.SetExtensionCertificate(ctx, r, req)
}

func (_ *ImplContext) SetField(ctx context.Context, r soap.RoundTripper, req *types.SetField) (*types.SetFieldResponse, error) {
	return methods.SetField(ctx, r, req)
}

func (_ *ImplContext) SetLicenseEdition(ctx context.Context, r soap.RoundTripper, req *types.SetLicenseEdition) (*types.SetLicenseEditionResponse, error) {
	return methods.SetLicenseEdition(ctx, r, req)
}

func (_ *ImplContext) SetLocale(ctx context.Context, r soap.RoundTripper, req *types.SetLocale) (*types.SetLocaleResponse, error) {
	return methods.SetLocale(ctx, r, req)
}

func (_ *ImplContext) SetMultipathLunPolicy(ctx context.Context, r soap.RoundTripper, req *types.SetMultipathLunPolicy) (*types.SetMultipathLunPolicyResponse, error) {
	return methods.SetMultipathLunPolicy(ctx, r, req)
}

func (_ *ImplContext) SetNFSUser(ctx context.Context, r soap.RoundTripper, req *types.SetNFSUser) (*types.SetNFSUserResponse, error) {
	return methods.SetNFSUser(ctx, r, req)
}

func (_ *ImplContext) SetPublicKey(ctx context.Context, r soap.RoundTripper, req *types.SetPublicKey) (*types.SetPublicKeyResponse, error) {
	return methods.SetPublicKey(ctx, r, req)
}

func (_ *ImplContext) SetRegistryValueInGuest(ctx context.Context, r soap.RoundTripper, req *types.SetRegistryValueInGuest) (*types.SetRegistryValueInGuestResponse, error) {
	return methods.SetRegistryValueInGuest(ctx, r, req)
}

func (_ *ImplContext) SetScreenResolution(ctx context.Context, r soap.RoundTripper, req *types.SetScreenResolution) (*types.SetScreenResolutionResponse, error) {
	return methods.SetScreenResolution(ctx, r, req)
}

func (_ *ImplContext) SetTaskDescription(ctx context.Context, r soap.RoundTripper, req *types.SetTaskDescription) (*types.SetTaskDescriptionResponse, error) {
	return methods.SetTaskDescription(ctx, r, req)
}

func (_ *ImplContext) SetTaskState(ctx context.Context, r soap.RoundTripper, req *types.SetTaskState) (*types.SetTaskStateResponse, error) {
	return methods.SetTaskState(ctx, r, req)
}

func (_ *ImplContext) SetVirtualDiskUuid(ctx context.Context, r soap.RoundTripper, req *types.SetVirtualDiskUuid) (*types.SetVirtualDiskUuidResponse, error) {
	return methods.SetVirtualDiskUuid(ctx, r, req)
}

func (_ *ImplContext) ShrinkVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.ShrinkVirtualDisk_Task) (*types.ShrinkVirtualDisk_TaskResponse, error) {
	return methods.ShrinkVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) ShutdownGuest(ctx context.Context, r soap.RoundTripper, req *types.ShutdownGuest) (*types.ShutdownGuestResponse, error) {
	return methods.ShutdownGuest(ctx, r, req)
}

func (_ *ImplContext) ShutdownHost_Task(ctx context.Context, r soap.RoundTripper, req *types.ShutdownHost_Task) (*types.ShutdownHost_TaskResponse, error) {
	return methods.ShutdownHost_Task(ctx, r, req)
}

func (_ *ImplContext) StageHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.StageHostPatch_Task) (*types.StageHostPatch_TaskResponse, error) {
	return methods.StageHostPatch_Task(ctx, r, req)
}

func (_ *ImplContext) StampAllRulesWithUuid_Task(ctx context.Context, r soap.RoundTripper, req *types.StampAllRulesWithUuid_Task) (*types.StampAllRulesWithUuid_TaskResponse, error) {
	return methods.StampAllRulesWithUuid_Task(ctx, r, req)
}

func (_ *ImplContext) StandbyGuest(ctx context.Context, r soap.RoundTripper, req *types.StandbyGuest) (*types.StandbyGuestResponse, error) {
	return methods.StandbyGuest(ctx, r, req)
}

func (_ *ImplContext) StartProgramInGuest(ctx context.Context, r soap.RoundTripper, req *types.StartProgramInGuest) (*types.StartProgramInGuestResponse, error) {
	return methods.StartProgramInGuest(ctx, r, req)
}

func (_ *ImplContext) StartRecording_Task(ctx context.Context, r soap.RoundTripper, req *types.StartRecording_Task) (*types.StartRecording_TaskResponse, error) {
	return methods.StartRecording_Task(ctx, r, req)
}

func (_ *ImplContext) StartReplaying_Task(ctx context.Context, r soap.RoundTripper, req *types.StartReplaying_Task) (*types.StartReplaying_TaskResponse, error) {
	return methods.StartReplaying_Task(ctx, r, req)
}

func (_ *ImplContext) StartService(ctx context.Context, r soap.RoundTripper, req *types.StartService) (*types.StartServiceResponse, error) {
	return methods.StartService(ctx, r, req)
}

func (_ *ImplContext) StopRecording_Task(ctx context.Context, r soap.RoundTripper, req *types.StopRecording_Task) (*types.StopRecording_TaskResponse, error) {
	return methods.StopRecording_Task(ctx, r, req)
}

func (_ *ImplContext) StopReplaying_Task(ctx context.Context, r soap.RoundTripper, req *types.StopReplaying_Task) (*types.StopReplaying_TaskResponse, error) {
	return methods.StopReplaying_Task(ctx, r, req)
}

func (_ *ImplContext) StopService(ctx context.Context, r soap.RoundTripper, req *types.StopService) (*types.StopServiceResponse, error) {
	return methods.StopService(ctx, r, req)
}

func (_ *ImplContext) SuspendVApp_Task(ctx context.Context, r soap.RoundTripper, req *types.SuspendVApp_Task) (*types.SuspendVApp_TaskResponse, error) {
	return methods.SuspendVApp_Task(ctx, r, req)
}

func (_ *ImplContext) SuspendVM_Task(ctx context.Context, r soap.RoundTripper, req *types.SuspendVM_Task) (*types.SuspendVM_TaskResponse, error) {
	return methods.SuspendVM_Task(ctx, r, req)
}

func (_ *ImplContext) TerminateFaultTolerantVM_Task(ctx context.Context, r soap.RoundTripper, req *types.TerminateFaultTolerantVM_Task) (*types.TerminateFaultTolerantVM_TaskResponse, error) {
	return methods.TerminateFaultTolerantVM_Task(ctx, r, req)
}

func (_ *ImplContext) TerminateProcessInGuest(ctx context.Context, r soap.RoundTripper, req *types.TerminateProcessInGuest) (*types.TerminateProcessInGuestResponse, error) {
	return methods.TerminateProcessInGuest(ctx, r, req)
}

func (_ *ImplContext) TerminateSession(ctx context.Context, r soap.RoundTripper, req *types.TerminateSession) (*types.TerminateSessionResponse, error) {
	return methods.TerminateSession(ctx, r, req)
}

func (_ *ImplContext) TerminateVM(ctx context.Context, r soap.RoundTripper, req *types.TerminateVM) (*types.TerminateVMResponse, error) {
	return methods.TerminateVM(ctx, r, req)
}

func (_ *ImplContext) TurnDiskLocatorLedOff_Task(ctx context.Context, r soap.RoundTripper, req *types.TurnDiskLocatorLedOff_Task) (*types.TurnDiskLocatorLedOff_TaskResponse, error) {
	return methods.TurnDiskLocatorLedOff_Task(ctx, r, req)
}

func (_ *ImplContext) TurnDiskLocatorLedOn_Task(ctx context.Context, r soap.RoundTripper, req *types.TurnDiskLocatorLedOn_Task) (*types.TurnDiskLocatorLedOn_TaskResponse, error) {
	return methods.TurnDiskLocatorLedOn_Task(ctx, r, req)
}

func (_ *ImplContext) TurnOffFaultToleranceForVM_Task(ctx context.Context, r soap.RoundTripper, req *types.TurnOffFaultToleranceForVM_Task) (*types.TurnOffFaultToleranceForVM_TaskResponse, error) {
	return methods.TurnOffFaultToleranceForVM_Task(ctx, r, req)
}

func (_ *ImplContext) UnassignUserFromGroup(ctx context.Context, r soap.RoundTripper, req *types.UnassignUserFromGroup) (*types.UnassignUserFromGroupResponse, error) {
	return methods.UnassignUserFromGroup(ctx, r, req)
}

func (_ *ImplContext) UnbindVnic(ctx context.Context, r soap.RoundTripper, req *types.UnbindVnic) (*types.UnbindVnicResponse, error) {
	return methods.UnbindVnic(ctx, r, req)
}

func (_ *ImplContext) UninstallHostPatch_Task(ctx context.Context, r soap.RoundTripper, req *types.UninstallHostPatch_Task) (*types.UninstallHostPatch_TaskResponse, error) {
	return methods.UninstallHostPatch_Task(ctx, r, req)
}

func (_ *ImplContext) UninstallIoFilter_Task(ctx context.Context, r soap.RoundTripper, req *types.UninstallIoFilter_Task) (*types.UninstallIoFilter_TaskResponse, error) {
	return methods.UninstallIoFilter_Task(ctx, r, req)
}

func (_ *ImplContext) UninstallService(ctx context.Context, r soap.RoundTripper, req *types.UninstallService) (*types.UninstallServiceResponse, error) {
	return methods.UninstallService(ctx, r, req)
}

func (_ *ImplContext) UnmapVmfsVolumeEx_Task(ctx context.Context, r soap.RoundTripper, req *types.UnmapVmfsVolumeEx_Task) (*types.UnmapVmfsVolumeEx_TaskResponse, error) {
	return methods.UnmapVmfsVolumeEx_Task(ctx, r, req)
}

func (_ *ImplContext) UnmountDiskMapping_Task(ctx context.Context, r soap.RoundTripper, req *types.UnmountDiskMapping_Task) (*types.UnmountDiskMapping_TaskResponse, error) {
	return methods.UnmountDiskMapping_Task(ctx, r, req)
}

func (_ *ImplContext) UnmountForceMountedVmfsVolume(ctx context.Context, r soap.RoundTripper, req *types.UnmountForceMountedVmfsVolume) (*types.UnmountForceMountedVmfsVolumeResponse, error) {
	return methods.UnmountForceMountedVmfsVolume(ctx, r, req)
}

func (_ *ImplContext) UnmountToolsInstaller(ctx context.Context, r soap.RoundTripper, req *types.UnmountToolsInstaller) (*types.UnmountToolsInstallerResponse, error) {
	return methods.UnmountToolsInstaller(ctx, r, req)
}

func (_ *ImplContext) UnmountVffsVolume(ctx context.Context, r soap.RoundTripper, req *types.UnmountVffsVolume) (*types.UnmountVffsVolumeResponse, error) {
	return methods.UnmountVffsVolume(ctx, r, req)
}

func (_ *ImplContext) UnmountVmfsVolume(ctx context.Context, r soap.RoundTripper, req *types.UnmountVmfsVolume) (*types.UnmountVmfsVolumeResponse, error) {
	return methods.UnmountVmfsVolume(ctx, r, req)
}

func (_ *ImplContext) UnmountVmfsVolumeEx_Task(ctx context.Context, r soap.RoundTripper, req *types.UnmountVmfsVolumeEx_Task) (*types.UnmountVmfsVolumeEx_TaskResponse, error) {
	return methods.UnmountVmfsVolumeEx_Task(ctx, r, req)
}

func (_ *ImplContext) UnregisterAndDestroy_Task(ctx context.Context, r soap.RoundTripper, req *types.UnregisterAndDestroy_Task) (*types.UnregisterAndDestroy_TaskResponse, error) {
	return methods.UnregisterAndDestroy_Task(ctx, r, req)
}

func (_ *ImplContext) UnregisterExtension(ctx context.Context, r soap.RoundTripper, req *types.UnregisterExtension) (*types.UnregisterExtensionResponse, error) {
	return methods.UnregisterExtension(ctx, r, req)
}

func (_ *ImplContext) UnregisterHealthUpdateProvider(ctx context.Context, r soap.RoundTripper, req *types.UnregisterHealthUpdateProvider) (*types.UnregisterHealthUpdateProviderResponse, error) {
	return methods.UnregisterHealthUpdateProvider(ctx, r, req)
}

func (_ *ImplContext) UnregisterVM(ctx context.Context, r soap.RoundTripper, req *types.UnregisterVM) (*types.UnregisterVMResponse, error) {
	return methods.UnregisterVM(ctx, r, req)
}

func (_ *ImplContext) UpdateAnswerFile_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateAnswerFile_Task) (*types.UpdateAnswerFile_TaskResponse, error) {
	return methods.UpdateAnswerFile_Task(ctx, r, req)
}

func (_ *ImplContext) UpdateAssignedLicense(ctx context.Context, r soap.RoundTripper, req *types.UpdateAssignedLicense) (*types.UpdateAssignedLicenseResponse, error) {
	return methods.UpdateAssignedLicense(ctx, r, req)
}

func (_ *ImplContext) UpdateAuthorizationRole(ctx context.Context, r soap.RoundTripper, req *types.UpdateAuthorizationRole) (*types.UpdateAuthorizationRoleResponse, error) {
	return methods.UpdateAuthorizationRole(ctx, r, req)
}

func (_ *ImplContext) UpdateBootDevice(ctx context.Context, r soap.RoundTripper, req *types.UpdateBootDevice) (*types.UpdateBootDeviceResponse, error) {
	return methods.UpdateBootDevice(ctx, r, req)
}

func (_ *ImplContext) UpdateChildResourceConfiguration(ctx context.Context, r soap.RoundTripper, req *types.UpdateChildResourceConfiguration) (*types.UpdateChildResourceConfigurationResponse, error) {
	return methods.UpdateChildResourceConfiguration(ctx, r, req)
}

func (_ *ImplContext) UpdateClusterProfile(ctx context.Context, r soap.RoundTripper, req *types.UpdateClusterProfile) (*types.UpdateClusterProfileResponse, error) {
	return methods.UpdateClusterProfile(ctx, r, req)
}

func (_ *ImplContext) UpdateConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateConfig) (*types.UpdateConfigResponse, error) {
	return methods.UpdateConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateConsoleIpRouteConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateConsoleIpRouteConfig) (*types.UpdateConsoleIpRouteConfigResponse, error) {
	return methods.UpdateConsoleIpRouteConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateCounterLevelMapping(ctx context.Context, r soap.RoundTripper, req *types.UpdateCounterLevelMapping) (*types.UpdateCounterLevelMappingResponse, error) {
	return methods.UpdateCounterLevelMapping(ctx, r, req)
}

func (_ *ImplContext) UpdateDVSHealthCheckConfig_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateDVSHealthCheckConfig_Task) (*types.UpdateDVSHealthCheckConfig_TaskResponse, error) {
	return methods.UpdateDVSHealthCheckConfig_Task(ctx, r, req)
}

func (_ *ImplContext) UpdateDVSLacpGroupConfig_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateDVSLacpGroupConfig_Task) (*types.UpdateDVSLacpGroupConfig_TaskResponse, error) {
	return methods.UpdateDVSLacpGroupConfig_Task(ctx, r, req)
}

func (_ *ImplContext) UpdateDateTime(ctx context.Context, r soap.RoundTripper, req *types.UpdateDateTime) (*types.UpdateDateTimeResponse, error) {
	return methods.UpdateDateTime(ctx, r, req)
}

func (_ *ImplContext) UpdateDateTimeConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateDateTimeConfig) (*types.UpdateDateTimeConfigResponse, error) {
	return methods.UpdateDateTimeConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateDefaultPolicy(ctx context.Context, r soap.RoundTripper, req *types.UpdateDefaultPolicy) (*types.UpdateDefaultPolicyResponse, error) {
	return methods.UpdateDefaultPolicy(ctx, r, req)
}

func (_ *ImplContext) UpdateDiskPartitions(ctx context.Context, r soap.RoundTripper, req *types.UpdateDiskPartitions) (*types.UpdateDiskPartitionsResponse, error) {
	return methods.UpdateDiskPartitions(ctx, r, req)
}

func (_ *ImplContext) UpdateDnsConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateDnsConfig) (*types.UpdateDnsConfigResponse, error) {
	return methods.UpdateDnsConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateDvsCapability(ctx context.Context, r soap.RoundTripper, req *types.UpdateDvsCapability) (*types.UpdateDvsCapabilityResponse, error) {
	return methods.UpdateDvsCapability(ctx, r, req)
}

func (_ *ImplContext) UpdateExtension(ctx context.Context, r soap.RoundTripper, req *types.UpdateExtension) (*types.UpdateExtensionResponse, error) {
	return methods.UpdateExtension(ctx, r, req)
}

func (_ *ImplContext) UpdateFlags(ctx context.Context, r soap.RoundTripper, req *types.UpdateFlags) (*types.UpdateFlagsResponse, error) {
	return methods.UpdateFlags(ctx, r, req)
}

func (_ *ImplContext) UpdateGraphicsConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateGraphicsConfig) (*types.UpdateGraphicsConfigResponse, error) {
	return methods.UpdateGraphicsConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateHostCustomizations_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostCustomizations_Task) (*types.UpdateHostCustomizations_TaskResponse, error) {
	return methods.UpdateHostCustomizations_Task(ctx, r, req)
}

func (_ *ImplContext) UpdateHostImageAcceptanceLevel(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostImageAcceptanceLevel) (*types.UpdateHostImageAcceptanceLevelResponse, error) {
	return methods.UpdateHostImageAcceptanceLevel(ctx, r, req)
}

func (_ *ImplContext) UpdateHostProfile(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostProfile) (*types.UpdateHostProfileResponse, error) {
	return methods.UpdateHostProfile(ctx, r, req)
}

func (_ *ImplContext) UpdateHostSpecification(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostSpecification) (*types.UpdateHostSpecificationResponse, error) {
	return methods.UpdateHostSpecification(ctx, r, req)
}

func (_ *ImplContext) UpdateHostSubSpecification(ctx context.Context, r soap.RoundTripper, req *types.UpdateHostSubSpecification) (*types.UpdateHostSubSpecificationResponse, error) {
	return methods.UpdateHostSubSpecification(ctx, r, req)
}

func (_ *ImplContext) UpdateInternetScsiAdvancedOptions(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiAdvancedOptions) (*types.UpdateInternetScsiAdvancedOptionsResponse, error) {
	return methods.UpdateInternetScsiAdvancedOptions(ctx, r, req)
}

func (_ *ImplContext) UpdateInternetScsiAlias(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiAlias) (*types.UpdateInternetScsiAliasResponse, error) {
	return methods.UpdateInternetScsiAlias(ctx, r, req)
}

func (_ *ImplContext) UpdateInternetScsiAuthenticationProperties(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiAuthenticationProperties) (*types.UpdateInternetScsiAuthenticationPropertiesResponse, error) {
	return methods.UpdateInternetScsiAuthenticationProperties(ctx, r, req)
}

func (_ *ImplContext) UpdateInternetScsiDigestProperties(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiDigestProperties) (*types.UpdateInternetScsiDigestPropertiesResponse, error) {
	return methods.UpdateInternetScsiDigestProperties(ctx, r, req)
}

func (_ *ImplContext) UpdateInternetScsiDiscoveryProperties(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiDiscoveryProperties) (*types.UpdateInternetScsiDiscoveryPropertiesResponse, error) {
	return methods.UpdateInternetScsiDiscoveryProperties(ctx, r, req)
}

func (_ *ImplContext) UpdateInternetScsiIPProperties(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiIPProperties) (*types.UpdateInternetScsiIPPropertiesResponse, error) {
	return methods.UpdateInternetScsiIPProperties(ctx, r, req)
}

func (_ *ImplContext) UpdateInternetScsiName(ctx context.Context, r soap.RoundTripper, req *types.UpdateInternetScsiName) (*types.UpdateInternetScsiNameResponse, error) {
	return methods.UpdateInternetScsiName(ctx, r, req)
}

func (_ *ImplContext) UpdateIpConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpConfig) (*types.UpdateIpConfigResponse, error) {
	return methods.UpdateIpConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateIpPool(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpPool) (*types.UpdateIpPoolResponse, error) {
	return methods.UpdateIpPool(ctx, r, req)
}

func (_ *ImplContext) UpdateIpRouteConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpRouteConfig) (*types.UpdateIpRouteConfigResponse, error) {
	return methods.UpdateIpRouteConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateIpRouteTableConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpRouteTableConfig) (*types.UpdateIpRouteTableConfigResponse, error) {
	return methods.UpdateIpRouteTableConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateIpmi(ctx context.Context, r soap.RoundTripper, req *types.UpdateIpmi) (*types.UpdateIpmiResponse, error) {
	return methods.UpdateIpmi(ctx, r, req)
}

func (_ *ImplContext) UpdateKmipServer(ctx context.Context, r soap.RoundTripper, req *types.UpdateKmipServer) (*types.UpdateKmipServerResponse, error) {
	return methods.UpdateKmipServer(ctx, r, req)
}

func (_ *ImplContext) UpdateKmsSignedCsrClientCert(ctx context.Context, r soap.RoundTripper, req *types.UpdateKmsSignedCsrClientCert) (*types.UpdateKmsSignedCsrClientCertResponse, error) {
	return methods.UpdateKmsSignedCsrClientCert(ctx, r, req)
}

func (_ *ImplContext) UpdateLicense(ctx context.Context, r soap.RoundTripper, req *types.UpdateLicense) (*types.UpdateLicenseResponse, error) {
	return methods.UpdateLicense(ctx, r, req)
}

func (_ *ImplContext) UpdateLicenseLabel(ctx context.Context, r soap.RoundTripper, req *types.UpdateLicenseLabel) (*types.UpdateLicenseLabelResponse, error) {
	return methods.UpdateLicenseLabel(ctx, r, req)
}

func (_ *ImplContext) UpdateLinkedChildren(ctx context.Context, r soap.RoundTripper, req *types.UpdateLinkedChildren) (*types.UpdateLinkedChildrenResponse, error) {
	return methods.UpdateLinkedChildren(ctx, r, req)
}

func (_ *ImplContext) UpdateLocalSwapDatastore(ctx context.Context, r soap.RoundTripper, req *types.UpdateLocalSwapDatastore) (*types.UpdateLocalSwapDatastoreResponse, error) {
	return methods.UpdateLocalSwapDatastore(ctx, r, req)
}

func (_ *ImplContext) UpdateLockdownExceptions(ctx context.Context, r soap.RoundTripper, req *types.UpdateLockdownExceptions) (*types.UpdateLockdownExceptionsResponse, error) {
	return methods.UpdateLockdownExceptions(ctx, r, req)
}

func (_ *ImplContext) UpdateModuleOptionString(ctx context.Context, r soap.RoundTripper, req *types.UpdateModuleOptionString) (*types.UpdateModuleOptionStringResponse, error) {
	return methods.UpdateModuleOptionString(ctx, r, req)
}

func (_ *ImplContext) UpdateNetworkConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateNetworkConfig) (*types.UpdateNetworkConfigResponse, error) {
	return methods.UpdateNetworkConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateNetworkResourcePool(ctx context.Context, r soap.RoundTripper, req *types.UpdateNetworkResourcePool) (*types.UpdateNetworkResourcePoolResponse, error) {
	return methods.UpdateNetworkResourcePool(ctx, r, req)
}

func (_ *ImplContext) UpdateOptions(ctx context.Context, r soap.RoundTripper, req *types.UpdateOptions) (*types.UpdateOptionsResponse, error) {
	return methods.UpdateOptions(ctx, r, req)
}

func (_ *ImplContext) UpdatePassthruConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdatePassthruConfig) (*types.UpdatePassthruConfigResponse, error) {
	return methods.UpdatePassthruConfig(ctx, r, req)
}

func (_ *ImplContext) UpdatePerfInterval(ctx context.Context, r soap.RoundTripper, req *types.UpdatePerfInterval) (*types.UpdatePerfIntervalResponse, error) {
	return methods.UpdatePerfInterval(ctx, r, req)
}

func (_ *ImplContext) UpdatePhysicalNicLinkSpeed(ctx context.Context, r soap.RoundTripper, req *types.UpdatePhysicalNicLinkSpeed) (*types.UpdatePhysicalNicLinkSpeedResponse, error) {
	return methods.UpdatePhysicalNicLinkSpeed(ctx, r, req)
}

func (_ *ImplContext) UpdatePortGroup(ctx context.Context, r soap.RoundTripper, req *types.UpdatePortGroup) (*types.UpdatePortGroupResponse, error) {
	return methods.UpdatePortGroup(ctx, r, req)
}

func (_ *ImplContext) UpdateProgress(ctx context.Context, r soap.RoundTripper, req *types.UpdateProgress) (*types.UpdateProgressResponse, error) {
	return methods.UpdateProgress(ctx, r, req)
}

func (_ *ImplContext) UpdateReferenceHost(ctx context.Context, r soap.RoundTripper, req *types.UpdateReferenceHost) (*types.UpdateReferenceHostResponse, error) {
	return methods.UpdateReferenceHost(ctx, r, req)
}

func (_ *ImplContext) UpdateRuleset(ctx context.Context, r soap.RoundTripper, req *types.UpdateRuleset) (*types.UpdateRulesetResponse, error) {
	return methods.UpdateRuleset(ctx, r, req)
}

func (_ *ImplContext) UpdateScsiLunDisplayName(ctx context.Context, r soap.RoundTripper, req *types.UpdateScsiLunDisplayName) (*types.UpdateScsiLunDisplayNameResponse, error) {
	return methods.UpdateScsiLunDisplayName(ctx, r, req)
}

func (_ *ImplContext) UpdateSelfSignedClientCert(ctx context.Context, r soap.RoundTripper, req *types.UpdateSelfSignedClientCert) (*types.UpdateSelfSignedClientCertResponse, error) {
	return methods.UpdateSelfSignedClientCert(ctx, r, req)
}

func (_ *ImplContext) UpdateServiceConsoleVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.UpdateServiceConsoleVirtualNic) (*types.UpdateServiceConsoleVirtualNicResponse, error) {
	return methods.UpdateServiceConsoleVirtualNic(ctx, r, req)
}

func (_ *ImplContext) UpdateServiceMessage(ctx context.Context, r soap.RoundTripper, req *types.UpdateServiceMessage) (*types.UpdateServiceMessageResponse, error) {
	return methods.UpdateServiceMessage(ctx, r, req)
}

func (_ *ImplContext) UpdateServicePolicy(ctx context.Context, r soap.RoundTripper, req *types.UpdateServicePolicy) (*types.UpdateServicePolicyResponse, error) {
	return methods.UpdateServicePolicy(ctx, r, req)
}

func (_ *ImplContext) UpdateSoftwareInternetScsiEnabled(ctx context.Context, r soap.RoundTripper, req *types.UpdateSoftwareInternetScsiEnabled) (*types.UpdateSoftwareInternetScsiEnabledResponse, error) {
	return methods.UpdateSoftwareInternetScsiEnabled(ctx, r, req)
}

func (_ *ImplContext) UpdateSystemResources(ctx context.Context, r soap.RoundTripper, req *types.UpdateSystemResources) (*types.UpdateSystemResourcesResponse, error) {
	return methods.UpdateSystemResources(ctx, r, req)
}

func (_ *ImplContext) UpdateSystemSwapConfiguration(ctx context.Context, r soap.RoundTripper, req *types.UpdateSystemSwapConfiguration) (*types.UpdateSystemSwapConfigurationResponse, error) {
	return methods.UpdateSystemSwapConfiguration(ctx, r, req)
}

func (_ *ImplContext) UpdateSystemUsers(ctx context.Context, r soap.RoundTripper, req *types.UpdateSystemUsers) (*types.UpdateSystemUsersResponse, error) {
	return methods.UpdateSystemUsers(ctx, r, req)
}

func (_ *ImplContext) UpdateUser(ctx context.Context, r soap.RoundTripper, req *types.UpdateUser) (*types.UpdateUserResponse, error) {
	return methods.UpdateUser(ctx, r, req)
}

func (_ *ImplContext) UpdateVAppConfig(ctx context.Context, r soap.RoundTripper, req *types.UpdateVAppConfig) (*types.UpdateVAppConfigResponse, error) {
	return methods.UpdateVAppConfig(ctx, r, req)
}

func (_ *ImplContext) UpdateVVolVirtualMachineFiles_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateVVolVirtualMachineFiles_Task) (*types.UpdateVVolVirtualMachineFiles_TaskResponse, error) {
	return methods.UpdateVVolVirtualMachineFiles_Task(ctx, r, req)
}

func (_ *ImplContext) UpdateVirtualMachineFiles_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateVirtualMachineFiles_Task) (*types.UpdateVirtualMachineFiles_TaskResponse, error) {
	return methods.UpdateVirtualMachineFiles_Task(ctx, r, req)
}

func (_ *ImplContext) UpdateVirtualNic(ctx context.Context, r soap.RoundTripper, req *types.UpdateVirtualNic) (*types.UpdateVirtualNicResponse, error) {
	return methods.UpdateVirtualNic(ctx, r, req)
}

func (_ *ImplContext) UpdateVirtualSwitch(ctx context.Context, r soap.RoundTripper, req *types.UpdateVirtualSwitch) (*types.UpdateVirtualSwitchResponse, error) {
	return methods.UpdateVirtualSwitch(ctx, r, req)
}

func (_ *ImplContext) UpdateVmfsUnmapPriority(ctx context.Context, r soap.RoundTripper, req *types.UpdateVmfsUnmapPriority) (*types.UpdateVmfsUnmapPriorityResponse, error) {
	return methods.UpdateVmfsUnmapPriority(ctx, r, req)
}

func (_ *ImplContext) UpdateVsan_Task(ctx context.Context, r soap.RoundTripper, req *types.UpdateVsan_Task) (*types.UpdateVsan_TaskResponse, error) {
	return methods.UpdateVsan_Task(ctx, r, req)
}

func (_ *ImplContext) UpgradeIoFilter_Task(ctx context.Context, r soap.RoundTripper, req *types.UpgradeIoFilter_Task) (*types.UpgradeIoFilter_TaskResponse, error) {
	return methods.UpgradeIoFilter_Task(ctx, r, req)
}

func (_ *ImplContext) UpgradeTools_Task(ctx context.Context, r soap.RoundTripper, req *types.UpgradeTools_Task) (*types.UpgradeTools_TaskResponse, error) {
	return methods.UpgradeTools_Task(ctx, r, req)
}

func (_ *ImplContext) UpgradeVM_Task(ctx context.Context, r soap.RoundTripper, req *types.UpgradeVM_Task) (*types.UpgradeVM_TaskResponse, error) {
	return methods.UpgradeVM_Task(ctx, r, req)
}

func (_ *ImplContext) UpgradeVmLayout(ctx context.Context, r soap.RoundTripper, req *types.UpgradeVmLayout) (*types.UpgradeVmLayoutResponse, error) {
	return methods.UpgradeVmLayout(ctx, r, req)
}

func (_ *ImplContext) UpgradeVmfs(ctx context.Context, r soap.RoundTripper, req *types.UpgradeVmfs) (*types.UpgradeVmfsResponse, error) {
	return methods.UpgradeVmfs(ctx, r, req)
}

func (_ *ImplContext) UpgradeVsanObjects(ctx context.Context, r soap.RoundTripper, req *types.UpgradeVsanObjects) (*types.UpgradeVsanObjectsResponse, error) {
	return methods.UpgradeVsanObjects(ctx, r, req)
}

func (_ *ImplContext) UploadClientCert(ctx context.Context, r soap.RoundTripper, req *types.UploadClientCert) (*types.UploadClientCertResponse, error) {
	return methods.UploadClientCert(ctx, r, req)
}

func (_ *ImplContext) UploadKmipServerCert(ctx context.Context, r soap.RoundTripper, req *types.UploadKmipServerCert) (*types.UploadKmipServerCertResponse, error) {
	return methods.UploadKmipServerCert(ctx, r, req)
}

func (_ *ImplContext) ValidateCredentialsInGuest(ctx context.Context, r soap.RoundTripper, req *types.ValidateCredentialsInGuest) (*types.ValidateCredentialsInGuestResponse, error) {
	return methods.ValidateCredentialsInGuest(ctx, r, req)
}

func (_ *ImplContext) ValidateHost(ctx context.Context, r soap.RoundTripper, req *types.ValidateHost) (*types.ValidateHostResponse, error) {
	return methods.ValidateHost(ctx, r, req)
}

func (_ *ImplContext) ValidateMigration(ctx context.Context, r soap.RoundTripper, req *types.ValidateMigration) (*types.ValidateMigrationResponse, error) {
	return methods.ValidateMigration(ctx, r, req)
}

func (_ *ImplContext) WaitForUpdates(ctx context.Context, r soap.RoundTripper, req *types.WaitForUpdates) (*types.WaitForUpdatesResponse, error) {
	return methods.WaitForUpdates(ctx, r, req)
}

func (_ *ImplContext) WaitForUpdatesEx(ctx context.Context, r soap.RoundTripper, req *types.WaitForUpdatesEx) (*types.WaitForUpdatesExResponse, error) {
	return methods.WaitForUpdatesEx(ctx, r, req)
}

func (_ *ImplContext) XmlToCustomizationSpecItem(ctx context.Context, r soap.RoundTripper, req *types.XmlToCustomizationSpecItem) (*types.XmlToCustomizationSpecItemResponse, error) {
	return methods.XmlToCustomizationSpecItem(ctx, r, req)
}

func (_ *ImplContext) ZeroFillVirtualDisk_Task(ctx context.Context, r soap.RoundTripper, req *types.ZeroFillVirtualDisk_Task) (*types.ZeroFillVirtualDisk_TaskResponse, error) {
	return methods.ZeroFillVirtualDisk_Task(ctx, r, req)
}

func (_ *ImplContext) GetServiceContent(ctx context.Context, r soap.RoundTripper) (types.ServiceContent, error) {
	return methods.GetServiceContent(ctx, r)
}

func (_ *ImplContext) GetCurrentTime(ctx context.Context, r soap.RoundTripper) (*time.Time, error) {
	return methods.GetCurrentTime(ctx, r)
}
