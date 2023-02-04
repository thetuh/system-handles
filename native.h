#pragma once

#include <winternl.h>

#pragma comment( lib, "ntdll.lib" )

#define STATUS_SUCCESS 0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

static constexpr auto SystemProcessorInformation = ( SYSTEM_INFORMATION_CLASS ) 0x01;
static constexpr auto SystemPathInformation = ( SYSTEM_INFORMATION_CLASS ) 0x04;
static constexpr auto SystemCallCountInformation = ( SYSTEM_INFORMATION_CLASS ) 0x06;
static constexpr auto SystemDeviceInformation = ( SYSTEM_INFORMATION_CLASS ) 0x07;
static constexpr auto SystemFlagsInformation = ( SYSTEM_INFORMATION_CLASS ) 0x09;
static constexpr auto SystemCallTimeInformation = ( SYSTEM_INFORMATION_CLASS ) 0x0A;
static constexpr auto SystemModuleInformation = ( SYSTEM_INFORMATION_CLASS ) 0x0B;
static constexpr auto SystemLocksInformation = ( SYSTEM_INFORMATION_CLASS ) 0x0C;
static constexpr auto SystemStackTraceInformation = ( SYSTEM_INFORMATION_CLASS ) 0x0D;
static constexpr auto SystemPagedPoolInformation = ( SYSTEM_INFORMATION_CLASS ) 0x0E;
static constexpr auto SystemNonPagedPoolInformation = ( SYSTEM_INFORMATION_CLASS ) 0x0F;
static constexpr auto SystemHandleInformation = ( SYSTEM_INFORMATION_CLASS ) 0x10;
static constexpr auto SystemObjectInformation = ( SYSTEM_INFORMATION_CLASS ) 0x11;
static constexpr auto SystemPageFileInformation = ( SYSTEM_INFORMATION_CLASS ) 0x12;
static constexpr auto SystemVdmInstemulInformation = ( SYSTEM_INFORMATION_CLASS ) 0x13;
static constexpr auto SystemVdmBopInformation = ( SYSTEM_INFORMATION_CLASS ) 0x14;
static constexpr auto SystemFileCacheInformation = ( SYSTEM_INFORMATION_CLASS ) 0x15;
static constexpr auto SystemPoolTagInformation = ( SYSTEM_INFORMATION_CLASS ) 0x16;
static constexpr auto SystemDpcBehaviorInformation = ( SYSTEM_INFORMATION_CLASS ) 0x18;
static constexpr auto SystemFullMemoryInformation = ( SYSTEM_INFORMATION_CLASS ) 0x19;
static constexpr auto SystemLoadGdiDriverInformation = ( SYSTEM_INFORMATION_CLASS ) 0x1A;
static constexpr auto SystemUnloadGdiDriverInformation = ( SYSTEM_INFORMATION_CLASS ) 0x1B;
static constexpr auto SystemTimeAdjustmentInformation = ( SYSTEM_INFORMATION_CLASS ) 0x1C;
static constexpr auto SystemSummaryMemoryInformation = ( SYSTEM_INFORMATION_CLASS ) 0x1D;
static constexpr auto SystemNextEventIdInformation = ( SYSTEM_INFORMATION_CLASS ) 0x1E;
static constexpr auto SystemMirrorMemoryInformation = ( SYSTEM_INFORMATION_CLASS ) 0x1E;
static constexpr auto SystemEventIdsInformation = ( SYSTEM_INFORMATION_CLASS ) 0x1F;
static constexpr auto SystemPerformanceTraceInformation = ( SYSTEM_INFORMATION_CLASS ) 0x1F;
static constexpr auto SystemCrashDumpInformation = ( SYSTEM_INFORMATION_CLASS ) 0x20;
static constexpr auto SystemCrashDumpStateInformation = ( SYSTEM_INFORMATION_CLASS ) 0x22;
static constexpr auto SystemKernelDebuggerInformation = ( SYSTEM_INFORMATION_CLASS ) 0x23;
static constexpr auto SystemContextSwitchInformation = ( SYSTEM_INFORMATION_CLASS ) 0x24;
static constexpr auto SystemExtendServiceTableInformation = ( SYSTEM_INFORMATION_CLASS ) 0x26;
static constexpr auto SystemPrioritySeperation = ( SYSTEM_INFORMATION_CLASS ) 0x27;
static constexpr auto SystemPlugPlayBusInformation = ( SYSTEM_INFORMATION_CLASS ) 0x28;
static constexpr auto SystemVerifierAddDriverInformation = ( SYSTEM_INFORMATION_CLASS ) 0x28;
static constexpr auto SystemDockInformation = ( SYSTEM_INFORMATION_CLASS ) 0x29;
static constexpr auto SystemVerifierRemoveDriverInformation = ( SYSTEM_INFORMATION_CLASS ) 0x29;
static constexpr auto SystemProcessorIdleInformation = ( SYSTEM_INFORMATION_CLASS ) 0x2A;
static constexpr auto SystemProcessorSpeedInformation = ( SYSTEM_INFORMATION_CLASS ) 0x2B;
static constexpr auto SystemLegacyDriverInformation = ( SYSTEM_INFORMATION_CLASS ) 0x2B;
static constexpr auto SystemCurrentTimeZoneInformation = ( SYSTEM_INFORMATION_CLASS ) 0x2C;
static constexpr auto SystemTimeSlipNotification = ( SYSTEM_INFORMATION_CLASS ) 0x2E;
static constexpr auto SystemSessionCreate = ( SYSTEM_INFORMATION_CLASS ) 0x2F;
static constexpr auto SystemSessionDetach = ( SYSTEM_INFORMATION_CLASS ) 0x30;
static constexpr auto SystemSessionInformation = ( SYSTEM_INFORMATION_CLASS ) 0x31;
static constexpr auto SystemRangeStartInformation = ( SYSTEM_INFORMATION_CLASS ) 0x32;
static constexpr auto SystemVerifierInformation = ( SYSTEM_INFORMATION_CLASS ) 0x33;
static constexpr auto SystemVerifierThunkExtend = ( SYSTEM_INFORMATION_CLASS ) 0x34;
static constexpr auto SystemSessionProcessInformation = ( SYSTEM_INFORMATION_CLASS ) 0x35;
//static constexpr auto SystemObjectSecurityMode = (SYSTEM_INFORMATION_CLASS)0x36;
static constexpr auto SystemLoadGdiDriverInSystemSpace = ( SYSTEM_INFORMATION_CLASS ) 0x36;
static constexpr auto SystemNumaProcessorMap = ( SYSTEM_INFORMATION_CLASS ) 0x37;
static constexpr auto SystemPrefetcherInformation = ( SYSTEM_INFORMATION_CLASS ) 0x38;
static constexpr auto SystemExtendedProcessInformation = ( SYSTEM_INFORMATION_CLASS ) 0x39;
static constexpr auto SystemRecommendedSharedDataAlignment = ( SYSTEM_INFORMATION_CLASS ) 0x3A;
static constexpr auto SystemComPlusPackage = ( SYSTEM_INFORMATION_CLASS ) 0x3B;
static constexpr auto SystemNumaAvailableMemory = ( SYSTEM_INFORMATION_CLASS ) 0x3C;
static constexpr auto SystemProcessorPowerInformation = ( SYSTEM_INFORMATION_CLASS ) 0x3D;
static constexpr auto SystemEmulationBasicInformation = ( SYSTEM_INFORMATION_CLASS ) 0x3E;
static constexpr auto SystemEmulationProcessorInformation = ( SYSTEM_INFORMATION_CLASS ) 0x3F;
static constexpr auto SystemExtendedHandleInformation = ( SYSTEM_INFORMATION_CLASS ) 0x40;
static constexpr auto SystemLostDelayedWriteInformation = ( SYSTEM_INFORMATION_CLASS ) 0x41;
static constexpr auto SystemBigPoolInformation = ( SYSTEM_INFORMATION_CLASS ) 0x42;
static constexpr auto SystemSessionPoolTagInformation = ( SYSTEM_INFORMATION_CLASS ) 0x43;
static constexpr auto SystemSessionMappedViewInformation = ( SYSTEM_INFORMATION_CLASS ) 0x44;
static constexpr auto SystemHotpatchInformation = ( SYSTEM_INFORMATION_CLASS ) 0x45;
static constexpr auto SystemObjectSecurityMode = ( SYSTEM_INFORMATION_CLASS ) 0x46;
static constexpr auto SystemWatchdogTimerHandler = ( SYSTEM_INFORMATION_CLASS ) 0x47;
static constexpr auto SystemWatchdogTimerInformation = ( SYSTEM_INFORMATION_CLASS ) 0x48;
static constexpr auto SystemLogicalProcessorInformation = ( SYSTEM_INFORMATION_CLASS ) 0x49;
static constexpr auto SystemWow = ( SYSTEM_INFORMATION_CLASS ) 0x4A;
static constexpr auto SystemRegisterFirmwareTableInformationHandler = ( SYSTEM_INFORMATION_CLASS ) 0x4B;
static constexpr auto SystemFirmwareTableInformation = ( SYSTEM_INFORMATION_CLASS ) 0x4C;
static constexpr auto SystemModuleInformationEx = ( SYSTEM_INFORMATION_CLASS ) 0x4D;
static constexpr auto SystemVerifierTriageInformation = ( SYSTEM_INFORMATION_CLASS ) 0x4E;
static constexpr auto SystemSuperfetchInformation = ( SYSTEM_INFORMATION_CLASS ) 0x4F;
static constexpr auto SystemMemoryListInformation = ( SYSTEM_INFORMATION_CLASS ) 0x50;
static constexpr auto SystemFileCacheInformationEx = ( SYSTEM_INFORMATION_CLASS ) 0x51;
static constexpr auto SystemThreadPriorityClientIdInformation = ( SYSTEM_INFORMATION_CLASS ) 0x52;
static constexpr auto SystemProcessorIdleCycleTimeInformation = ( SYSTEM_INFORMATION_CLASS ) 0x53;
static constexpr auto SystemVerifierCancellationInformation = ( SYSTEM_INFORMATION_CLASS ) 0x54;
static constexpr auto SystemProcessorPowerInformationEx = ( SYSTEM_INFORMATION_CLASS ) 0x55;
static constexpr auto SystemRefTraceInformation = ( SYSTEM_INFORMATION_CLASS ) 0x56;
static constexpr auto SystemSpecialPoolInformation = ( SYSTEM_INFORMATION_CLASS ) 0x57;
static constexpr auto SystemProcessIdInformation = ( SYSTEM_INFORMATION_CLASS ) 0x58;
static constexpr auto SystemErrorPortInformation = ( SYSTEM_INFORMATION_CLASS ) 0x59;
static constexpr auto SystemBootEnvironmentInformation = ( SYSTEM_INFORMATION_CLASS ) 0x5A;
static constexpr auto SystemHypervisorInformation = ( SYSTEM_INFORMATION_CLASS ) 0x5B;
static constexpr auto SystemVerifierInformationEx = ( SYSTEM_INFORMATION_CLASS ) 0x5C;
static constexpr auto SystemTimeZoneInformation = ( SYSTEM_INFORMATION_CLASS ) 0x5D;
static constexpr auto SystemImageFileExecutionOptionsInformation = ( SYSTEM_INFORMATION_CLASS ) 0x5E;
static constexpr auto SystemCoverageInformation = ( SYSTEM_INFORMATION_CLASS ) 0x5F;
static constexpr auto SystemPrefetchPatchInformation = ( SYSTEM_INFORMATION_CLASS ) 0x60;
static constexpr auto SystemVerifierFaultsInformation = ( SYSTEM_INFORMATION_CLASS ) 0x61;
static constexpr auto SystemSystemPartitionInformation = ( SYSTEM_INFORMATION_CLASS ) 0x62;
static constexpr auto SystemSystemDiskInformation = ( SYSTEM_INFORMATION_CLASS ) 0x63;
static constexpr auto SystemProcessorPerformanceDistribution = ( SYSTEM_INFORMATION_CLASS ) 0x64;
static constexpr auto SystemNumaProximityNodeInformation = ( SYSTEM_INFORMATION_CLASS ) 0x65;
static constexpr auto SystemDynamicTimeZoneInformation = ( SYSTEM_INFORMATION_CLASS ) 0x66;
static constexpr auto SystemProcessorMicrocodeUpdateInformation = ( SYSTEM_INFORMATION_CLASS ) 0x68;
static constexpr auto SystemProcessorBrandString = ( SYSTEM_INFORMATION_CLASS ) 0x69;
static constexpr auto SystemVirtualAddressInformation = ( SYSTEM_INFORMATION_CLASS ) 0x6A;
static constexpr auto SystemLogicalProcessorAndGroupInformation = ( SYSTEM_INFORMATION_CLASS ) 0x6B;
static constexpr auto SystemProcessorCycleTimeInformation = ( SYSTEM_INFORMATION_CLASS ) 0x6C;
static constexpr auto SystemStoreInformation = ( SYSTEM_INFORMATION_CLASS ) 0x6D;
static constexpr auto SystemRegistryAppendString = ( SYSTEM_INFORMATION_CLASS ) 0x6E;
static constexpr auto SystemAitSamplingValue = ( SYSTEM_INFORMATION_CLASS ) 0x6F;
static constexpr auto SystemVhdBootInformation = ( SYSTEM_INFORMATION_CLASS ) 0x70;
static constexpr auto SystemCpuQuotaInformation = ( SYSTEM_INFORMATION_CLASS ) 0x71;
static constexpr auto SystemNativeBasicInformation = ( SYSTEM_INFORMATION_CLASS ) 0x72;
static constexpr auto SystemErrorPortTimeouts = ( SYSTEM_INFORMATION_CLASS ) 0x73;
static constexpr auto SystemLowPriorityIoInformation = ( SYSTEM_INFORMATION_CLASS ) 0x74;
static constexpr auto SystemBootEntropyInformation = ( SYSTEM_INFORMATION_CLASS ) 0x75;
static constexpr auto SystemVerifierCountersInformation = ( SYSTEM_INFORMATION_CLASS ) 0x76;
static constexpr auto SystemPagedPoolInformationEx = ( SYSTEM_INFORMATION_CLASS ) 0x77;
static constexpr auto SystemSystemPtesInformationEx = ( SYSTEM_INFORMATION_CLASS ) 0x78;
static constexpr auto SystemNodeDistanceInformation = ( SYSTEM_INFORMATION_CLASS ) 0x79;
static constexpr auto SystemAcpiAuditInformation = ( SYSTEM_INFORMATION_CLASS ) 0x7A;
static constexpr auto SystemBasicPerformanceInformation = ( SYSTEM_INFORMATION_CLASS ) 0x7B;
static constexpr auto SystemQueryPerformanceCounterInformation = ( SYSTEM_INFORMATION_CLASS ) 0x7C;
static constexpr auto SystemSessionBigPoolInformation = ( SYSTEM_INFORMATION_CLASS ) 0x7D;
static constexpr auto SystemBootGraphicsInformation = ( SYSTEM_INFORMATION_CLASS ) 0x7E;
static constexpr auto SystemScrubPhysicalMemoryInformation = ( SYSTEM_INFORMATION_CLASS ) 0x7F;
static constexpr auto SystemBadPageInformation = ( SYSTEM_INFORMATION_CLASS ) 0x80;
static constexpr auto SystemProcessorProfileControlArea = ( SYSTEM_INFORMATION_CLASS ) 0x81;
static constexpr auto SystemCombinePhysicalMemoryInformation = ( SYSTEM_INFORMATION_CLASS ) 0x82;
static constexpr auto SystemEntropyInterruptTimingInformation = ( SYSTEM_INFORMATION_CLASS ) 0x83;
static constexpr auto SystemConsoleInformation = ( SYSTEM_INFORMATION_CLASS ) 0x84;
static constexpr auto SystemPlatformBinaryInformation = ( SYSTEM_INFORMATION_CLASS ) 0x85;
static constexpr auto SystemThrottleNotificationInformation = ( SYSTEM_INFORMATION_CLASS ) 0x86;
static constexpr auto SystemHypervisorProcessorCountInformation = ( SYSTEM_INFORMATION_CLASS ) 0x87;
static constexpr auto SystemDeviceDataInformation = ( SYSTEM_INFORMATION_CLASS ) 0x88;
static constexpr auto SystemDeviceDataEnumerationInformation = ( SYSTEM_INFORMATION_CLASS ) 0x89;
static constexpr auto SystemMemoryTopologyInformation = ( SYSTEM_INFORMATION_CLASS ) 0x8A;
static constexpr auto SystemMemoryChannelInformation = ( SYSTEM_INFORMATION_CLASS ) 0x8B;
static constexpr auto SystemBootLogoInformation = ( SYSTEM_INFORMATION_CLASS ) 0x8C;
static constexpr auto SystemProcessorPerformanceInformationEx = ( SYSTEM_INFORMATION_CLASS ) 0x8D;
static constexpr auto SystemCriticalProcessErrorLogInformation = ( SYSTEM_INFORMATION_CLASS ) 0x8E;
static constexpr auto SystemSecureBootPolicyInformation = ( SYSTEM_INFORMATION_CLASS ) 0x8F;
static constexpr auto SystemPageFileInformationEx = ( SYSTEM_INFORMATION_CLASS ) 0x90;
static constexpr auto SystemSecureBootInformation = ( SYSTEM_INFORMATION_CLASS ) 0x91;
static constexpr auto SystemEntropyInterruptTimingRawInformation = ( SYSTEM_INFORMATION_CLASS ) 0x92;
static constexpr auto SystemPortableWorkspaceEfiLauncherInformation = ( SYSTEM_INFORMATION_CLASS ) 0x93;
static constexpr auto SystemFullProcessInformation = ( SYSTEM_INFORMATION_CLASS ) 0x94;
static constexpr auto SystemKernelDebuggerInformationEx = ( SYSTEM_INFORMATION_CLASS ) 0x95;
static constexpr auto SystemBootMetadataInformation = ( SYSTEM_INFORMATION_CLASS ) 0x96;
static constexpr auto SystemSoftRebootInformation = ( SYSTEM_INFORMATION_CLASS ) 0x97;
static constexpr auto SystemElamCertificateInformation = ( SYSTEM_INFORMATION_CLASS ) 0x98;
static constexpr auto SystemOfflineDumpConfigInformation = ( SYSTEM_INFORMATION_CLASS ) 0x99;
static constexpr auto SystemProcessorFeaturesInformation = ( SYSTEM_INFORMATION_CLASS ) 0x9A;
static constexpr auto SystemRegistryReconciliationInformation = ( SYSTEM_INFORMATION_CLASS ) 0x9B;
static constexpr auto SystemEdidInformation = ( SYSTEM_INFORMATION_CLASS ) 0x9C;
static constexpr auto SystemManufacturingInformation = ( SYSTEM_INFORMATION_CLASS ) 0x9D;
static constexpr auto SystemEnergyEstimationConfigInformation = ( SYSTEM_INFORMATION_CLASS ) 0x9E;
static constexpr auto SystemHypervisorDetailInformation = ( SYSTEM_INFORMATION_CLASS ) 0x9F;
static constexpr auto SystemProcessorCycleStatsInformation = ( SYSTEM_INFORMATION_CLASS ) 0xA0;
static constexpr auto SystemVmGenerationCountInformation = ( SYSTEM_INFORMATION_CLASS ) 0xA1;
static constexpr auto SystemTrustedPlatformModuleInformation = ( SYSTEM_INFORMATION_CLASS ) 0xA2;
static constexpr auto SystemKernelDebuggerFlags = ( SYSTEM_INFORMATION_CLASS ) 0xA3;
static constexpr auto SystemCodeIntegrityPolicyInformation = ( SYSTEM_INFORMATION_CLASS ) 0xA4;
static constexpr auto SystemIsolatedUserModeInformation = ( SYSTEM_INFORMATION_CLASS ) 0xA5;
static constexpr auto SystemHardwareSecurityTestInterfaceResultsInformation = ( SYSTEM_INFORMATION_CLASS ) 0xA6;
static constexpr auto SystemSingleModuleInformation = ( SYSTEM_INFORMATION_CLASS ) 0xA7;
static constexpr auto SystemAllowedCpuSetsInformation = ( SYSTEM_INFORMATION_CLASS ) 0xA8;
static constexpr auto SystemDmaProtectionInformation = ( SYSTEM_INFORMATION_CLASS ) 0xA9;
static constexpr auto SystemInterruptCpuSetsInformation = ( SYSTEM_INFORMATION_CLASS ) 0xAA;
static constexpr auto SystemSecureBootPolicyFullInformation = ( SYSTEM_INFORMATION_CLASS ) 0xAB;
static constexpr auto SystemCodeIntegrityPolicyFullInformation = ( SYSTEM_INFORMATION_CLASS ) 0xAC;
static constexpr auto SystemAffinitizedInterruptProcessorInformation = ( SYSTEM_INFORMATION_CLASS ) 0xAD;
static constexpr auto SystemRootSiloInformation = ( SYSTEM_INFORMATION_CLASS ) 0xAE;
static constexpr auto SystemCpuSetInformation = ( SYSTEM_INFORMATION_CLASS ) 0xAF;
static constexpr auto SystemCpuSetTagInformation = ( SYSTEM_INFORMATION_CLASS ) 0xB0;
static constexpr auto SystemWin = ( SYSTEM_INFORMATION_CLASS ) 0xB1;
static constexpr auto SystemSecureKernelProfileInformation = ( SYSTEM_INFORMATION_CLASS ) 0xB2;
static constexpr auto SystemCodeIntegrityPlatformManifestInformation = ( SYSTEM_INFORMATION_CLASS ) 0xB3;
static constexpr auto SystemInterruptSteeringInformation = ( SYSTEM_INFORMATION_CLASS ) 0xB4;
static constexpr auto SystemSuppportedProcessorArchitectures = ( SYSTEM_INFORMATION_CLASS ) 0xB5;
static constexpr auto SystemMemoryUsageInformation = ( SYSTEM_INFORMATION_CLASS ) 0xB6;
static constexpr auto SystemCodeIntegrityCertificateInformation = ( SYSTEM_INFORMATION_CLASS ) 0xB7;
static constexpr auto SystemPhysicalMemoryInformation = ( SYSTEM_INFORMATION_CLASS ) 0xB8;
static constexpr auto SystemControlFlowTransition = ( SYSTEM_INFORMATION_CLASS ) 0xB9;
static constexpr auto SystemKernelDebuggingAllowed = ( SYSTEM_INFORMATION_CLASS ) 0xBA;
static constexpr auto SystemActivityModerationExeState = ( SYSTEM_INFORMATION_CLASS ) 0xBB;
static constexpr auto SystemActivityModerationUserSettings = ( SYSTEM_INFORMATION_CLASS ) 0xBC;
static constexpr auto SystemCodeIntegrityPoliciesFullInformation = ( SYSTEM_INFORMATION_CLASS ) 0xBD;
static constexpr auto SystemCodeIntegrityUnlockInformation = ( SYSTEM_INFORMATION_CLASS ) 0xBE;
static constexpr auto SystemIntegrityQuotaInformation = ( SYSTEM_INFORMATION_CLASS ) 0xBF;
static constexpr auto SystemFlushInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC0;
static constexpr auto SystemProcessorIdleMaskInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC1;
static constexpr auto SystemSecureDumpEncryptionInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC2;
static constexpr auto SystemWriteConstraintInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC3;
static constexpr auto SystemKernelVaShadowInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC4;
static constexpr auto SystemHypervisorSharedPageInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC5;
static constexpr auto SystemFirmwareBootPerformanceInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC6;
static constexpr auto SystemCodeIntegrityVerificationInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC7;
static constexpr auto SystemFirmwarePartitionInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC8;
static constexpr auto SystemSpeculationControlInformation = ( SYSTEM_INFORMATION_CLASS ) 0xC9;
static constexpr auto SystemDmaGuardPolicyInformation = ( SYSTEM_INFORMATION_CLASS ) 0xCA;
static constexpr auto SystemEnclaveLaunchControlInformation = ( SYSTEM_INFORMATION_CLASS ) 0xCB;

using NtQuerySystemInformation_t = NTSTATUS( __stdcall* )(
    SYSTEM_INFORMATION_CLASS    SystemInformationClass,
    PVOID                       SystemInformation,
    ULONG                       SystemInformationLength,
    PULONG                      ReturnLength
    );

typedef NTSTATUS( NTAPI* RtlAdjustPrivilege_fn )( ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled );

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION
{
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[ 3 ];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;