
#include <Windows.h>
#include <iostream>
#include <winternl.h>

#pragma comment( lib, "ntdll.lib" )

#define STATUS_SUCCESS 0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

static constexpr auto SystemHandleInformation = ( SYSTEM_INFORMATION_CLASS ) 0x10;

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

int main( )
{
	const DWORD my_pid{ GetCurrentProcessId( ) };

	// TODO: enumerate through processlist, attach to it, and run the procedure below for each one

	NTSTATUS returnVal;
	ULONG dataLength = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;

	// Query the system handles. If the call fails because of a length mismatch, recreate a bigger buffer and try again.
	do
	{
		handleInfo = ( PSYSTEM_HANDLE_INFORMATION ) VirtualAlloc( NULL, dataLength, MEM_COMMIT, PAGE_READWRITE );
		returnVal = NtQuerySystemInformation( SystemHandleInformation, handleInfo, dataLength, &dataLength );
		if ( returnVal == STATUS_INFO_LENGTH_MISMATCH )
		{
			// The length of the buffer was not sufficient. Expand the buffer before retrying.
			VirtualFree( handleInfo, 0, MEM_RELEASE );
			dataLength *= 2;
		}
	} while ( returnVal == STATUS_INFO_LENGTH_MISMATCH );

	if ( returnVal == STATUS_SUCCESS )
	{
		// The system query succeeded, let's allocate buffers to hold the necessary information.
		POBJECT_TYPE_INFORMATION objInfo = ( POBJECT_TYPE_INFORMATION ) VirtualAlloc( NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE );

		for ( DWORD i = 0; i < handleInfo->HandleCount; ++i )
		{
			const auto curHandle = &handleInfo->Handles[ i ];
			
			// Skip the occurrences in the process does not own the handle.
			if ( curHandle->ProcessId != current_pid )
				continue;

			// TODO: query the handle information and check if it's opened to us
		}

		// Free allocated query objects.
		VirtualFree( objInfo, 0, MEM_RELEASE );
	}

	// Free heap allocated handle information.
	VirtualFree( handleInfo, 0, MEM_RELEASE );
}