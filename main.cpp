
#include <Windows.h>
#include <iostream>
#include <Psapi.h>

#include "native.h"

int main( )
{
	const DWORD my_pid{ GetCurrentProcessId( ) };

	NTSTATUS status{ };
	ULONG size{ 0x10000 };
	PSYSTEM_HANDLE_INFORMATION handle_info{ };

	while ( true )
	{
		do
		{
			handle_info = ( PSYSTEM_HANDLE_INFORMATION ) VirtualAlloc( NULL, size, MEM_COMMIT, PAGE_READWRITE );
			status = NtQuerySystemInformation( SystemHandleInformation, handle_info, size, &size );
			if ( status == STATUS_INFO_LENGTH_MISMATCH )
			{
				VirtualFree( handle_info, 0, MEM_RELEASE );
				size *= 2;
			}
		} while ( status == STATUS_INFO_LENGTH_MISMATCH );

		if ( status == STATUS_SUCCESS )
		{
			POBJECT_TYPE_INFORMATION object_info = ( POBJECT_TYPE_INFORMATION ) VirtualAlloc( NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE );

			for ( DWORD i = 0; i < handle_info->HandleCount; ++i )
			{
				const auto current_handle = &handle_info->Handles[ i ];

				/* we aren't interested in handles we own */
				if ( current_handle->ProcessId == my_pid )
					continue;

				/* we need a handle to the process with PROCESS_DUP_HANDLE access rights */
				const HANDLE process_handle{ OpenProcess( PROCESS_DUP_HANDLE, false, current_handle->ProcessId ) };
				if ( !process_handle )
					continue;

				HANDLE duplicate_handle{ };
				DuplicateHandle( process_handle, ( HANDLE )current_handle->Handle, GetCurrentProcess( ), &duplicate_handle, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0 );
				if ( !duplicate_handle )
					continue;

				/* query the object information of the handle */
				if ( NtQueryObject( duplicate_handle, ObjectTypeInformation, object_info, 0x1000, NULL ) == STATUS_SUCCESS )
				{
					/* if the object type is a process, print out its path */
					if ( wcsncmp( object_info->TypeName.Buffer, L"Process", object_info->TypeName.Length + 1 ) == 0 )
					{
						char path[ MAX_PATH ];
						if ( GetProcessImageFileNameA( duplicate_handle, path, MAX_PATH ) )
							std::cout << path << std::endl;
					}
				}
			}

			VirtualFree( object_info, 0, MEM_RELEASE );
		}

		VirtualFree( handle_info, 0, MEM_RELEASE );

		Sleep( 10000 );
	}

}