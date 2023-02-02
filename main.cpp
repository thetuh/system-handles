
#include <Windows.h>
#include <iostream>
#include <Psapi.h>

#include "native.h"

int main( )
{
	const HANDLE my_process{ GetCurrentProcess( ) };
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
				/* buffer wasn't big enough, free the memory and expand it */
				VirtualFree( handle_info, 0, MEM_RELEASE );
				size *= 2;
			}
		} while ( status == STATUS_INFO_LENGTH_MISMATCH );

		if ( status == STATUS_SUCCESS )
		{
			POBJECT_TYPE_INFORMATION object_info = ( POBJECT_TYPE_INFORMATION ) VirtualAlloc( NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE );

			size_t handles{ };

			for ( DWORD i = 0; i < handle_info->HandleCount; ++i )
			{
				const auto current_handle = &handle_info->Handles[ i ];

				/* we aren't interested in handles we own */
				if ( current_handle->ProcessId == my_pid )
					continue;

				/* we need a handle to the process with PROCESS_DUP_HANDLE access rights */
				const HANDLE process_handle{ OpenProcess( PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, current_handle->ProcessId ) };
				if ( !process_handle )
					continue;

				/* we need to duplicate the handle in order to query the object information */
				HANDLE duplicate_handle{ };
				DuplicateHandle( process_handle, ( HANDLE )current_handle->Handle, GetCurrentProcess( ), &duplicate_handle, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0 );
				if ( !duplicate_handle )
				{
					CloseHandle( process_handle );
					continue;
				}

				/* check if the handle is opened us */
				if ( GetProcessId( duplicate_handle ) == my_pid )
				{
					char process_name[ MAX_PATH ];
					GetModuleFileNameEx( process_handle, NULL, process_name, MAX_PATH );

					std::cout << process_name << std::endl;

					handles++;
				}

				CloseHandle( duplicate_handle );
				CloseHandle( process_handle );
			}

			std::cout << "opened handles to our process: " << handles << "\n";
			std::cout << "------------------------------------------------\n";

			VirtualFree( object_info, 0, MEM_RELEASE );
		}

		VirtualFree( handle_info, 0, MEM_RELEASE );

		Sleep( 10000 );
	}

}