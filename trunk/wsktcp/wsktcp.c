/*++


Module Name:

    Wskudp.c

Author:
	reinhard v.z. 	
	
	http://zpacket.blogspot.kr/

Environment:

    Kernel-Mode only

Revision History:

--*/

#pragma warning(push)
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int

#include <ntddk.h>
#include <wsk.h>
#include "simplewsk.h"


#pragma warning(pop)

// Software Tracing definitions
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(WsktcpCtlGuid, \
        (998bdf51, 0349, 4fbc, 870c, d6130a955a5f), \
        WPP_DEFINE_BIT(TRCERROR) \
        WPP_DEFINE_BIT(TRCINFO) )

#include "wsktcp.tmh"

// Pool tags used for memory allocations
#define WSKTCP_SOCKET_POOL_TAG ((ULONG)'sksw')
#define WSKTCP_BUFFER_POOL_TAG ((ULONG)'bksw')
#define WSKTCP_GENERIC_POOL_TAG ((ULONG)'xksw')

// Default length for data buffers used in send and receive operations

static PWSK_SOCKET              g_TcpSocket = NULL;

#define LOG_PORT     			3000

#define HTON_SHORT(n) (((((unsigned short)(n) & 0xFFu  )) << 8) | \
					(((unsigned short)(n) & 0xFF00u) >> 8))

#define HTON_LONG(x)	(((((x)& 0xff)<<24) | ((x)>>24) & 0xff) | \
					(((x) & 0xff0000)>>8) | (((x) & 0xff00)<<8))

VOID
WsktcpUnload(
    __in PDRIVER_OBJECT DriverObject
    );

// Driver entry routine
NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS 		status = STATUS_SUCCESS;
	SOCKADDR_IN 	LocalAddress = {0,};
	SOCKADDR_IN 	RemoteAddress = {0,};
	
    LONG    		BufferSize = 0;
    CHAR    		GreetMessage[] = "Hello WSK TCP Client \r\n";

    UNREFERENCED_PARAMETER(RegistryPath);

    PAGED_CODE();

    DriverObject->DriverUnload = WsktcpUnload;

	status = WSKStartup();

    g_TcpSocket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET);
    if (g_TcpSocket == NULL) {
        DbgPrint("DriverEntry(): CreateSocket() returned NULL\n");
		return (status = STATUS_UNSUCCESSFUL);
    }

    LocalAddress.sin_family = AF_INET;
    LocalAddress.sin_addr.s_addr = INADDR_ANY;
    //LocalAddress.sin_port = INADDR_PORT;
	
	// Bind Required
	status = Bind(g_TcpSocket, (PSOCKADDR)&LocalAddress);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Bind() failed with status 0x%08X\n", status);
		CloseSocket(g_TcpSocket);
		return status;
	}
	
	RemoteAddress.sin_family = AF_INET;
    RemoteAddress.sin_addr.s_addr = HTON_LONG(INADDR_LOOPBACK);
    RemoteAddress.sin_port = HTON_SHORT(LOG_PORT);

	status = Connect(g_TcpSocket, (PSOCKADDR)&RemoteAddress);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Connect() failed with status 0x%08X\n", status);
		CloseSocket(g_TcpSocket);
		return status;
	}

    if (Send(g_TcpSocket, GreetMessage, sizeof(GreetMessage)-1, WSK_FLAG_NODELAY) == sizeof(GreetMessage)-1) {
	} else {
		
	}

	CloseSocket(g_TcpSocket);
		
    // Initialize software tracing
    WPP_INIT_TRACING(DriverObject, RegistryPath);
    
    DoTraceMessage(TRCINFO, "LOADED");
    
    return status;
}

// Driver unload routine
VOID
WsktcpUnload(
    __in PDRIVER_OBJECT DriverObject
    )
{  
    
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    DoTraceMessage(TRCINFO, "UNLOAD START");

	WSKCleanup();
	
    DoTraceMessage(TRCINFO, "UNLOAD END");

    WPP_CLEANUP(DriverObject);
}

