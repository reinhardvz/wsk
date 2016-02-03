/*++


Module Name:

    wsktcp.c

Author:
	reinhard v.z. 	
	
	https://github.com/reinhardvz

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


// Pool tags used for memory allocations
#define WSKTCP_SOCKET_POOL_TAG ((ULONG)'sksw')
#define WSKTCP_BUFFER_POOL_TAG ((ULONG)'bksw')
#define WSKTCP_GENERIC_POOL_TAG ((ULONG)'xksw')

// Default length for data buffers used in send and receive operations

static PWSK_SOCKET              g_TcpSocket = NULL;
PETHREAD gEThread = NULL;
SOCKADDR_IN 	LocalAddress = { 0, };
SOCKADDR_IN 	RemoteAddress = { 0, };

LONG    		BufferSize = 0;
ULONG			ByteCount = 0;
CHAR    		GreetMessage[10] = "hello WSK";
CHAR*    		pRxBuf = NULL;
BOOLEAN			bStopThread = FALSE;


#define SRV_PORT     			40007

#define HTON_SHORT(n) (((((unsigned short)(n) & 0xFFu  )) << 8) | \
					(((unsigned short)(n) & 0xFF00u) >> 8))

#define HTON_LONG(x)	(((((unsigned long)(x)& 0xff)<<24) | ((unsigned long)(x)>>24) & 0xff) | \
					(((unsigned long)(x) & 0xff0000)>>8) | (((unsigned long)(x) & 0xff00)<<8))

NTSTATUS
AsyncSendComplete(
		PDEVICE_OBJECT DeviceObject,
		PIRP Irp,
		PVOID Context
);

VOID
WsktcpUnload(
    __in PDRIVER_OBJECT DriverObject
    );

VOID
TcpSendWorker(
__in PVOID Context
);

// Driver entry routine
NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS 		status = STATUS_SUCCESS;
	
	HANDLE			hThread = NULL;
    UNREFERENCED_PARAMETER(RegistryPath);

    PAGED_CODE();

    DriverObject->DriverUnload = WsktcpUnload;

	pRxBuf = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, 10, 'dddd');

	status = WSKStartup();
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "WSKStartup failed with status 0x%08X\n", status);
		ExFreePool(pRxBuf);
		return status;
	}

    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, TcpSendWorker, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "thread Create failed with status 0x%08X\n", status);
		ExFreePool(pRxBuf);
		CloseSocket(g_TcpSocket);
		return status;
	}

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&gEThread, NULL);
	if (NT_SUCCESS(status) == FALSE) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "ObReferenceObjectByHandle failed with status 0x%08X\n", status);
		ExFreePool(pRxBuf);
		CloseSocket(g_TcpSocket);
		return status;
	}
	ZwClose(hThread);

	return status;
}

#define ASYNC_SEND_TEST		0
#define CONNECT_SEND_TEST	1
ULONG ltest1 = 0;
ULONG ltest2 = 0;

VOID
TcpSendWorker(
__in PVOID Context
)
{
	UNREFERENCED_PARAMETER(Context);

	NTSTATUS		status = STATUS_SUCCESS;
	LARGE_INTEGER	interval;
	RemoteAddress.sin_family = AF_INET;
	//RemoteAddress.sin_addr.s_addr = HTON_LONG(INADDR_LOOPBACK);
	RemoteAddress.sin_addr.s_addr = HTON_LONG(0x0a0a00f6); //10.10.0.232 test
	RemoteAddress.sin_port = HTON_SHORT(SRV_PORT); //40007
		
#if CONNECT_SEND_TEST
	g_TcpSocket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET);
	if (g_TcpSocket == NULL) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "CreateSocket() returned NULL\n");
		goto $EXIT;
	}

	LocalAddress.sin_family = AF_INET;
	LocalAddress.sin_addr.s_addr = INADDR_ANY;

	// Bind Required
	status = Bind(g_TcpSocket, (PSOCKADDR)&LocalAddress);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "Bind() failed with status 0x%08X\n", status);
		goto $EXIT;
	}

	status = Connect(g_TcpSocket, (PSOCKADDR)&RemoteAddress);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "Connect() failed with status 0x%08X\n", status);
		goto $EXIT;
	}

	while (!bStopThread) {
		
		interval.QuadPart = (-1 * 1000 * 10000);   // wait 1000ms relative

		KeDelayExecutionThread(KernelMode, TRUE, &interval);

		if (Send(g_TcpSocket, GreetMessage, 10, WSK_FLAG_NODELAY) == sizeof(GreetMessage)) {
			//DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "send ok\n ");
		} else {
			DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "send error happend\n ");
			goto $EXIT;
		}

		if (Receive(g_TcpSocket, pRxBuf, 10, 0)) {

		}
		else {
			DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "Receive fail\n ");
			goto $EXIT;
		}

	}
	
#endif

#if ASYNC_SEND_TEST
	g_TcpSocket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET);
	if (g_TcpSocket == NULL) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "CreateSocket() returned NULL\n");
		goto $EXIT;
	}

	LocalAddress.sin_family = AF_INET;
	LocalAddress.sin_addr.s_addr = INADDR_ANY;

	// Bind Required
	status = Bind(g_TcpSocket, (PSOCKADDR)&LocalAddress);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "Bind() failed with status 0x%08X\n", status);
		goto $EXIT;
	}

	status = Connect(g_TcpSocket, (PSOCKADDR)&RemoteAddress);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "Connect() failed with status 0x%08X\n", status);
		goto $EXIT;
	}
	
	
	InitWskBuffer(GreetMessage, sizeof(GreetMessage) - 1, &WskBuffer);

	while (!bStopThread) {
		PIRP			Irp;
		
		
		interval.QuadPart = (-1 * 1000 * 1000 * 10);   // wait 1 sec relative

		KeDelayExecutionThread(KernelMode, TRUE, &interval);
		// Allocate an IRP
		Irp = IoAllocateIrp( 1, FALSE );
		// Check result
		if (!Irp) {
			goto $EXIT;
		}
		
		// Set the completion routine for the IRP
		IoSetCompletionRoutine(Irp, AsyncSendComplete , &WskBuffer, TRUE, TRUE, TRUE);

		//g_TcpSocket->Dispatch->WskSend(g_TcpSocket, WskBuffer, 0, Irp);
		((PWSK_PROVIDER_CONNECTION_DISPATCH)g_TcpSocket->Dispatch)->WskSend(g_TcpSocket, &WskBuffer, 0, Irp);
		
	}

#endif

$EXIT:	
	if (g_TcpSocket) {
		CloseSocket(g_TcpSocket);
		g_TcpSocket = NULL;
	}
	
	PsTerminateSystemThread(STATUS_SUCCESS);
	return;
}

NTSTATUS
AsyncSendComplete(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PVOID Context
)
{
	
	PWSK_BUF pDataBuffer = NULL;

	UNREFERENCED_PARAMETER(DeviceObject);

	// Check the result of the send operation
	if (Irp->IoStatus.Status == STATUS_SUCCESS)	{
		// Get the pointer to the data buffer
		pDataBuffer = (PWSK_BUF)Context;
		// Get the number of bytes sent
		ByteCount = (ULONG)(Irp->IoStatus.Information);

		// Re-use or free the data buffer
	} else { 	// Error status
		// Handle error
	}

	//FreeWskBuffer(pDataBuffer);

	// Free the IRP
	IoFreeIrp(Irp);

	// Always return STATUS_MORE_PROCESSING_REQUIRED to
	// terminate the completion processing of the IRP.
	return STATUS_MORE_PROCESSING_REQUIRED;
}


// Driver unload routine
VOID
WsktcpUnload(
__in PDRIVER_OBJECT DriverObject
)
{

	UNREFERENCED_PARAMETER(DriverObject);

	PAGED_CODE();

	//status = DisConnect(g_TcpSocket);
	//if (!NT_SUCCESS(status)) {
	//	DbgPrintEx(DPFLTR_IHVNETWORK_ID, 0xFFFFFFFF, "DisConnect() failed with status 0x%08X\n", status);
	//}

	if (g_TcpSocket) {
		CloseSocket(g_TcpSocket);
		g_TcpSocket = NULL;
	}
	
	bStopThread = TRUE;

	KeWaitForSingleObject(gEThread,
		Executive,
		KernelMode,
		FALSE,
		NULL);        //wait for terminate thread....  

	

	ObDereferenceObject(gEThread);
	
	WSKCleanup();

	ExFreePool(pRxBuf);
	

}
