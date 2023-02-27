
#include "stdafx.h"
#include "entry.h"
#include "infinityhook.h"
#include <ntddk.h>
#include <Wdm.h>
#include "HipsSession.h"
#include "OasSession.h"
#include "HipsRequest.h"
#include "HipsResponse.h"
#include "OasRequest.h"
#include "SelfDefenceSession.h"
#include "SelfDefenceRequest.h"
#include "SelfDefenceResponse.h"

//#include <jxy/map.hpp>
//#include <fltKernel.h>

#define IOCTL_GUI_SERVICE_HELLO CTL_CODE( FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_WAIT_FOR_HIPS_REQUEST CTL_CODE( FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_WAIT_FOR_OAS_REQUEST CTL_CODE( FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_WAIT_FOR_SELF_DEFENCE_REQUEST CTL_CODE( FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_SEND_HIPS_RESPONSE CTL_CODE( FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_SEND_OAS_RESPONSE CTL_CODE( FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_SEND_SELF_DEFENCE_RESPONSE CTL_CODE( FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

const WCHAR deviceNameBuffer[] = L"\\Device\\kinfinity";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\kinfinity";
static PDEVICE_OBJECT g_MyDevice; // Global pointer to our device object

static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static UNICODE_STRING StringZwTerminateProcess = RTL_CONSTANT_STRING(L"ZwTerminateProcess");
static UNICODE_STRING StringZwQueryInformationProcess = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
static UNICODE_STRING StringNtOpenProcess = RTL_CONSTANT_STRING(L"NtOpenProcess");
static UNICODE_STRING StringNtSetInformationProcess = RTL_CONSTANT_STRING(L"NtSetInformationProcess");

static NtCreateFile_t OriginalNtCreateFile = nullptr;
static ZwTerminateProcess_t OriginalZwTerminateProcess = nullptr;
static ZwQueryInformationProcess_t OriginalZwQueryInformationProcess = nullptr;
static NtOpenProcess_t OriginalNtOpenProcess = nullptr;
static NtSetInformationProcess_t OriginalNtSetInformationProcess = nullptr;

static FAST_MUTEX SessionMutex;
static Session* Sessions[1024] = { nullptr };
static int SessionsCount = 0;

//static OasSession* OasSessions[1024] = { nullptr };

static HANDLE GuiServiceProcessId = 0;
static bool IsGuiServiceAnnounced = false;



void DumpSessions()
{
	kprintf("[+] infinityhook: SESSIONS DUMP:.\n");

	for (int i = 0; i < 10; i++)
	{
		kprintf("0x%p\n", Sessions[i]);
	}
}

NTSTATUS Function_IRP_MJ_CREATE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	kprintf("IRP MJ CREATE received.\n");
	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_MJ_CLOSE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	kprintf("IRP MJ CLOSE received.\n");
	return STATUS_SUCCESS;
}


NTSTATUS HandleGuiServiceHello(PIO_STACK_LOCATION pIoStackLocation, PIRP Irp)
{
	GuiServiceProcessId = PsGetCurrentProcessId();
	IsGuiServiceAnnounced = true;
	ULONG BreakOnTermination = 1;
	
	HANDLE currentProcess = nullptr;
	CLIENT_ID clientId = { 0 };
	clientId.UniqueProcess = PsGetCurrentProcessId();
	NTSTATUS status = OriginalNtOpenProcess(&currentProcess, PROCESS_ALL_ACCESS, nullptr, &clientId);
	kprintf("OriginalNtOpenProcess(): status: 0x%p, handle: 0x%p.\n", status, currentProcess);
	status = OriginalNtSetInformationProcess(currentProcess, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	kprintf("OriginalNtSetInformationProcess(): status: 0x%p, handle: 0x%p.\n", status, currentProcess);

	//RtlSetProcessIsCritical()
	
	/*PWCHAR welcome = L"Hello from kerneland.";
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;

	kprintf("HandleGuiServiceHello.");
	Sleep(15000);
	kprintf("Message received : %S", (PWCHAR)pBuf);

	RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
	RtlCopyMemory(pBuf, welcome, wcslen(welcome) * 2 + 2);*/

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
template </*typename T,*/ size_t size>
Session* WaitForNewSession(Session*(&array)[size], ProtectionType protectionType)
{
	kprintf("WaitForNewSession.\n");
	DumpSessions();
	while (true)
	{
		ExAcquireFastMutex(&SessionMutex);
		if (SessionsCount == 0)
		{
			ExReleaseFastMutex(&SessionMutex);
			KernelSleep(50);
			continue;
		}

		for (int i = 0;i < size;i++)
		{
			if (array[i] != nullptr && 
				array[i]->ProtectionType == protectionType &&
				array[i]->IsRequestReadByService == false)
			{
				kprintf("WaitForNewSession(): new request at slot %d.\n", i);
				DumpSessions();
				ExReleaseFastMutex(&SessionMutex);
				return array[i];
			}
		}
		ExReleaseFastMutex(&SessionMutex);
	}
}

template <size_t size>
Session* FindSessionById(UUID id, Session* (&array)[size], ProtectionType protectionType)
{
	kprintf("FindSessionById.\n");
	ExAcquireFastMutex(&SessionMutex);


	for (int i = 0;i < size;i++)
	{
		if (array[i] != nullptr && array[i]->SessionId == id && array[i]->ProtectionType == protectionType)
		{
			kprintf("FindSessionById(): found request at slot %d.\n", i);
			ExReleaseFastMutex(&SessionMutex);
			return array[i];
		}
	}

	kprintf("FindSessionById(): error: no such session by session id.\n");
	ExRaiseStatus(STATUS_NOT_FOUND);
	ExReleaseFastMutex(&SessionMutex);
	return nullptr;
}


template <size_t size>
void FindDriverRequestFreeSlotAndSetSession(Session*(&array)[size], Session* session)
{
	kprintf("FindDriverRequestFreeSlotAndSetSession.\n");

	ExAcquireFastMutex(&SessionMutex);

	for (int i = 0;i < size;i++)
	{
		if (array[i] == nullptr)
		{
			kprintf("FindDriverRequestFreeSlotAndSetSession(): Found free slot %d.\n", i);
			array[i] = session;
			SessionsCount++;
			kprintf("FindDriverRequestFreeSlotAndSetSession(): Sessions count %d.\n", SessionsCount);

			ExReleaseFastMutex(&SessionMutex);
			return;
		}
	}

	kprintf("FindDriverRequestFreeSlotAndSetSession(): can't find free slot.\n");
	ExRaiseStatus(STATUS_NOT_FOUND);
	ExReleaseFastMutex(&SessionMutex);
}

template <size_t size>
void FreeSession(Session* (&array)[size], Session* session)
{
	ExAcquireFastMutex(&SessionMutex);
	for (int i = 0;i < size;i++)
	{
		if (array[i] == session)
		{
			array[i] = nullptr;
			SessionsCount--;
			kprintf("FreeSession(): Sessions count %d.\n", SessionsCount);
			ExReleaseFastMutex(&SessionMutex);
			return;
		}
	}

	kprintf("FreeSession(): can't find find session to free.\n");
	ExRaiseStatus(STATUS_NOT_FOUND);
	ExReleaseFastMutex(&SessionMutex);
}


//Session* GetSession(int slot)
//{
//	kprintf("GetSession on slot %d.\n", slot);
//
//	ExAcquireFastMutex(&SessionMutex);
//
//	Session* session = Sessions[slot];
//
//	ExReleaseFastMutex(&SessionMutex);
//
//	return session;
//}

//template <size_t size>
//int FindDriverOasRequestSlotBySessionId(UUID id, const OasSession*(&array)[size])
//{
//	kprintf("FindDriverOasRequestSlotBySessionId.");
//
//	for (int i = 0;i < size;i++)
//	{
//		if (array[i] != nullptr && array[i]->SessionId == id)
//		{
//			kprintf("FindDriverOasRequestSlotBySessionId(): found request at slot %d.", i);
//			return i;
//		}
//	}
//	kprintf("FindDriverOasRequestSlotBySessionId(): error: no such session by session id.");
//	ExRaiseStatus(STATUS_NOT_FOUND);
//	return -1;
//}

bool Authorize()
{
	kprintf("Authorize.\n");

	if (GuiServiceProcessId != PsGetCurrentProcessId())
	{
		kprintf("Authorize(): GuiServiceProcessId: 0x%p, PsGetCurrentProcessId(): 0x%p. Operation is not permitted\n", 
			GuiServiceProcessId, PsGetCurrentProcessId());
		return false;
	}
	return true;
}

NTSTATUS HandleWaitForHipsRequset(PIO_STACK_LOCATION pIoStackLocation, PIRP Irp)
{
	kprintf("HandleWaitForHipsRequset.\n");

	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;

	DumpSessions();
	HipsSession* session = (HipsSession*)WaitForNewSession(Sessions, ProtectionType::Hips);
	session->IsRequestReadByService = true;
	DumpSessions();

	auto totalSize = sizeof(*session->Request);
	kprintf("Got new hips request. Request size: %zu, input buffer: %zu, output buffer: %zu\n", totalSize, 
		pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength,
		pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);

	RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);
	RtlCopyMemory(pBuf, session->Request, totalSize);
	
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = totalSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	kprintf("HandleWaitForHipsRequset(): request sent to gui service.\n");

	return STATUS_SUCCESS;
}

NTSTATUS HandleWaitForOasRequset(PIO_STACK_LOCATION pIoStackLocation, PIRP Irp)
{
	kprintf("HandleWaitForOasRequset.\n");

	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;

	//Ожидаем появления событие на открытие файла
	OasSession* session = (OasSession*)WaitForNewSession(Sessions, ProtectionType::Oas);

	//Помечаем событие как обработанное, что бы оно не передавалось при новом запросе на получение событий
	session->IsRequestReadByService = true;

	auto totalSize = sizeof(*session->Request);
	kprintf("Got new oas request. Request size: %zu, input buffer: %zu, output buffer: %zu\n", totalSize,
		pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength,
		pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);

	RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);

	//Копируем тело запроса в буфер, переданный из пространства пользователя
	RtlCopyMemory(pBuf, session->Request, totalSize);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = totalSize;

	//Завершаем вызов DeviceIoControl с результатом NTSTATUS = STATUS_SUCCESS
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS HandleWaitForSelfDefenceRequset(PIO_STACK_LOCATION pIoStackLocation, PIRP Irp)
{
	kprintf("HandleWaitForSelfDefenceRequset.\n");

	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;

	SelfDefenceSession* session = (SelfDefenceSession*)WaitForNewSession(Sessions, ProtectionType::SelfDefence);
	session->IsRequestReadByService = true;

	auto totalSize = sizeof(*session->Request);
	kprintf("Got new self defence request. Request size: %zu, input buffer: %zu, output buffer: %zu\n", totalSize,
		pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength,
		pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);

	RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);
	RtlCopyMemory(pBuf, session->Request, totalSize);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = totalSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS HandleSendSelfDefenceResponse(PIO_STACK_LOCATION pIoStackLocation, PIRP Irp)
{
	kprintf("HandleSendSelfDefenceResponse.\n");

	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	SelfDefenceResponse* response = (SelfDefenceResponse*)ExAllocatePool(NonPagedPool, sizeof(SelfDefenceResponse));
	RtlCopyBytes(response, pBuf, sizeof(*response));

	SelfDefenceSession* session = (SelfDefenceSession*)FindSessionById(response->SessionId, Sessions, ProtectionType::SelfDefence);
	session->Response = response;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	kprintf("HandleSendSelfDefenceResponse() response received and set to session.\n");

	return STATUS_SUCCESS;
}

NTSTATUS HandleSendHipsResponse(PIO_STACK_LOCATION pIoStackLocation, PIRP Irp)
{
	kprintf("HandleSendHipsResponse.\n");

	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	HipsResponse* response = (HipsResponse*)ExAllocatePool(NonPagedPool, sizeof(HipsResponse));
	RtlCopyBytes(response, pBuf, sizeof(*response));

	HipsSession* session = (HipsSession*)FindSessionById(response->SessionId, Sessions, ProtectionType::Hips);
	session->Response = response;
	
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	kprintf("HandleSendHipsResponse() response received and set to session.\n");

	return STATUS_SUCCESS;
}

NTSTATUS HandleSendOasResponse(PIO_STACK_LOCATION pIoStackLocation, PIRP Irp)
{
	kprintf("HandleSendOasResponse.\n");

	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	OasResponse* response = (OasResponse*)ExAllocatePool(NonPagedPool, sizeof(OasResponse));
	RtlCopyBytes(response, pBuf, sizeof(*response));

	OasSession* session = (OasSession*)FindSessionById(response->SessionId, Sessions, ProtectionType::Oas);
	session->Response = response;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	kprintf("HandleSendOasResponse() response received and set to session.\n");

	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	
	if (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode != IOCTL_GUI_SERVICE_HELLO && !Authorize())
	{
		kprintf("Function_IRP_DEVICE_CONTROL(): Authorize() failed.\n");
		Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_ACCESS_DENIED;
	}
	
	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_GUI_SERVICE_HELLO:
			return HandleGuiServiceHello(pIoStackLocation, Irp);
		break;
		
		case IOCTL_WAIT_FOR_HIPS_REQUEST:
			return HandleWaitForHipsRequset(pIoStackLocation, Irp);
			break;

		case IOCTL_WAIT_FOR_OAS_REQUEST:
			return HandleWaitForOasRequset(pIoStackLocation, Irp);
			break;

		case IOCTL_WAIT_FOR_SELF_DEFENCE_REQUEST:
			return HandleWaitForSelfDefenceRequset(pIoStackLocation, Irp);
			break;
			
		case IOCTL_SEND_HIPS_RESPONSE:
			return HandleSendHipsResponse(pIoStackLocation, Irp);
			break;

		case IOCTL_SEND_OAS_RESPONSE:
			return HandleSendOasResponse(pIoStackLocation, Irp);
			break;
		case IOCTL_SEND_SELF_DEFENCE_RESPONSE:
			return HandleSendSelfDefenceResponse(pIoStackLocation, Irp);
			break;
			
		default:
			kprintf("Unexcpected ioctl code received.\n");
			Irp->IoStatus.Status = STATUS_NOT_FOUND;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_NOT_FOUND;
	}
}

void PrepareMajorFunctions(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS ntStatus = 0;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;

	// Normalize name and symbolic link.
	RtlInitUnicodeString(&deviceNameUnicodeString,
		deviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString,
		deviceSymLinkBuffer);

	ntStatus = IoCreateDevice(pDriverObject,
		0, // For driver extension
		&deviceNameUnicodeString,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_UNKNOWN,
		FALSE,
		&g_MyDevice);

	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString,
		&deviceNameUnicodeString);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;
}



extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	kprintf("[+] infinityhook: Loaded.\n");
	DriverObject->DriverUnload = DriverUnload;

	ExInitializeFastMutex(&SessionMutex);
	
	PrepareMajorFunctions(DriverObject);
	
	NTSTATUS status = STATUS_SUCCESS;

	//NtSetInformationProcess(GetCurrentProcess(), ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	UNICODE_STRING test = RTL_CONSTANT_STRING(L"NtSetInformationProcess");
	kprintf("[-] infinityhook: NtSetInformationProcess:0x%p.\n", MmGetSystemRoutineAddress(&test));
	test = RTL_CONSTANT_STRING(L"ZwSetInformationProcess");
	kprintf("[-] infinityhook: ZwSetInformationProcess:0x%p.\n", MmGetSystemRoutineAddress(&test));


	//kprintf("[+] NtTerminateProcess 0x%p: \n", MmGetSystemRoutineAddress(&b));
	OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
	if (!OriginalNtCreateFile)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtCreateFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	
	OriginalZwTerminateProcess = (ZwTerminateProcess_t)MmGetSystemRoutineAddress(&StringZwTerminateProcess);
	if (!OriginalZwTerminateProcess)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringZwTerminateProcess);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	OriginalZwQueryInformationProcess = (ZwQueryInformationProcess_t)MmGetSystemRoutineAddress(&StringZwQueryInformationProcess);
	if (!OriginalZwQueryInformationProcess)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringZwQueryInformationProcess);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	OriginalNtOpenProcess = (NtOpenProcess_t)MmGetSystemRoutineAddress(&StringNtOpenProcess);
	if (!OriginalNtOpenProcess)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtOpenProcess);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	OriginalNtSetInformationProcess = (NtSetInformationProcess_t)MmGetSystemRoutineAddress(&StringNtSetInformationProcess);
	if (!OriginalNtSetInformationProcess)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtSetInformationProcess);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	if (!NT_SUCCESS((status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, FALSE))))
	{
		kprintf("[-] infinityhook: PsSetCreateProcessNotifyRoutineEx failed\n");
		return status;
	}

	status = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(status))
	{
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", status);
		return status;
	}

	//jxy::map<int, int, PagedPool, '0GAT'> map{ { 1, 1 }, { 2, 2 } };
	////map.insert(22, 33);
	//kprintf("[+] infinityhook: test: 0xd.\n", map[1]);
	//kprintf("[+] infinityhook: test: 0xd.\n", map[2]);
	////kprintf("[+] infinityhook: test: 0xd.\n", map[22]);
	//kprintf("[+] infinityhook: test: 0xd.\n", map.size());
	
	
	return status;
}




void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink;

	RtlInitUnicodeString(&symLink, deviceSymLinkBuffer);

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	IfhRelease();
	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, TRUE);
	kprintf("\n[!] infinityhook: Unloading... BYE!\n");
}

/*
*	For each usermode syscall, this stub will be invoked.
*/
void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex, 
	_Inout_ void** SystemCallFunction)
{
	// 
	// Enabling this message gives you VERY verbose logging... and slows
	// down the system. Use it only for debugging.
	//
	
#if 0
	kprintf("[+] infinityhook: SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
#endif

	UNREFERENCED_PARAMETER(SystemCallIndex);

	//
	// In our demo, we care only about nt!NtCreateFile calls.
	//
	if (*SystemCallFunction == OriginalNtCreateFile)
	{
		//
		// We can overwrite the return address on the stack to our detoured
		// NtCreateFile.
		//
		*SystemCallFunction = DetourNtCreateFile;
	}

	if (*SystemCallFunction == NtOpenProcess)
	{
		*SystemCallFunction = DetourNtOpenProcess;
	}

	/*if (*SystemCallFunction == ZwOpenProcess)
	{
		kprintf("[+] infinityhook: SelfDefense: ZwOpenProcess: 0x%p\n", ZwOpenProcess);

	}

	if (*SystemCallFunction == ZwTerminateProcess)
	{
		kprintf("[+] infinityhook: SelfDefense: ZwTerminateProcess: 0x%p\n", ZwTerminateProcess);
	}*/
	
	//if (*SystemCallFunction == OriginalZwTerminateProcess)
	//{
	//	kprintf("[+] infinityhook: SelfDefense: OriginalZwTerminateProcess: 0x%p\n", OriginalZwTerminateProcess);
	//	*SystemCallFunction = DetourZwTerminateProcess;
	//}
}

NTSTATUS DetourNtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PCLIENT_ID ClientId)
{
	if (!IsGuiServiceAnnounced)
	{
		kprintf("[+] infinityhook: SelfDefense: DetourNtOpenProcess(): gui service is not announced. DetourNtOpenProcess call allowed\n");
		return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}
	HANDLE callerProcessId = PsGetCurrentProcessId();

	//kprintf("[+] infinityhook: SelfDefense: DetourNtOpenProcess(): process 0x%p is triyng to open process 0x%p handle\n", callerProcessId, ClientId->UniqueProcess);

	if (callerProcessId == GuiServiceProcessId)
	{
		kprintf("[+] infinityhook: SelfDefense: DetourNtOpenProcess(): process 0x%p is gui proccess. open process 0x%p handle allowed\n", callerProcessId, ClientId->UniqueProcess);
		return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}

	/*if (ClientId->UniqueProcess == GuiServiceProcessId)
	{
		kprintf("[+] infinityhook: SelfDefense: DetourNtOpenProcess(): process 0x%p is triyng to get gui service process handle. access denied\n", PsGetCurrentProcessId());
		return STATUS_ACCESS_DENIED;
	}*/

	//if (ClientId->UniqueProcess != GuiServiceProcessId)
	//{
	//	//kprintf("[+] infinityhook: SelfDefense: DetourNtOpenProcess(): process 0x%p is triyng to open process 0x%p handle\n", PsGetCurrentProcessId(), ClientId->UniqueProcess);
	//	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	//}


	UUID uuid;
	ExUuidCreate(&uuid);
	HANDLE pid = PsGetCurrentProcessId();

	SelfDefenceRequest* sd = (SelfDefenceRequest*)ExAllocatePool(NonPagedPool, sizeof(SelfDefenceRequest));
	sd->SessionId = uuid;
	sd->CallerPid = pid;
	sd->SelfDefenceEvent = SelfDefenceEvent::OpenProcess;
	sd->CalleePid = ClientId->UniqueProcess;
	sd->CalleeTid = ClientId->UniqueThread;
	sd->DesiredAccess = DesiredAccess;

	SelfDefenceSession* session = (SelfDefenceSession*)ExAllocatePool(NonPagedPool, sizeof(SelfDefenceSession));
	session->SessionId = uuid;
	session->Request = sd;
	session->Response = nullptr;
	session->ProtectionType = ProtectionType::SelfDefence;
	session->IsRequestReadByService = false;

	DumpSessions();
	FindDriverRequestFreeSlotAndSetSession(Sessions, session);
	DumpSessions();
	kprintf("[+] infinityhook: Waiting on response...\n");

	while (session->Response == nullptr)
	{
		KernelSleep(10);
	}

	kprintf("[+] infinityhook: Response received\n");
	SelfDefenceResponse* response = (SelfDefenceResponse*)session->Response;

	Verdict verdict = response->Verdict;

	FreeSession(Sessions, session);

	ExFreePool(sd);
	ExFreePool(response);
	ExFreePool(session);

	if (verdict == Verdict::Allow)
	{
		kprintf("[+] infinityhook: SelfDefence: Process 0x%p is allowed to open process 0x%p with access %lu\n", pid, ClientId->UniqueProcess, DesiredAccess);
		return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}
	else
	{
		kprintf("[+] infinityhook: SelfDefence: Process 0x%p is denied to open process 0x%p with access %lu\n", pid, ClientId->UniqueProcess, DesiredAccess);
		return STATUS_ACCESS_DENIED;
	}
}

//NTSTATUS DetourZwTerminateProcess(
//	_In_ HANDLE ProcessHandle,
//	_In_ NTSTATUS ExitStatus)
//{
//
//	if (!IsGuiServiceAnnounced)
//	{
//		kprintf("[+] infinityhook: SelfDefense: DetourZwTerminateProcess(): gui service is not announced. termination allowed\n");
//		return OriginalZwTerminateProcess(ProcessHandle, ExitStatus);
//	}
//	
//	HANDLE callerPid = PsGetCurrentProcessId();
//	if (callerPid == GuiServiceProcessId)
//	{
//		kprintf("[+] infinityhook: SelfDefense: DetourZwTerminateProcess(): Process 0x%p is process gui service process, process termination allowed\n", callerPid);
//		return OriginalZwTerminateProcess(ProcessHandle, ExitStatus);
//	}
//
//	ULONG ReturnLength;
//	PROCESS_BASIC_INFORMATION ProcessInformation;
//	if (!NT_SUCCESS(OriginalZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &ReturnLength)))
//	{
//		kprintf("[+] infinityhook: SelfDefense: DetourZwTerminateProcess(): Process 0x%p is trying to terminate process. ZwQueryInformationProcess faliled, process termination allowed\n", callerPid);
//		return OriginalZwTerminateProcess(ProcessHandle, ExitStatus);
//	}
//
//	HANDLE targetPid = (HANDLE)ProcessInformation.UniqueProcessId;
//	if (targetPid == GuiServiceProcessId)
//	{
//		kprintf("[+] infinityhook: SelfDefense: DetourZwTerminateProcess(): Process 0x%p is trying to terminate gui service process 0x%p, process termination denied\n", callerPid, targetPid);
//		return STATUS_ACCESS_DENIED;
//	}
//	/*CLIENT_ID ClientId;
//	OBJECT_ATTRIBUTES ObjectAttributes;
//	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
//	ClientId.UniqueThread = NULL;
//	ClientId.UniqueProcess = GuiServiceProcessId;
//	HANDLE guiProcessHandle;
//	NTSTATUS Status = NtOpenProcess(&guiProcessHandle,
//		PROCESS_QUERY_INFORMATION,
//		&ObjectAttributes,
//		&ClientId);*/
//
//	return OriginalZwTerminateProcess(ProcessHandle, ExitStatus);
//
//	//kprintf("[+] infinityhook: ZwTerminateProcess: 0x%p.\n", ProcessHandle);
//}

NTSTATUS DetourNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength)
{
	if (ObjectAttributes == nullptr ||
		ObjectAttributes->ObjectName == nullptr ||
		ObjectAttributes->ObjectName->Buffer == nullptr)
	{
		return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
			ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}

	if (!IsGuiServiceAnnounced)
	{
		kprintf("[+] infinityhook: Oas: DetourNtCreateFile(): gui service is not announced. create file allowed\n");
		return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
			ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}

	HANDLE pid = PsGetCurrentProcessId();
	kprintf("[+] infinityhook: Oas: Process 0x%p is about to access file %wZ \n", pid, ObjectAttributes->ObjectName);

	if (pid == GuiServiceProcessId)
	{
		kprintf("[+] infinityhook: Oas: Process 0x%p is process gui service process, access allowed\n", pid);
		return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
			ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}
	
	PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
	RtlZeroBytes(ObjectName, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
	RtlCopyBytes(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

	PWCHAR colon;
	if ((colon = wcsrchr(ObjectName, ':')) == nullptr)
	{
		kprintf("[+] infinityhook: Oas: DetourNtCreateFile(): file %wZ is not regular file, access allowed\n", ObjectAttributes->ObjectName);
		ExFreePool(ObjectName);
		return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
			ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}

	ExFreePool(ObjectName);
	
	/*PWCHAR ext;
	if ((ext = wcsrchr(ObjectName, '.')) == nullptr)
	{
		ExFreePool(ObjectName);
		return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
			ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}

	if (wcscmp(ext, L".exe") != 0 && wcscmp(ext, L".dll") != 0)
	{
		ExFreePool(ObjectName);
		return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
			ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}*/

	

	UUID uuid;
	ExUuidCreate(&uuid);

	//Выделяем память и инициализируем тело запроса
	OasRequest* oas = (OasRequest*)ExAllocatePool(NonPagedPool, sizeof(OasRequest));
	oas->SessionId = uuid;
	oas->CallerPid = pid;
	oas->DesiredAccess = DesiredAccess;
	RtlZeroMemory(oas->ObjectPath, sizeof(oas->ObjectPath));
	RtlCopyMemory(oas->ObjectPath, (PVOID)ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
	OasSession* session = (OasSession*)ExAllocatePool(NonPagedPool, sizeof(OasSession));
	session->SessionId = uuid;
	session->Request = oas;
	session->Response = nullptr;
	session->ProtectionType = ProtectionType::Oas;
	session->IsRequestReadByService = false;

	//Помещаем событие в очередь
	DumpSessions();
	FindDriverRequestFreeSlotAndSetSession(Sessions, session);
	DumpSessions();
	kprintf("[+] infinityhook: Waiting on response...\n");

	//Блокируем управление до тех пор, пока сервисный процесс не обработает событие, и не вынесет вердикт
	while (session->Response == nullptr) { KernelSleep(10); }

	kprintf("[+] infinityhook: Response received\n");
	OasResponse* response = (OasResponse*)session->Response;

	FreeSession(Sessions, session);

	ExFreePool(oas);
	ExFreePool(response);
	ExFreePool(session);

	//Вердикт получен, принимаем решение о разрешении получения дескриптора файла, 
	//иначе возвращаем состояние NTSTATUS = STATUS_ACCESS_DENIED, запрещая доступ
	Verdict verdict = response->Verdict;
	if (verdict == Verdict::Allow)
	{
		kprintf("[+] infinityhook: Oas: Process 0x%p is allowed to access %wZ.\n", pid, ObjectAttributes->ObjectName);
		return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
			ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}
	else
	{
		kprintf("[+] infinityhook: Oas: Process 0x%p is not allowed to access %wZ.\n", pid, ObjectAttributes->ObjectName);
		return STATUS_ACCESS_DENIED;
	}
	//
	// Unicode strings aren't guaranteed to be NULL terminated so
	// we allocate a copy that is.
	//
	//PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
	//if (ObjectName)
	//{
	//	memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
	//	memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
	//
	//	if (wcsstr(ObjectName, IfhMagicFileName))
	//	{
	//		kprintf("[+] infinityhook: Denying access to file: %wZ.\n", ObjectAttributes->ObjectName);

	//		LARGE_INTEGER waitTime;

	//		/*KEVENT Event;
	//		KeInitializeEvent(&Event, NotificationEvent, FALSE);
	//		KeWaitForSingleObject(&Event,
	//			Executive,
	//			KernelMode,
	//			FALSE,
	//			&waitTime);*/
	//		kprintf("[+] infinityhook: Return!\n");


	//		ExFreePool(ObjectName);

	//		return STATUS_ACCESS_DENIED;
	//	}

	//	ExFreePool(ObjectName);
	//}
}




void CreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE calleePid, PPS_CREATE_NOTIFY_INFO createInfo)
{
	UNREFERENCED_PARAMETER(process);
	UNREFERENCED_PARAMETER(calleePid);

	if (createInfo == NULL)
	{
		return;
	}
	
	HANDLE callerPid = PsGetCurrentProcessId();
	kprintf("[+] infinityhook: Hips: Process 0x%p is about to start new process %wZ \n", callerPid, createInfo->ImageFileName);

	if (!IsGuiServiceAnnounced)
	{
		kprintf("[+] infinityhook: Hips: CreateProcessNotifyRoutineEx(): gui service is not announced. process cration allowed\n");
		createInfo->CreationStatus = STATUS_SUCCESS;
		return;
	}

	if (callerPid == GuiServiceProcessId)
	{
		kprintf("[+] infinityhook: Hips: Process 0x%p is process gui service process, access allowed\n", callerPid);
		createInfo->CreationStatus = STATUS_SUCCESS;
		return;
	}

	UUID uuid;
	ExUuidCreate(&uuid);

	HipsRequest* hips = (HipsRequest*)ExAllocatePool(NonPagedPool, sizeof(HipsRequest));
	hips->SessionId = uuid;
	hips->CallerPid = callerPid;
	hips->CalleePid = calleePid;
	RtlZeroMemory(hips->ObjectPath, sizeof(hips->ObjectPath));
	RtlCopyMemory(hips->ObjectPath, (PVOID)createInfo->ImageFileName->Buffer, createInfo->ImageFileName->Length);

	HipsSession* session = (HipsSession*)ExAllocatePool(NonPagedPool, sizeof(HipsSession));
	session->SessionId = uuid;
	session->Request = hips;
	session->Response = nullptr;
	session->ProtectionType = ProtectionType::Hips;
	session->IsRequestReadByService = false;

	DumpSessions();
	FindDriverRequestFreeSlotAndSetSession(Sessions, session);
	DumpSessions();
	kprintf("[+] infinityhook: Waiting on response...\n");

	while (session->Response == nullptr)
	{
		//KeStallExecutionProcessor(1000);
		KernelSleep(10);
	}

	kprintf("[+] infinityhook: Response received\n");
	HipsResponse* response = (HipsResponse*)session->Response;

	if (response->Verdict == Verdict::Allow)
	{
		kprintf("[+] infinityhook: Hips: Process %wZ is allowed to run.\n", createInfo->ImageFileName);
		createInfo->CreationStatus = STATUS_SUCCESS;
	}
	else
	{
		kprintf("[+] infinityhook: Hips: Process %wZ is not allowed to run.\n", createInfo->ImageFileName);
		createInfo->CreationStatus = STATUS_ACCESS_DENIED;
	}

	FreeSession(Sessions, session);

	ExFreePool(hips);
	ExFreePool(response);
	ExFreePool(session);

	/*if (wcsstr(createInfo->CommandLine->Buffer, L"vadimAmbal") != NULL)
	{
		kprintf("[!] Access to launch notepad.exe was denied!\n");
		Sleep(5000);
		kprintf("[!] Returned!\n");
		createInfo->CreationStatus = STATUS_ACCESS_DENIED;
	}*/
}

void KernelSleep(LONGLONG ms)
{
	LARGE_INTEGER waitTime;
	waitTime.QuadPart = -(ms*10000);   // wait 500000us (500ms) relative
	KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
}
