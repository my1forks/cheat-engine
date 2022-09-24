#pragma warning( disable: 4100 4101 4103 4189)

#include "DBKFunc.h"
#include <ntifs.h>
#include <windef.h>
#include "DBKDrvr.h"

#include "deepkernel.h"
#include "processlist.h"
#include "memscan.h"
#include "threads.h"
#include "vmxhelper.h"
#include "debugger.h"
#include "vmxoffload.h"

#include "IOPLDispatcher.h"
#include "interruptHook.h"
#include "ultimap.h"
#include "ultimap2.h"
#include "noexceptions.h"

#include "ultimap2\apic.h"

#define TOBESIGNED 1
#if (AMD64 && TOBESIGNED)
#include "sigcheck.h"
//#pragma comment (lib,"bcrypt.lib")	
//#pragma comment(lib,"ksecdd.lib")			链接器->输入  ksecdd.lib 才有用  上面的是用户层的
#endif


#ifdef CETC
	#include "cetc.h"
#endif


void UnloadDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);


#ifndef AMD64
//no api hooks for x64

//-----NtUserSetWindowsHookEx----- //prevent global hooks
typedef ULONG (NTUSERSETWINDOWSHOOKEX)(
    IN HANDLE hmod,
    IN PUNICODE_STRING pstrLib OPTIONAL,
    IN DWORD idThread,
    IN int nFilterType,
    IN PVOID pfnFilterProc,
    IN DWORD dwFlags
);
NTUSERSETWINDOWSHOOKEX OldNtUserSetWindowsHookEx;
ULONG NtUserSetWindowsHookEx_callnumber;
//HHOOK NewNtUserSetWindowsHookEx(IN HANDLE hmod,IN PUNICODE_STRING pstrLib OPTIONAL,IN DWORD idThread,IN int nFilterType, IN PROC pfnFilterProc,IN DWORD dwFlags);


typedef NTSTATUS (*ZWSUSPENDPROCESS)
(
    IN ULONG ProcessHandle  // Handle to the process
);
ZWSUSPENDPROCESS ZwSuspendProcess;

NTSTATUS ZwCreateThread(
	OUT PHANDLE  ThreadHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	IN HANDLE  ProcessHandle,
	OUT PCLIENT_ID  ClientId,
	IN PCONTEXT  ThreadContext,
	IN PVOID  UserStack,
	IN BOOLEAN  CreateSuspended);

//PVOID GetApiEntry(ULONG FunctionNumber);
#endif





typedef NTSTATUS(*PSRCTNR)(__in PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);
PSRCTNR PsRemoveCreateThreadNotifyRoutine2;

typedef NTSTATUS(*PSRLINR)(__in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);
PSRLINR PsRemoveLoadImageNotifyRoutine2;

UNICODE_STRING  uszDeviceString;
PVOID BufDeviceString=NULL;



void hideme(PDRIVER_OBJECT DriverObject)
{
#ifndef AMD64
	
	typedef struct _MODULE_ENTRY {
	LIST_ENTRY le_mod;
	DWORD  unknown[4];
	DWORD  base;
	DWORD  driver_start;
	DWORD  unk1;
	UNICODE_STRING driver_Path;
	UNICODE_STRING driver_Name;
} MODULE_ENTRY, *PMODULE_ENTRY;

	PMODULE_ENTRY pm_current;

	pm_current =  *((PMODULE_ENTRY*)((DWORD)DriverObject + 0x14)); //eeeeew

	*((PDWORD)pm_current->le_mod.Blink)        = (DWORD) pm_current->le_mod.Flink;
	pm_current->le_mod.Flink->Blink            = pm_current->le_mod.Blink;
	HiddenDriver=TRUE;

#endif
}


int testfunction(int p1,int p2)
{
	DbgPrint("Hello\nParam1=%d\nParam2=%d\n",p1,p2);
	


	return 0x666;
}


void* functionlist[1];
char  paramsizes[1];
int registered=0;

#define DEBUG1
#ifdef DEBUG1
VOID TestPassive(UINT_PTR param)
{
	DbgPrint("passive cpu call for cpu %d\n", KeGetCurrentProcessorNumber());
}


VOID TestDPC(IN struct _KDPC *Dpc, IN PVOID  DeferredContext, IN PVOID  SystemArgument1, IN PVOID  SystemArgument2)
{
	EFLAGS e=getEflags();
	
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"Defered cpu call for cpu %d (Dpc=%p  IF=%d IRQL=%d)\n", KeGetCurrentProcessorNumber(), Dpc, e.IF, KeGetCurrentIrql());
}
#endif

void myunload(PDRIVER_OBJECT p) {
	return STATUS_SUCCESS;
}

ULONG_PTR ipi_worker(ULONG_PTR arg) {
	EFLAGS e = getEflags();

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Defered cpu call for cpu %d (  IF=%d IRQL=%d)\n", KeGetCurrentProcessorNumber(), e.IF, KeGetCurrentIrql());
}

void f(ULONG_PTR param) {
	EFLAGS e = getEflags();

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Defered cpu call for cpu %d (  IF=%d IRQL=%d)\n", KeGetCurrentProcessorNumber(), e.IF, KeGetCurrentIrql());
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath)
{
#if 0		//测试签名相关
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[+] Driver Load\n");
	DriverObject->DriverUnload = myunload;

	NTSTATUS s = SecurityCheck();
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[+] SecurityCheck return %x\n",s);
#endif

#if 1
	//同步
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "dpc同步...\n");
	forEachCpu(TestDPC,NULL,NULL,NULL,NULL);
	//异步
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "dpc异步...\n");
	forEachCpuAsync(TestDPC, NULL, NULL, NULL, NULL);
	//passive 同步
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "passive 同步...\n");
	forEachCpuPassive(f, 0);

	//ipi 
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ipi 同步...\n");
	KeIpiGenericCall(ipi_worker, 0);
#endif

    return STATUS_SUCCESS;
}

//IRP_MJ_CREATE
NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject,
                       IN PIRP Irp)
{
	// Check for SeDebugPrivilege. (So only processes with admin rights can use it)

	LUID sedebugprivUID;
	sedebugprivUID.LowPart=SE_DEBUG_PRIVILEGE;
	sedebugprivUID.HighPart=0;

	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;



	if (SeSinglePrivilegeCheck(sedebugprivUID, UserMode))
	{		
		Irp->IoStatus.Status = STATUS_SUCCESS;
#ifdef AMD64
#ifdef TOBESIGNED	//校验调用进程数字签名
		{
			NTSTATUS s=SecurityCheck();	
			Irp->IoStatus.Status = s; 		
		}
	//	DbgPrint("Returning %x (and %x)\n", Irp->IoStatus.Status, s);
#endif
#endif


	}
	else
	{
		DbgPrint("A process without SeDebugPrivilege tried to open the dbk driver\n");
		Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	}

    Irp->IoStatus.Information=0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}


NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject,
                       IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information=0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}





void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	cleanupDBVM();
	
	if (!debugger_stopDebugging())
	{
		DbgPrint("Can not unload the driver because of debugger\n");
		return; //
	}

	debugger_shutdown();

	ultimap_disable();
	DisableUltimap2();
	UnregisterUltimapPMI();

	clean_APIC_BASE();

	NoExceptions_Cleanup();
	
	if ((CreateProcessNotifyRoutineEnabled) || (ImageNotifyRoutineLoaded)) 
	{
		PVOID x;
		UNICODE_STRING temp;

		RtlInitUnicodeString(&temp, L"PsRemoveCreateThreadNotifyRoutine");
		PsRemoveCreateThreadNotifyRoutine2 = (PSRCTNR)MmGetSystemRoutineAddress(&temp);

		RtlInitUnicodeString(&temp, L"PsRemoveCreateThreadNotifyRoutine");
		PsRemoveLoadImageNotifyRoutine2 = (PSRLINR)MmGetSystemRoutineAddress(&temp);
		
		RtlInitUnicodeString(&temp, L"ObOpenObjectByName");
		x=MmGetSystemRoutineAddress(&temp);
		
		DbgPrint("ObOpenObjectByName=%p\n",x);
			

		if ((PsRemoveCreateThreadNotifyRoutine2) && (PsRemoveLoadImageNotifyRoutine2))
		{
			DbgPrint("Stopping processwatch\n");

			if (CreateProcessNotifyRoutineEnabled)
			{
				DbgPrint("Removing process watch");
#if (NTDDI_VERSION >= NTDDI_VISTASP1)
				PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx,TRUE);
#else
				PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine,TRUE);
#endif

				
				DbgPrint("Removing thread watch");
				PsRemoveCreateThreadNotifyRoutine2(CreateThreadNotifyRoutine);
			}

			if (ImageNotifyRoutineLoaded)
				PsRemoveLoadImageNotifyRoutine2(LoadImageNotifyRoutine);
		}
		else return;  //leave now!!!!!		
	}


	DbgPrint("Driver unloading\n");

    IoDeleteDevice(DriverObject->DeviceObject);

#ifdef CETC
#ifndef CETC_RELEASE
	UnloadCETC(); //not possible in the final build
#endif
#endif

#ifndef CETC_RELEASE
	DbgPrint("DeviceString=%S\n",uszDeviceString.Buffer);
	{
		NTSTATUS r = IoDeleteSymbolicLink(&uszDeviceString);
		DbgPrint("IoDeleteSymbolicLink: %x\n", r);
	}
	ExFreePool(BufDeviceString);
#endif

	CleanProcessList();

	ExDeleteResourceLite(&ProcesslistR);

	RtlZeroMemory(&ProcesslistR, sizeof(ProcesslistR));

#if (NTDDI_VERSION >= NTDDI_VISTA)
	if (DRMHandle)
	{
		DbgPrint("Unregistering DRM handle");
		ObUnRegisterCallbacks(DRMHandle);
		DRMHandle = NULL;
	}
#endif
}
