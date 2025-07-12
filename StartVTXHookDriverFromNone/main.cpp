#include "main.h"

#pragma code_seg("PAGE")
NTSTATUS DriverIOHandler(IN PDEVICE_OBJECT,
	IN PIRP Irp)
{
	PAGED_CODE();
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void UnloadDriver(IN PDRIVER_OBJECT drvObj)
{
	PAGED_CODE();
	PDEVICE_OBJECT devObj = drvObj->DeviceObject;
	if (devObj != NULL)
	{
		UNICODE_STRING symLinkName;
		RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\VTXDriver");
		GlobalManager* pGlobalManager = (GlobalManager*)drvObj->DeviceObject->DeviceExtension;
		//�������DriverEntry�������IoCreateSymbolicLink�Ļ��������
		//��Ϊ����DriverEntry����ʹ�õĳ�������DriverEntryһ��ж����
		IoDeleteSymbolicLink(&symLinkName);
		IoDeleteDevice(devObj);
		CallDestroyer(pGlobalManager);
	}
	KdPrint(("VT-X driver has exited\n"));
}

#pragma code_seg("INIT")
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING)
{
	////��ObRegisterCallbacks����ǩ�����
	//PVOID thisDrvSection = pDriverObject->DriverSection;
	//*((PUINT32)((PUCHAR)thisDrvSection + 0x68)) |= 0x20;

	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
		pDriverObject->MajorFunction[IRP_MJ_CREATE] =
		pDriverObject->MajorFunction[IRP_MJ_READ] =
		pDriverObject->MajorFunction[IRP_MJ_WRITE] = DriverIOHandler;
	pDriverObject->DriverUnload = UnloadDriver;

	UINT32 initStep = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT fdo = NULL;
	GlobalManager* pGlobalManager = NULL;
	UNICODE_STRING devName;
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&devName, L"\\DosDevices\\VTXDriver");
	RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\VTXDriver");

	do
	{
		KdPrint(("DriverEntry(): Starting VT-X Driver\n"));

		status = IoCreateDevice(pDriverObject, sizeof(GlobalManager), &devName, FILE_DEVICE_UNKNOWN,
			0, TRUE, &fdo);
		if (!NT_SUCCESS(status))
			break;
		initStep = 1;

		status = IoCreateSymbolicLink(&symLinkName, &devName);
		if (!NT_SUCCESS(status))
			break;
		initStep = 2;

		//ʹ���豸��չ��ʼ��GlobalManager
		pGlobalManager = ((GlobalManager*)fdo->DeviceExtension);
		CallConstructor(pGlobalManager);

		//����VM
		status = pGlobalManager->Init();
		if (!NT_SUCCESS(status))
			break;
		initStep = 3;

		fdo->Flags |= DO_BUFFERED_IO;
		KdPrint(("DriverEntry(): VT-X Driver Start successfully.\n"));
	} while (0);

	if (!NT_SUCCESS(status))
	{
		CHAR errorInfo[100] = {};
		sprintf(errorInfo, "DriverEntry(): VT-X Driver Init Err, Step: %d, Code: %x\n", initStep, status);
		KdPrint((errorInfo));
		switch (initStep)
		{
		case 3:
			CallDestroyer(pGlobalManager);
		case 2:
			IoDeleteSymbolicLink(&symLinkName);
		case 1:
			IoDeleteDevice(fdo);
		default:
			break;
		}
	}

	return status;
}