#include "Hook.h"
#include <intrin.h>

extern "C" PTR_TYPE LStarHookCallback;
extern "C" PTR_TYPE OldLStarEntry;
extern "C" PTR_TYPE LStarHookCallbackParam1;
extern "C" PTR_TYPE LStarHookCallbackParam2;
extern "C" PTR_TYPE LStarHookCallbackParam3;
extern "C" void LStarHookEntry();
extern "C" void _mystac();
extern "C" void
_myclac();

constexpr UINT32 EPT_HOOK_VTXCALL_FUNCTION = 0x400000ff;
constexpr UINT32 ADD_HOOK_VTXCALL_SUBFUNCTION = 0x00000000;
constexpr UINT32 DEL_HOOK_VTXCALL_SUBFUNCTION = 0x00000001;

#pragma code_seg("PAGE")
void SetLStrHookEntryParameters(PTR_TYPE oldEntry, PTR_TYPE pCallback, PTR_TYPE param1, PTR_TYPE param2, PTR_TYPE param3)
{
	PAGED_CODE();
	//���ò���
	LStarHookCallback = pCallback;
	OldLStarEntry = oldEntry;
	LStarHookCallbackParam1 = param1;
	LStarHookCallbackParam2 = param2;
	LStarHookCallbackParam3 = param3;
}

//��ȡLStarHookEntry����������ĵ�ַ��hookʱ��MSR_LSTAR��ʵ�ʵ�ַ
#pragma code_seg("PAGE")
PTR_TYPE GetLStarHookEntry()
{
	PAGED_CODE();
	return (PTR_TYPE)LStarHookEntry;
}

#pragma code_seg()
SIZE_TYPE EptHookData::FindHookRecordByOriginVirtAddr(PTR_TYPE pOriginAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < hookRecords.Length(); ++idx)
	{
		if (hookRecords[idx].pOriginVirtAddr == (PVOID)pOriginAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
SIZE_TYPE EptHookData::FindSmallPageLevel2RefCntByPhyAddr(PTR_TYPE phyAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < smallPageRecord.Length(); ++idx)
	{
		if (smallPageRecord[idx].level3PhyAddr == phyAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
SIZE_TYPE EptHookData::FindSwapPageRefCntByOriginPhyAddr(PTR_TYPE phyAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < swapPageRecord.Length(); ++idx)
	{
		if (swapPageRecord[idx].pOriginPhyAddr == phyAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
SIZE_TYPE EptHookData::FindSwapPageRefCntByOriginVirtAddr(PTR_TYPE pOriginAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < swapPageRecord.Length(); ++idx)
	{
		if (swapPageRecord[idx].pOriginVirtAddr == (PVOID)pOriginAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

SIZE_TYPE EptHookData::FindSwapPageRefCntBySwapVirtAddr(PTR_TYPE pSwapAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < swapPageRecord.Length(); ++idx)
	{
		if (swapPageRecord[idx].pSwapVirtAddr == (PVOID)pSwapAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg("PAGE")
void EptHookManager::SetupVTXManager(VTXManager& vtxManager)
{
	PAGED_CODE();

	//���ó�ʼEPTҳ��
	vtxManager.SetEptpProvider(&pageTableManager1);
	//����EPTV
	vtxManager.SetEptVInterceptPluginsr(this);
	//����BP
	vtxManager.SetBreakpointPlugin(this);
	//����MSR
	vtxManager.SetMsrInterceptPlugin(this);
}

#pragma code_seg()
bool EptHookManager::HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters)
{
	UNREFERENCED_PARAMETER(pGuestRegisters);

	bool result = false;

	const EptHookData& data = hookData[pVirtCpuInfo->otherInfo.cpuIdx];

	//���ƥ�䵽hook��ֱ����ת
	SIZE_TYPE hookIdx = data.FindHookRecordByOriginVirtAddr(pGuestRegisters->rip);

	if (hookIdx != INVALID_INDEX)
	{
		pGuestRegisters->rip = (UINT64)data.hookRecords[hookIdx].pGotoVirtAddr;
		result = true;
	}

	return result;
}

#pragma code_seg()
bool EptHookManager::HandleEptViolation(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters)
{
	UNREFERENCED_PARAMETER(pGuestRegisters);

	bool result = false;

	PHYSICAL_ADDRESS pa = {};
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, (size_t*)&pa.QuadPart);
	EPT_VIOLATION_DATA info = {};
	__vmx_vmread(EXIT_QUALIFICATION, &info.AsUInt64);

	if (info.Fields.PTERead && info.Fields.Execute)
	{
		//ͨ���޸�ִ��Ȩ��ʵ��hook��Ĭ��hookҳ���ִֹ�У����ִ����hookҳ����Ϊִ�е�hookҳ������ִ�У�����ҳ������ִ�У�ִ�г�hookҳ��֮���ٻָ�Ĭ��

		//Ĭ��״̬ʹ���ⲿҳ����Ȩ�������hookʱ�Ѿ��������
		//hookҳ��ִ��ʱʹ���ڲ�ҳ���ڲ�ҳ��Ĭ�Ͻ�ִֹ�У������޸�ִ�е�hook����ִ��
		//����ϴ�ִ�е���hookҳ�棬�ָ��ڲ�ҳ���ӦҳΪ��ִֹ��

		//��ȡCPU IDX
		UINT32 cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

		//��ȡ����EPT HOOK״̬
		EptHookStatus& hookStatus = hookData[cpuIdx].hookStatus;

		//��ȡ��Ӧ�ĺ���ҳ�������
		CoreEptPageTableManager& externalCorePageTableManager = pageTableManager1.GetCoreEptPageTables()[cpuIdx];
		CoreEptPageTableManager& internalCorePageTableManager = pageTableManager2.GetCoreEptPageTables()[cpuIdx];

		SIZE_TYPE swapPageIdx = INVALID_INDEX;
		EptEntry entry = {};

		PTR_TYPE tempPhyAddr = INVALID_ADDR;

		EptHookData& data = hookData[cpuIdx];

		if (hookStatus.pLastActiveHookPageVirtAddr != NULL)
		{
			//���������ַ��ѯ����ҳ��Ŀ
			swapPageIdx = data.FindSwapPageRefCntByOriginVirtAddr(hookStatus.pLastActiveHookPageVirtAddr);

			if (swapPageIdx != INVALID_INDEX)
			{
				//�ָ��ϴ�hookҳ��Ϊ��ִֹ��
				entry.fields.readAccess = true;
				entry.fields.writeAccess = true;
				entry.fields.executeAccess = false;

				tempPhyAddr = data.swapPageRecord[swapPageIdx].pOriginPhyAddr;

				internalCorePageTableManager.ChangePageTableEntryPermession(tempPhyAddr, entry, 1);
			}
		}

		//��ѯ���������ҳ���Ƿ�ΪHOOKҳ��
		swapPageIdx = data.FindSwapPageRefCntByOriginPhyAddr(pa.QuadPart & 0xFFFFFFFFFF000);

		if (swapPageIdx != INVALID_INDEX)
		{
			//����hookҳ���ִ��
			entry.fields.readAccess = true;
			entry.fields.writeAccess = true;
			entry.fields.executeAccess = true;

			internalCorePageTableManager.ChangePageTableEntryPermession(pa.QuadPart, entry, 1);

			//�л����ڲ�ҳ��
			tempPhyAddr = internalCorePageTableManager.GetEptPageTablePa();

			EPT_TABLE_POINTER EPTP = {};

			EPTP.Fields.PhysAddr = tempPhyAddr >> 12;
			EPTP.Fields.PageWalkLength = 3;
			EPTP.Fields.MemoryType = VTX_MEM_TYPE_UNCACHEABLE;

			__vmx_vmwrite(EPT_POINTER, EPTP.AsUInt64);

			//����״̬
			hookStatus.pLastActiveHookPageVirtAddr = (PTR_TYPE)data.swapPageRecord[swapPageIdx].pOriginVirtAddr;
			hookStatus.premissionStatus = EptHookStatus::PremissionStatus::HookPageExecuted;
		}
		else
		{
			//�л����ⲿҳ��
			tempPhyAddr = externalCorePageTableManager.GetEptPageTablePa();

			EPT_TABLE_POINTER EPTP = {};

			EPTP.Fields.PhysAddr = tempPhyAddr >> 12;
			EPTP.Fields.PageWalkLength = 3;
			EPTP.Fields.MemoryType = VTX_MEM_TYPE_UNCACHEABLE;

			__vmx_vmwrite(EPT_POINTER, EPTP.AsUInt64);

			//����״̬
			hookStatus.pLastActiveHookPageVirtAddr = NULL;
			hookStatus.premissionStatus = EptHookStatus::PremissionStatus::HookPageNotExecuted;
		}

		result = true;
	}
	else
	{
		result = pageTableManager1.HandleEptViolation(pVirtCpuInfo, pGuestRegisters) &&
			pageTableManager2.HandleEptViolation(pVirtCpuInfo, pGuestRegisters);
	}

	EPT_CTX ctx = {};
	_invept(INV_ALL_CONTEXTS, &ctx);

	return result;
}

#pragma code_seg("PAGE")
void EptHookManager::SetMsrPremissionMap(RTL_BITMAP& bitmap)
{
	pageTableManager1.SetMsrPremissionMap(bitmap);
}

#pragma code_seg()
NTSTATUS EptHookManager::AddHookInSignleCore(const EptHookRecord& record, UINT32 idx)
{
	NTSTATUS status = STATUS_SUCCESS;
	PTR_TYPE pOriginPhyAddr = MmGetPhysicalAddress(record.pOriginVirtAddr).QuadPart;
	PTR_TYPE pOriginPageVirtAddr = (PTR_TYPE)record.pOriginVirtAddr & 0xfffffffffffff000;
	SIZE_TYPE smallPagIdx = INVALID_INDEX;
	SIZE_TYPE swapPageIdx = INVALID_INDEX;
	SIZE_TYPE hookIdx = INVALID_INDEX;
	UINT8* swapPageVirtAddr = NULL;
	PTR_TYPE swapPagePhyAddr = INVALID_ADDR;
	bool needChangePagePermission = false;

	CoreEptPageTableManager& corePageTableManager1 = pageTableManager1.GetCoreEptPageTables()[idx];
	CoreEptPageTableManager& corePageTableManager2 = pageTableManager2.GetCoreEptPageTables()[idx];

	auto changeToSmallPage = [](CoreEptPageTableManager& pageTableManager, PTR_TYPE pa) -> NTSTATUS
		{
			NTSTATUS status = STATUS_SUCCESS;

			do
			{
				status = pageTableManager.UsingSmallPage(pa, true);

				if (!NT_SUCCESS(status)) break;

				status = pageTableManager.MapSmallPageByPhyAddr(pa, pa + 0x200000);

				if (!NT_SUCCESS(status))
				{
					pageTableManager.UsingSmallPage(pa, false);
					break;
				}

			} while (false);

			return status;
		};

	do
	{
		//���hook��Ŀ�Ƿ����
		hookIdx = hookData[idx].FindHookRecordByOriginVirtAddr((PTR_TYPE)record.pOriginVirtAddr);

		if (hookIdx != INVALID_INDEX)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		hookData[idx].hookRecords.PushBack(record);

		swapPageIdx = hookData[idx].FindSwapPageRefCntByOriginVirtAddr(pOriginPageVirtAddr);

		if (swapPageIdx == INVALID_INDEX)
		{
			swapPageVirtAddr = (UINT8*)AllocExecutableNonPagedMem(PAGE_SIZE, HOOK_TAG);

			if (swapPageVirtAddr == NULL)
			{
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			//��������
			RtlCopyMemory(swapPageVirtAddr, (PVOID)pOriginPageVirtAddr, PAGE_SIZE);
			//д��ϵ�
			swapPageVirtAddr[(PTR_TYPE)record.pOriginVirtAddr & 0xfff] = EptHookCode;

			//���뽻��ҳ����Ŀ
			SwapPageRecord newItem = {};

			newItem.pOriginVirtAddr = (PVOID)pOriginPageVirtAddr;
			newItem.pOriginPhyAddr = MmGetPhysicalAddress(newItem.pOriginVirtAddr).QuadPart;
			newItem.pSwapVirtAddr = swapPageVirtAddr;
			newItem.pSwapPhyAddr = MmGetPhysicalAddress(newItem.pSwapVirtAddr).QuadPart;
			newItem.refCnt = 1;

			swapPagePhyAddr = newItem.pSwapPhyAddr;

			hookData[idx].swapPageRecord.PushBack(newItem);
		}
		else
		{
			SwapPageRecord swapPageRefCnt = {};

			//��ȡ����ҳ����Ŀ
			swapPageRefCnt = hookData[idx].swapPageRecord[swapPageIdx];

			//д��ϵ�
			swapPageVirtAddr = (UINT8*)swapPageRefCnt.pSwapVirtAddr;
			swapPageVirtAddr[(PTR_TYPE)record.pOriginVirtAddr & 0xfff] = EptHookCode;

			//��������
			++hookData[idx].swapPageRecord[swapPageIdx].refCnt;
		}

		//��ȡ����ҳ�������ַ
		swapPagePhyAddr = MmGetPhysicalAddress((PVOID)swapPageVirtAddr).QuadPart;

		//���ý���ҳ��Ӧ��ҳ��ΪСҳ
		//�Ȳ�ѯ�Ƿ�������ΪСҳ�ļ�¼
		smallPagIdx = hookData[idx].FindSmallPageLevel2RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

		if (smallPagIdx == INVALID_INDEX)
		{
			//���û�в�ѯ��ΪСҳ�ļ�¼��������ΪСҳ����������¼
			status = changeToSmallPage(corePageTableManager1, swapPagePhyAddr & 0xFFFFFFFFFFE00000);

			if (!NT_SUCCESS(status))
				break;

			status = changeToSmallPage(corePageTableManager2, swapPagePhyAddr & 0xFFFFFFFFFFE00000);

			if (!NT_SUCCESS(status))
				break;

			SmallPageRecord newItem = {};

			newItem.level3PhyAddr = swapPagePhyAddr & 0xFFFFFFFFFFE00000;
			newItem.refCnt = 1;

			hookData[idx].smallPageRecord.PushBack(newItem);
		}
		else
		{
			++hookData[idx].smallPageRecord[smallPagIdx].refCnt;
		}

		//����ԭʼҳ��Ӧ��ҳ��ΪСҳ
		//�Ȳ�ѯ�Ƿ�������ΪСҳ�ļ�¼

		smallPagIdx = hookData[idx].FindSmallPageLevel2RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

		if (smallPagIdx == INVALID_INDEX)
		{
			//���û�в�ѯ��ΪСҳ�ļ�¼��������ΪСҳ����������¼
			status = changeToSmallPage(corePageTableManager1, pOriginPhyAddr & 0xFFFFFFFFFFE00000);

			if (!NT_SUCCESS(status))
				break;

			status = changeToSmallPage(corePageTableManager2, pOriginPhyAddr & 0xFFFFFFFFFFE00000);

			if (!NT_SUCCESS(status))
				break;

			needChangePagePermission = true;

			SmallPageRecord newItem = {};

			newItem.level3PhyAddr = pOriginPhyAddr & 0xFFFFFFFFFFE00000;

			hookData[idx].smallPageRecord.PushBack(newItem);
		}
		else
		{
			++hookData[idx].smallPageRecord[smallPagIdx].refCnt;
		}

	} while (false);

	if (NT_SUCCESS(status) && needChangePagePermission)
	{
		EptEntry permission = {};

		//����ҳ����
		corePageTableManager2.SwapSmallPagePpn(pOriginPhyAddr, swapPagePhyAddr, 1);

		permission.fields.readAccess = true;
		permission.fields.writeAccess = true;
		permission.fields.executeAccess = false;

		corePageTableManager1.ChangePageTableEntryPermession(pOriginPhyAddr, permission, 1);
	}

	corePageTableManager1.UpdateMemoryType();
	corePageTableManager2.UpdateMemoryType();

	return status;
}

#pragma code_seg()
NTSTATUS EptHookManager::RemoveHookInSignleCore(PVOID pHookOriginVirtAddr, UINT32 idx)
{
	NTSTATUS status = STATUS_SUCCESS;
	PTR_TYPE pOriginPhyAddr = MmGetPhysicalAddress(pHookOriginVirtAddr).QuadPart;
	PTR_TYPE pOriginPageVirtAddr = (PTR_TYPE)pHookOriginVirtAddr & 0xfffffffffffff000;
	SIZE_TYPE smallPagIdx = INVALID_INDEX;
	SIZE_TYPE swapPageIdx = INVALID_INDEX;
	SIZE_TYPE hookIdx = INVALID_INDEX;
	UINT8* swapPageVirtAddr = NULL;
	PTR_TYPE swapPagePhyAddr = INVALID_ADDR;
	EptEntry permission = {};

	CoreEptPageTableManager& corePageTableManager1 = pageTableManager1.GetCoreEptPageTables()[idx];
	CoreEptPageTableManager& corePageTableManager2 = pageTableManager2.GetCoreEptPageTables()[idx];

	do
	{
		//���hook��Ŀ�Ƿ����
		hookIdx = hookData[idx].FindHookRecordByOriginVirtAddr((PTR_TYPE)pHookOriginVirtAddr);

		if (hookIdx == INVALID_INDEX)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		swapPageIdx = hookData[idx].FindSwapPageRefCntByOriginVirtAddr(pOriginPageVirtAddr);

		if (swapPageIdx != INVALID_INDEX)
		{
			SwapPageRecord& record = hookData[idx].swapPageRecord[swapPageIdx];

			swapPageVirtAddr = (UINT8*)record.pSwapVirtAddr;

			//��ԭHOOK
			swapPageVirtAddr[(PTR_TYPE)record.pOriginVirtAddr & 0xfff] = *((UINT8*)record.pOriginVirtAddr);

			if (!(--record.refCnt))
			{
				corePageTableManager2.SwapSmallPagePpn(record.pOriginPhyAddr, record.pSwapPhyAddr, 1);

				//�ͷ��ڴ�
				FreeExecutableNonPagedMem(hookData[idx].swapPageRecord[swapPageIdx].pSwapVirtAddr, HOOK_TAG);

				//ɾ����¼��
				hookData[idx].swapPageRecord.Remove(swapPageIdx);
			}
		}

		//��ȡ����ҳ�������ַ
		swapPagePhyAddr = MmGetPhysicalAddress((PVOID)swapPageVirtAddr).QuadPart;

		//�ݼ��������������Ϊ0�ָ���ҳ�������¼
		smallPagIdx = hookData[idx].FindSmallPageLevel2RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

		if (smallPagIdx != INVALID_INDEX)
		{
			SmallPageRecord& record = hookData[idx].smallPageRecord[smallPagIdx];
			if (!(--record.refCnt))
			{
				corePageTableManager1.UsingSmallPage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, false);
				
				UINT64 entryPermission = pageTableManager2.GetDefaultPermission(2);

				((EptEntry*)&entryPermission)->fields.executeAccess = false;

				pageTableManager2.SetDefaultPermission(entryPermission, 2);

				corePageTableManager2.UsingSmallPage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, false);

				((EptEntry*)&entryPermission)->fields.executeAccess = true;

				pageTableManager2.SetDefaultPermission(entryPermission, 2);

				hookData[idx].smallPageRecord.Remove(smallPagIdx);
			}
		}

		//�ݼ��������������Ϊ0�ָ���ҳ�������¼
		smallPagIdx = hookData[idx].FindSmallPageLevel2RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

		if (smallPagIdx != INVALID_INDEX)
		{
			SmallPageRecord& record = hookData[idx].smallPageRecord[smallPagIdx];
			if (!(--record.refCnt))
			{
				corePageTableManager1.UsingSmallPage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, false);

				UINT64 entryPermission = pageTableManager2.GetDefaultPermission(2);

				((EptEntry*)&entryPermission)->fields.executeAccess = false;

				pageTableManager2.SetDefaultPermission(entryPermission, 2);

				corePageTableManager2.UsingSmallPage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, false);

				((EptEntry*)&entryPermission)->fields.executeAccess = true;

				pageTableManager2.SetDefaultPermission(entryPermission, 2);

				hookData[idx].smallPageRecord.Remove(smallPagIdx);
			}
		}

		hookData[idx].hookRecords.Remove(hookIdx);

	} while (false);

	corePageTableManager1.UpdateMemoryType();
	corePageTableManager2.UpdateMemoryType();

	return status;
}

#pragma code_seg()
bool EptHookManager::HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, UINT32 msrNum)
{
	UNREFERENCED_PARAMETER(pGuestRegisters);

	if (msrNum == IA32_MSR_MTRR_DEF_TYPE || msrNum == IA32_MSR_MTRR_FIX64K_00000 ||
		msrNum == IA32_MSR_MTRR_FIX16K_80000 || msrNum == IA32_MSR_MTRR_FIX16K_A0000 ||
		(msrNum >= IA32_MSR_MTRR_FIX4K_C0000 && msrNum <= IA32_MSR_MTRR_FIX4K_F8000) ||
		(msrNum >= IA32_MSR_MTRR_PHYSBASE0 && msrNum <= IA32_MSR_MTRR_PHYSBASE0 + 511))
	{

		CR0 cr0 = {};
		__vmx_vmread(GUEST_CR0, &cr0.data);

		if (!cr0.fields.cacheDisable)
		{
			(pageTableManager1.GetCoreEptPageTables() + pVirtCpuInfo->otherInfo.cpuIdx)->UpdateMemoryType();
			(pageTableManager2.GetCoreEptPageTables() + pVirtCpuInfo->otherInfo.cpuIdx)->UpdateMemoryType();
		}

		EPT_CTX ctx = {};
		_invept(INV_ALL_CONTEXTS, &ctx);

	}

	return false;
}

#pragma code_seg("PAGE")
NTSTATUS EptHookManager::AddHook(const EptHookRecord& record)
{
	PAGED_CODE();

	auto processor = [&record, this](UINT32 cpuIdx) -> NTSTATUS
		{
			return AddHookInSignleCore(record, cpuIdx);
		};

	auto rollbacker = [&record, this](UINT32 cpuIdx) -> NTSTATUS
		{
			return RemoveHookInSignleCore(record.pOriginVirtAddr, cpuIdx);
		};

	NTSTATUS status = RunOnEachCore(0, KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS), processor);

	if (!NT_SUCCESS(status))
		RunOnEachCore(0, KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS), rollbacker);

	EPT_CTX ctx = {};
	_invept(INV_ALL_CONTEXTS, &ctx);

	return NT_SUCCESS(status) ? status : STATUS_UNSUCCESSFUL;
}

#pragma code_seg("PAGE")
NTSTATUS EptHookManager::RemoveHook(PVOID pHookOriginVirtAddr)
{
	PAGED_CODE();

	auto processor = [pHookOriginVirtAddr, this](UINT32 cpuIdx) -> NTSTATUS
		{
			return RemoveHookInSignleCore(pHookOriginVirtAddr, cpuIdx);
		};

	NTSTATUS status = RunOnEachCore(0, KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS), processor);

	EPT_CTX ctx = {};
	_invept(INV_ALL_CONTEXTS, &ctx);

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS EptHookManager::Init()
{
	PAGED_CODE();

	cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	//hookData.SetCapacity(cpuCnt);
	for (SIZE_T cnt = 0; cnt < cpuCnt; ++cnt)
		hookData.EmplaceBack(static_cast<EptHookData&&>(EptHookData()));

	//��������ҳ��
	NTSTATUS status = pageTableManager1.Init();

	if (!NT_SUCCESS(status))
		return status;

	status = pageTableManager2.Init();

	if (!NT_SUCCESS(status))
		return status;

	//�ڲ�ҳ����ϲ�ҳ��������ִ�е�
	//��ײ�ҳ������ִ��
	//�������л�ĳҳ�浽��2ִ��ʱ������Ϊ�ϲ�ҳ������ִ�ж�����
	EptEntry permission = {};
	permission.fields.readAccess = true;
	permission.fields.writeAccess = true;
	permission.fields.executeAccess = false;

	//��ײ�ҳ������ִ��
	for (SIZE_TYPE idx = 0; idx < pageTableManager2.GetCoreEptPageTablesCnt(); ++idx)
	{
		CoreEptPageTableManager& pCoreEptPageTableManager = pageTableManager2.GetCoreEptPageTables()[idx];

		pCoreEptPageTableManager.ChangeAllEndLevelPageTablePermession(permission);;
	}

	//�����µ�Ĭ��Ȩ��Ϊ����ִ�У���Ϊ���������޸Ļ���������ײ�ҳ����޸�
	pageTableManager2.SetDefaultPermission(permission.data, 1);

	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void EptHookManager::Deinit()
{
	PAGED_CODE();

	for (SIZE_T idx1 = 0; idx1 < hookData.Length(); ++idx1)
	{
		//�ͷ�EPT HOOK �ڴ�
		for (SIZE_TYPE idx2 = 0; idx2 < hookData[idx1].swapPageRecord.Length(); ++idx2)
			FreeExecutableNonPagedMem(hookData[idx1].swapPageRecord[idx2].pSwapVirtAddr, HOOK_TAG);
	}

	hookData.Clear();

	//��������EPTҳ��
	pageTableManager1.Deinit();

	pageTableManager2.Deinit();

	//��ճ�Ա
	cpuCnt = 0;
}


#pragma code_seg()
PVOID FunctionCallerManager::AllocFunctionCallerForHook(PVOID pFunction)
{
	constexpr unsigned char jmpOpCodeTemplate[] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	constexpr SIZE_TYPE jmpAddressOffset = 6;

	static bool isXedInited = false;

	//���xedδ��ʼ������ʼ��xed
	if (!isXedInited) {
		xed_tables_init();
	}

	//����ɺ����ĵ�һ��ָ��ĳ���
	xed_decoded_inst_t xedd;
	xed_state_t dstate = {};

	dstate.mmode = XED_MACHINE_MODE_LONG_64;

	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	xed_error_enum_t result = xed_ild_decode(&xedd, (unsigned char*)pFunction, XED_MAX_INSTRUCTION_BYTES);

	if (result != XED_ERROR_NONE)
		return NULL;

	unsigned int length = xed_decoded_inst_get_length(&xedd);

	//��������hook�е��þɺ�����ָ���
	PVOID pFunctionCaller = AllocExecutableNonPagedMem(length + sizeof jmpOpCodeTemplate, HOOK_TAG);

	if (pFunctionCaller == NULL)
		return NULL;

	RtlCopyMemory(pFunctionCaller, pFunction, length);
	RtlCopyMemory((PCHAR)pFunctionCaller + length, jmpOpCodeTemplate, sizeof jmpOpCodeTemplate);

	PTR_TYPE* pJmpAddress = (PTR_TYPE*)((PCHAR)pFunctionCaller + length + jmpAddressOffset);

	*pJmpAddress = ((PTR_TYPE)pFunction + length);

	return pFunctionCaller;
}

#pragma code_seg()
void FunctionCallerManager::FreeFunctionCallerForHook(PVOID pFunctionCaller)
{
	FreeExecutableNonPagedMem(pFunctionCaller, HOOK_TAG);
}

#pragma code_seg()
SIZE_TYPE FunctionCallerManager::FindFunctionCallerItemBySourceFunction(PVOID pSourceFunction)
{
	SIZE_TYPE callerCnt = functionCallerItems.Length();

	for (SIZE_TYPE idx = 0; idx < callerCnt; ++idx)
	{
		if (pSourceFunction == functionCallerItems[idx].pSourceFunction)
			return idx;
	}

	return INVALID_INDEX;
}

#pragma code_seg()
void FunctionCallerManager::Deinit()
{
	SIZE_TYPE callerCnt = functionCallerItems.Length();

	for (SIZE_TYPE idx = 0; idx < callerCnt; ++idx)
		FreeFunctionCallerForHook(functionCallerItems[idx].pFunctionCaller);

	functionCallerItems.Clear();
}

#pragma code_seg()
PVOID FunctionCallerManager::GetFunctionCaller(PVOID pSourceFunction)
{
	PVOID result = NULL;

	//������û���Ѿ������Caller�ڴ��
	SIZE_TYPE idx = FindFunctionCallerItemBySourceFunction(pSourceFunction);

	//���򷵻أ����򴴽��ٷ���
	if (idx != INVALID_INDEX)
	{
		result = functionCallerItems[idx].pFunctionCaller;
	}
	else
	{
		PVOID pNewFunctionCaller = AllocFunctionCallerForHook(pSourceFunction);

		if (pNewFunctionCaller != NULL)
		{
			FunctionCallerItem newItem = {};
			newItem.pFunctionCaller = pNewFunctionCaller;
			newItem.pSourceFunction = pSourceFunction;

			functionCallerItems.PushBack(newItem);

			result = pNewFunctionCaller;
		}
	}

	return result;
}

#pragma code_seg()
void FunctionCallerManager::RemoveFunctionCaller(PVOID pSourceFunction)
{
	//������û���Ѿ������Caller�ڴ�飬����ɾ����¼���ͷ��ڴ��
	SIZE_TYPE idx = FindFunctionCallerItemBySourceFunction(pSourceFunction);

	if (idx != INVALID_INDEX)
	{
		FreeFunctionCallerForHook(functionCallerItems[idx].pFunctionCaller);
		functionCallerItems.Remove(idx);
	}
}
