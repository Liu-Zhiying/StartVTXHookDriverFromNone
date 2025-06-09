#ifndef HOOK_H
#define HOOK_H

#include "Basic.h"
#include "VTX.h"
#include "PageTable.h"
#include "CasLockers.h"
#include <intrin.h>

bool SetRegsThenVTXCallWrapper(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx);

//����MSR HOOK������CPUID��Function
constexpr UINT32 CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION = 0x400000fe;
constexpr UINT32 READ_MSR_VTXCALL_SUBFUNCTION = 0x00000000;
constexpr UINT32 WRITE_MSR_VTXCALL_SUBFUNCTION = 0x00000001;
constexpr UINT32 GET_CPU_IDX_VTXCALL_SUBFUNCTION = 0x00000002;

constexpr UINT32 HOOK_TAG = MAKE_TAG('h', 'o', 'o', 'k');

//int 3 opcode
constexpr UINT32 EptHookCode = 0xCC;

//һЩ���� VMM CPUID�����ܵĲ�������
struct MsrHookParameter
{
	//MSR ���
	UINT32 msrNum;
	//�Ƿ�����HOOK�������Ǻ��������������Ӧ�ĺ����Ƿ�����hook
	bool* coreHookEnabled;
	//Fake value ֵ�����ָ�룬�����Ǻ�������
	PTR_TYPE* pFakeValues;
	//Guest Real value ֵ�����ָ�룬�����Ǻ�������
	PTR_TYPE* pGuestRealValues;
	//Host Real value ֵ�����ָ�룬�����Ǻ������������MSR��Virtualized MSR����ֵΪNULL
	PTR_TYPE* pHostRealValues;
};

//��ЧMSR��ų���
const UINT32 INVALID_MSRNUM = (UINT32)-1;

//HOOK MSR_LSTAR �ĺ���ԭ�ͣ�GenericRegisters �� extraInfo1 �� �û�̬ rsp ��ַ
typedef void(*pLStarHookCallback)(GenericRegisters* pRegisters, PVOID param1, PVOID param2, PVOID param3);

//READ_MSR_CPUID_SUBFUNCTION �� WRITE_MSR_CPUID_SUBFUNCTION �Ĳ���
struct MsrOperationParameter
{
	//MSR ���
	UINT32 msrNum;
	//MSR ֵ���ڴ��ַ
	PTR_TYPE* pValueInOut;
};

//MSR HOOK ��������msrHookCount����ҪHook��MSR�ĸ���
template<SIZE_TYPE msrHookCount>
class MsrHookManager : public IManager, public IMsrInterceptPlugin, public IVmCallInterceptPlugin, public IMsrBackupRestorePlugin
{
private:
	template<SIZE_TYPE msrCnt>
	friend void EnableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager, pLStarHookCallback pCallback, PVOID param1, PVOID param2, PVOID param3);
	//�ж�MSR�Ƿ���VMCB�����ֶΣ�֧��MSR�����⻯
	static bool IsVirtualizedMsr(UINT32 msrNum)
	{
		static constexpr UINT32 VIRTUALIZED_MSRS[] =
		{
			IA32_MSR_EFER,
			IA32_MSR_PAT,
			IA32_MSR_FS_BASE,
			IA32_MSR_GS_BASE,
			IA32_MSR_SYSENTER_CS,
			IA32_MSR_SYSENTER_ESP,
			IA32_MSR_SYSENTER_EIP,
		};

		for (UINT32 virtualizedMsr : VIRTUALIZED_MSRS)
			if (virtualizedMsr == msrNum)
				return true;

		return false;
	}

	//ͨ��MSR��Ų��Ҷ�Ӧ������
	MsrHookParameter* FindHookParameter(UINT32 msrNum)
	{
		for (MsrHookParameter& param : parameters)
			if (param.msrNum == msrNum)
				return &param;
		return NULL;
	}

	//MSR HOOK ֵ����
	MsrHookParameter parameters[msrHookCount];
	//�Ƿ��Ѿ���ʼ��
	bool inited;
	//CPO���ĸ���
	ULONG cpuCnt;
	//��
	ReadWriteLock locker;
public:
	MsrHookManager();
	//����ÿ��Ҫhook��msr�ı��
	void SetHookMsrs(UINT32(&msrNums)[msrHookCount]);
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) override;
	virtual bool HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		UINT32 msrNum) override;
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		UINT32 msrNum) override;
	virtual bool HandleVmCall(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) override;
	//���� msr hook��msrNum�����ţ�realValue ������ʵֵ��֮���msr�Ķ�д��������ƭֵ���ڴ��У�����Ӱ����ʵֵ��ֻ�Ե�ǰ������Ч��
	void EnableMsrHook(UINT32 msrNum, PTR_TYPE realValue);
	//���� msr hook��writeFakeValueToMsr�����Ƿ���ƭֵд��msr�Ի�ԭmsr��ֻ�Ե�ǰ������Ч��
	void DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr = true);

	//���غͱ���guest��MSR
	virtual void LoadGuestMsrForCpu(UINT32 cpuIdx) override;
	virtual void SaveGuestMsrForCpu(UINT32 cpuIdx) override;

	//���غͱ���host��MSR
	virtual void LoadHostMsrForCpu(UINT32 cpuIdx) override;
	virtual void SaveHostMsrForCpu(UINT32 cpuIdx) override;

	#pragma code_seg("PAGE")
	virtual ~MsrHookManager() { PAGED_CODE(); Deinit(); }
};

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
MsrHookManager<msrHookCount>::MsrHookManager() : inited(false), cpuCnt(0)
{
	PAGED_CODE();
	//��msr����Ĭ��ֵ
	RtlZeroMemory(&parameters, sizeof parameters);
	for (MsrHookParameter& param : parameters)
		param.msrNum = INVALID_MSRNUM;
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
void MsrHookManager<msrHookCount>::SetHookMsrs(UINT32(&msrNums)[msrHookCount])
{
	PAGED_CODE();
	for (SIZE_TYPE idx = 0; idx < msrHookCount; ++idx)
		parameters[idx].msrNum = msrNums[idx];
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
NTSTATUS MsrHookManager<msrHookCount>::Init()
{
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;
	if (!inited)
	{
		inited = true;

		//��ȡCPU������
		cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
		//Ϊÿ��Ҫhook��msr����ֵ���ݿռ�
		for (MsrHookParameter& param : parameters)
		{
			param.pFakeValues = (PTR_TYPE*)AllocNonPagedMem(sizeof * param.pFakeValues * cpuCnt, HOOK_TAG);
			if (param.pFakeValues == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(param.pFakeValues, sizeof * param.pFakeValues * cpuCnt);

			param.coreHookEnabled = (bool*)AllocNonPagedMem(sizeof * param.coreHookEnabled * cpuCnt, HOOK_TAG);
			if (param.coreHookEnabled == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(param.coreHookEnabled, sizeof * param.coreHookEnabled * cpuCnt);

			param.pGuestRealValues = (PTR_TYPE*)AllocNonPagedMem(sizeof * param.pGuestRealValues * cpuCnt, HOOK_TAG);
			if (param.pGuestRealValues == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(param.pGuestRealValues, sizeof * param.pGuestRealValues * cpuCnt);

			if (!IsVirtualizedMsr(param.msrNum))
			{
				param.pHostRealValues = (PTR_TYPE*)AllocNonPagedMem(sizeof * param.pHostRealValues * cpuCnt, HOOK_TAG);
				if (param.pHostRealValues == NULL)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				RtlZeroMemory(param.pHostRealValues, sizeof * param.pHostRealValues * cpuCnt);
			}
			else
			{
				param.pHostRealValues = NULL;
			}
		}

		if (!NT_SUCCESS(status))
			Deinit();
	}
	return status;
}

#pragma code_seg("PAGE")
template <SIZE_TYPE msrHookCount>
void MsrHookManager<msrHookCount>::Deinit()
{
	PAGED_CODE();
	if (inited)
	{
		auto coreAction = [this](UINT32 coreIndex) -> NTSTATUS
			{
				MsrOperationParameter optParam = {};
				for (MsrHookParameter& param : parameters)
				{
					if (param.coreHookEnabled[coreIndex])
					{
						optParam.msrNum = param.msrNum; 
						optParam.pValueInOut = &param.pFakeValues[coreIndex];

						PTR_TYPE regs[] = { CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION, param.msrNum, WRITE_MSR_VTXCALL_SUBFUNCTION, (PTR_TYPE)&optParam };
						SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);

						param.coreHookEnabled[coreIndex] = false;
					}
				}
				return STATUS_SUCCESS;
			};

		//��д��ƭֵ��ÿ�����ĵ�MSR
		RunOnEachCore(0, cpuCnt, coreAction);

		//�ͷ��ڴ�
		for (MsrHookParameter param : parameters)
		{
			if (param.pFakeValues != NULL)
			{
				FreeNonPagedMem(param.pFakeValues, HOOK_TAG);
				param.pFakeValues = NULL;
			}

			if (param.coreHookEnabled != NULL)
			{
				FreeNonPagedMem(param.coreHookEnabled, HOOK_TAG);
				param.coreHookEnabled = NULL;
			}

			if (param.pHostRealValues != NULL)
			{
				FreeNonPagedMem(param.pHostRealValues, HOOK_TAG);
				param.pHostRealValues = NULL;
			}

			if (param.pGuestRealValues != NULL)
			{
				FreeNonPagedMem(param.pGuestRealValues, HOOK_TAG);
				param.pGuestRealValues = NULL;
			}
		}
		//��ճ�Ա
		cpuCnt = 0;

		inited = false;
	}
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::SetMsrPremissionMap(RTL_BITMAP& bitmap)
{
	PAGED_CODE();
	constexpr UINT32 LOW_MSR_READ_BYTE_OFFSET = 0;
	constexpr UINT32 HIGH_MSR_READ_BYTE_OFFSET = 1024;
	constexpr UINT32 LOW_MSR_WRITE_BYTE_OFFSET = 2048;
	constexpr UINT32 HIGH_MSR_WRITE_BYTE_OFFSET = 3072;
	constexpr UINT32 BITS_PER_BYTE = 8;
	constexpr UINT32 HIGH_MSR_BASE = 0xC0000000;

	//����Ҫhook��msr�������msr permission map
	for (const MsrHookParameter& param : parameters)
	{
		UINT32 msrpmOffset = 0;
		if (param.msrNum < HIGH_MSR_BASE)
		{
			msrpmOffset = LOW_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + param.msrNum;
			RtlSetBit(&bitmap, msrpmOffset);
			msrpmOffset = LOW_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + param.msrNum;
			RtlSetBit(&bitmap, msrpmOffset);
		}
		else
		{
			msrpmOffset = HIGH_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + param.msrNum - HIGH_MSR_BASE;
			RtlSetBit(&bitmap, msrpmOffset);
			msrpmOffset = HIGH_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + param.msrNum - HIGH_MSR_BASE;
			RtlSetBit(&bitmap, msrpmOffset);
		}
	}
}

#pragma code_seg()
template<SIZE_TYPE msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
	UINT32 msrNum)
{
	UNREFERENCED_PARAMETER(pVirtCpuInfo);

	bool handled = false;

	locker.ReadLock();

	UINT32 cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

	for (MsrHookParameter& param : parameters)
	{
		//MSR Hook������MSR���ƥ���򷵻���ƭֵ
		if (msrNum == param.msrNum && param.coreHookEnabled[cpuIdx])
		{
			LARGE_INTEGER value = {};
			value.QuadPart = param.pFakeValues[cpuIdx];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rax) = value.LowPart;
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rdx) = value.HighPart;
			JumpToNextInstruction(pGuestRegisters->rip);
			handled = true;
			break;
		}
	}

	locker.ReadUnlock();

	return handled;
}

#pragma code_seg()
template<SIZE_TYPE msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
	UINT32 msrNum)
{
	UNREFERENCED_PARAMETER(pVirtCpuInfo);

	bool handled = false;

	locker.ReadLock();

	UINT32 cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

	for (MsrHookParameter param : parameters)
	{
		//MSR Hook������MSR���ƥ���򱣴���ֵΪ��ƭֵ
		if (msrNum == param.msrNum && param.coreHookEnabled[cpuIdx])
		{
			LARGE_INTEGER value = {};
			value.LowPart = (UINT32)pGuestRegisters->rax;
			value.HighPart = (UINT32)pGuestRegisters->rdx;
			param.pFakeValues[cpuIdx] = value.QuadPart;
			JumpToNextInstruction(pGuestRegisters->rip);
			handled = true;
			break;
		}
	}

	locker.ReadUnlock();

	return handled;
}

#pragma code_seg()
template<SIZE_TYPE msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleVmCall(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters)
{
	//eaxΪ����MSR HOOK��CPUID���
	if (((int)pGuestRegisters->rax) == CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION)
	{
		bool handled = false;
		MsrOperationParameter* pOptParam = (MsrOperationParameter*)pGuestRegisters->rdx;

		switch ((int)pGuestRegisters->rcx)
		{
		//rdx -> in/out MsrOperationParameter
		case READ_MSR_VTXCALL_SUBFUNCTION:
		{
			/*
			IA32_MSR_EFER
			IA32_MSR_PAT
			IA32_MSR_FS_BASE
			IA32_MSR_GS_BASE
			IA32_MSR_SYSENTER_CS
			IA32_MSR_SYSENTER_ESP
			IA32_MSR_SYSENTER_EIP
			��Щmsr�Ĵ�������VMCS���������Դ�VMCB�ж�ȡ
			����msr��ֱ�Ӷ�
			*/

			MsrHookParameter* pHookParameter = FindHookParameter(pOptParam->msrNum);

			switch (pOptParam->msrNum)
			{
			case IA32_MSR_EFER:
				__vmx_vmread(GUEST_IA32_EFER, pOptParam->pValueInOut);
				break;
			case IA32_MSR_PAT:
				__vmx_vmread(GUEST_IA32_PAT, pOptParam->pValueInOut);
				break;
			case IA32_MSR_FS_BASE:
				__vmx_vmread(GUEST_FS_BASE, pOptParam->pValueInOut);
				break;
			case IA32_MSR_GS_BASE:
				__vmx_vmread(GUEST_GS_BASE, pOptParam->pValueInOut);
				break;
			case IA32_MSR_SYSENTER_CS:
				__vmx_vmread(GUEST_SYSENTER_CS, pOptParam->pValueInOut);
				break;
			case IA32_MSR_SYSENTER_ESP:
				__vmx_vmread(GUEST_SYSENTER_ESP, pOptParam->pValueInOut);
				break;
			case IA32_MSR_SYSENTER_EIP:
				__vmx_vmread(GUEST_SYSENTER_EIP, pOptParam->pValueInOut);
				break;
			default:
				//����ǵ�¼hook��msr�����guest msr��¼����ȡ��
				if (pHookParameter != NULL)
				{
					*pOptParam->pValueInOut = pHookParameter->pGuestRealValues[pVirtCpuInfo->otherInfo.cpuIdx];
				}
				//���MSR���û�еǼ�HOOK��ֱ������
				else
				{
					__debugbreak();
					KeBugCheck(MANUALLY_INITIATED_CRASH);
				}
				break;
			}

			JumpToNextInstruction(pGuestRegisters->rip);

			handled = true;

			break;
		}
		//rdx -> in/out MsrOperationParameter
		case WRITE_MSR_VTXCALL_SUBFUNCTION:
		{
			/*
			IA32_MSR_EFER
			IA32_MSR_PAT
			IA32_MSR_FS_BASE
			IA32_MSR_GS_BASE
			IA32_MSR_SYSENTER_CS
			IA32_MSR_SYSENTER_ESP
			IA32_MSR_SYSENTER_EIP
			��Щmsr�Ĵ�������VMCS����������ֱ��д��VMCB
			����msr��ֱ��д
			*/

			MsrHookParameter* pHookParameter = FindHookParameter(pOptParam->msrNum);

			switch (pOptParam->msrNum)
			{
			case IA32_MSR_EFER:
				__vmx_vmwrite(GUEST_IA32_EFER, *pOptParam->pValueInOut);
				break;
			case IA32_MSR_PAT:
				__vmx_vmwrite(GUEST_IA32_PAT, *pOptParam->pValueInOut);
				break;
			case IA32_MSR_FS_BASE:
				__vmx_vmwrite(GUEST_FS_BASE, *pOptParam->pValueInOut);
				break;
			case IA32_MSR_GS_BASE:
				__vmx_vmwrite(GUEST_GS_BASE, *pOptParam->pValueInOut);
				break;
			case IA32_MSR_SYSENTER_CS:
				__vmx_vmwrite(GUEST_SYSENTER_CS, *pOptParam->pValueInOut);
				break;
			case IA32_MSR_SYSENTER_ESP:
				__vmx_vmwrite(GUEST_SYSENTER_ESP, *pOptParam->pValueInOut);
				break;
			case IA32_MSR_SYSENTER_EIP:
				__vmx_vmwrite(GUEST_SYSENTER_EIP, *pOptParam->pValueInOut);
				break;
			default:
				//����ǵ�¼hook��msr����д��guest msr��¼���棬��vmm����ʱ��Ч
				if (pHookParameter != NULL)
				{
					pHookParameter->pGuestRealValues[pVirtCpuInfo->otherInfo.cpuIdx] = *pOptParam->pValueInOut;
				}
				//���MSR���û�еǼ�HOOK��ֱ������
				else
				{
					__debugbreak();
					KeBugCheck(MANUALLY_INITIATED_CRASH);
				}
				break;
			}

			JumpToNextInstruction(pGuestRegisters->rip);

			handled = true;

			break;
		}
		//rbx -> out CpuIdx
		case GET_CPU_IDX_VTXCALL_SUBFUNCTION:
		{
			//���ص�ǰCPU������
			pGuestRegisters->rbx = pVirtCpuInfo->otherInfo.cpuIdx;

			JumpToNextInstruction(pGuestRegisters->rip);

			handled = true;
			break;
		}
		default:
			break;
		}

		return handled;
	}
	return false;
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::EnableMsrHook(UINT32 msrNum, PTR_TYPE realValue)
{
	PAGED_CODE();
	locker.WriteLock();

	UINT32 cpuIdx;
	PTR_TYPE regs[4] = {};

	regs[0] = CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION;
	regs[1] = 0;
	regs[2] = GET_CPU_IDX_VTXCALL_SUBFUNCTION;
	regs[3] = 0;

	SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);

	cpuIdx = (UINT32)regs[1];

	MsrOperationParameter optParam = {};

	for (MsrHookParameter& param : parameters)
	{
		if (param.msrNum == msrNum && !param.coreHookEnabled[cpuIdx])
		{
			optParam.msrNum = param.msrNum;

			optParam.pValueInOut = &param.pFakeValues[cpuIdx];

			regs[0] = CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION;
			regs[1] = 0;
			regs[2] = READ_MSR_VTXCALL_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&optParam;
			SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);

			optParam.pValueInOut = &realValue;

			regs[0] = CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION;
			regs[1] = 0;
			regs[2] = WRITE_MSR_VTXCALL_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&optParam;
			SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);

			param.coreHookEnabled[cpuIdx] = true;
		}
	}

	locker.WriteUnlock();
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr)
{
	PAGED_CODE();
	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};
	MsrOperationParameter optParam = {};

	locker.WriteLock();

	UINT32 cpuIdx;
	PTR_TYPE regs[4] = {};

	regs[0] = CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION;
	regs[1] = 0;
	regs[2] = GET_CPU_IDX_VTXCALL_SUBFUNCTION;
	regs[3] = 0;

	SetRegsThenVTXCall(&regs[0], &regs[1], &regs[2], &regs[3]);

	cpuIdx = (UINT32)regs[1];

	MsrOperationParameter optParam = {};

	for (MsrHookParameter& param : parameters)
	{
		if (param.msrNum == msrNum && param.coreHookEnabled[cpuIdx])
		{
			optParam.msrNum = param.msrNum;
			optParam.pValueInOut = &param.pFakeValues[cpuIdx];

			if (writeFakeValueToMsr)
			{
				regs[0] = CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION;
				regs[1] = 0;
				regs[2] = WRITE_MSR_VTXCALL_SUBFUNCTION;
				regs[3] = (PTR_TYPE)&optParam;
				SetRegsThenVTXCall(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
			
			param.coreHookEnabled[cpuIdx] = false;
		}
	}

	locker.WriteUnlock();
}

template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::LoadGuestMsrForCpu(UINT32 cpuIdx)
{
	for (MsrHookParameter& param : parameters)
	{
		if (param.pGuestRealValues != NULL)
			__writemsr(param.msrNum, param.pGuestRealValues[cpuIdx]);
	}
}

template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::SaveGuestMsrForCpu(UINT32 cpuIdx)
{
	for (MsrHookParameter& param : parameters)
	{
		if (param.pGuestRealValues != NULL)
			param.pGuestRealValues[cpuIdx] = __readmsr(param.msrNum);
	}
}

template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::LoadHostMsrForCpu(UINT32 cpuIdx)
{
	for (MsrHookParameter& param : parameters)
	{
		if (param.pHostRealValues != NULL)
			__writemsr(param.msrNum, param.pHostRealValues[cpuIdx]);
	}
}

template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::SaveHostMsrForCpu(UINT32 cpuIdx)
{
	for (MsrHookParameter& param : parameters)
	{
		if (param.pHostRealValues != NULL)
			param.pHostRealValues[cpuIdx] = __readmsr(param.msrNum);
	}
}

//MSR_LSTAR HOOK ��������������HOOK
//����IA32_MSR_LSTAR HOOK ʹ��֮ǰ��Ҫ����MsrHookManager::SetHookMsrsע��IA32_MSR_LSTAR
#pragma code_seg("PAGE")
template<SIZE_TYPE msrCnt>
void EnableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager, pLStarHookCallback pCallback, PVOID param1, PVOID param2, PVOID param3)
{
	PAGED_CODE();
	extern void SetLStrHookEntryParameters(PTR_TYPE oldEntry, PTR_TYPE pCallback, PTR_TYPE param1, PTR_TYPE param2, PTR_TYPE param3);
	extern PTR_TYPE GetLStarHookEntry();

	MsrOperationParameter optParam = {};
	PTR_TYPE pOldEntry = NULL;
	optParam.msrNum = IA32_MSR_LSTAR;
	optParam.pValueInOut = &pOldEntry;

	PTR_TYPE regs[] = { CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION, IA32_MSR_LSTAR, READ_MSR_VTXCALL_SUBFUNCTION, (PTR_TYPE)&optParam };

	SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);

	SetLStrHookEntryParameters((PTR_TYPE)pOldEntry, (PTR_TYPE)pCallback, (PTR_TYPE)param1, (PTR_TYPE)param2, (PTR_TYPE)param3);

	auto enableHook = [pMsrHookManager](UINT32 cpuIdx) -> NTSTATUS
		{
			UNREFERENCED_PARAMETER(cpuIdx);
			pMsrHookManager->EnableMsrHook(IA32_MSR_LSTAR, (PTR_TYPE)GetLStarHookEntry());
			return STATUS_SUCCESS;
		};

	RunOnEachCore(0, pMsrHookManager->cpuCnt, enableHook);
}

//MSR_LSTAR HOOK ��������������HOOK
#pragma code_seg("PAGE")
template<SIZE_TYPE msrCnt>
void DisableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager)
{
	PAGED_CODE();

	auto disableHook = [pMsrHookManager](UINT32 cpuIdx) -> NTSTATUS
		{
			UNREFERENCED_PARAMETER(cpuIdx);
			pMsrHookManager->DisableMsrHook(IA32_MSR_LSTAR);
			return STATUS_SUCCESS;
		};

	RunOnEachCore(0, pMsrHookManager->cpuCnt, disableHook);
}

//ҳ��Level3��Сҳ�ļ�¼��������Ϊ0������Իָ���ҳ
struct SmallPageRecord
{
	//����level 1 2 3ƫ�Ƶĵ������ַ
	PTR_TYPE level3PhyAddr;
	PTR_TYPE refCnt;
#pragma code_seg()
	SmallPageRecord() : level3PhyAddr(INVALID_ADDR), refCnt(0) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(SmallPageRecord)
};

//����ҳ�ļ�¼
struct SwapPageRecord
{
	//ԭʼҳ��������ַ
	PVOID pOriginVirtAddr;
	//ԭʼҳ��������ַ
	PTR_TYPE pOriginPhyAddr;
	//�滻ҳ��������ַ
	PVOID pSwapVirtAddr;
	//�滻ҳ��������ַ
	PTR_TYPE pSwapPhyAddr;
	//ʹ�ü���
	PTR_TYPE refCnt = 0;
#pragma code_seg()
	SwapPageRecord() : pOriginVirtAddr(NULL), pOriginPhyAddr(INVALID_ADDR), pSwapVirtAddr(NULL), pSwapPhyAddr(INVALID_ADDR), refCnt(0) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(SwapPageRecord)
};

//hook��Ŀ��¼
struct EptHookRecord
{
	//hookԭʼ�����ַ
	PVOID pOriginVirtAddr;
	//hook����ת��ַ
	PVOID pGotoVirtAddr;
#pragma code_seg()
	EptHookRecord() : pOriginVirtAddr(NULL), pGotoVirtAddr(NULL) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(EptHookRecord)
};

//ÿ�����ĵ�EPT HOOK״̬
struct EptHookStatus
{
	enum PremissionStatus
	{
		HookPageNotExecuted,
		HookPageExecuted
	};
	PremissionStatus premissionStatus;
	PTR_TYPE pLastActiveHookPageVirtAddr;
	//���ļ乲������ݵĿ�����ָ��7

	//���ļ乲������ݻ������ݣ�һ����EptHookManager�У���һ���������ָ��ָ��
	//�޸�HOOKʱ���ȸ���EptHookManager�е����ݣ��ٿ���һ��EptHookManager�У�����������ָ����µ����ָ���У�����������ָ���ֵָ�������
public:
#pragma code_seg()
	EptHookStatus() : premissionStatus(HookPageNotExecuted), pLastActiveHookPageVirtAddr(NULL) {}
};

//EPT HOOK ���ļ乲������ݣ���Ҫ��HOOK��¼��Сҳ��¼������ҳ��¼
class EptHookData
{
public:
	KernelVector<SmallPageRecord, HOOK_TAG> smallPageRecord;
	KernelVector<SwapPageRecord, HOOK_TAG> swapPageRecord;
	KernelVector<EptHookRecord, HOOK_TAG> hookRecords;
	EptHookStatus hookStatus;

	//ͨ��hook��ԭʼ�����ַ���Ҽ�¼��HookRecord��
	SIZE_TYPE FindHookRecordByOriginVirtAddr(PTR_TYPE pOriginAddr) const;
	//ͨ�������ַ��ֻ����Level 4 3 2����ƫ�ƣ�����Сҳ��¼��SmallPageLevel3RefCnt��
	SIZE_TYPE FindSmallPageLevel2RefCntByPhyAddr(PTR_TYPE phyAddr) const;
	//ͨ��hookԴ�����ַ���ҽ���ҳ��¼��SwapPageRefCnt��
	SIZE_TYPE FindSwapPageRefCntByOriginPhyAddr(PTR_TYPE phyAddr) const;
	//ͨ��hookԴ�����ַ���ҽ���ҳ��¼��SwapPageRefCnt��
	SIZE_TYPE FindSwapPageRefCntByOriginVirtAddr(PTR_TYPE pOriginAddr) const;
	//ͨ������ҳ�������ַ���ҽ�����¼��SwapPageRefCnt��
	SIZE_TYPE FindSwapPageRefCntBySwapVirtAddr(PTR_TYPE pSwapAddr) const;

	EptHookData() = default;
	~EptHookData() = default;

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(EptHookData)
};

class EptHookManager : public IManager, public IBreakprointInterceptPlugin, public IEptVInterceptPlugin, public IMsrInterceptPlugin
{
	//CPU������
	ULONG cpuCnt;
	//���ļ乲������
	KernelVector<EptHookData, HOOK_TAG> hookData;
	//�ⲿҳ���������ָ��
	PageTableManager pageTableManager1;
	//�ڲ�ҳ���������ÿ���������ڲ�ҳ����ⲿҳ��֮���л����ӿ�EPT HOOK���ٶ�
	PageTableManager pageTableManager2;

	//���hook
	NTSTATUS AddHookInSignleCore(const EptHookRecord& record, UINT32 idx);
	//ɾ��hook��pHookOriginVirtAddr��hookλ�õ������ַ
	NTSTATUS RemoveHookInSignleCore(PVOID pHookOriginVirtAddr, UINT32 idx);

	friend class FunctionInterface;

public:
	//����SVMManager
	void SetupVTXManager(VTXManager& vtxManager);
	//HOOK ��ת
	virtual bool HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) override;
	//HOOKҳ��Ȩ���޸�
	virtual bool HandleEptViolation(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) override;
	//�������ص�msr�Ĵ���
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) override;
	//�������ص�msr��ȡ��true�����Ѿ�����false����δ����
#pragma code_seg()
	virtual bool HandleMsrImterceptRead(VirtCpuInfo*, GenericRegisters*, UINT32) override { return false; }
	//�������ص�Msrд�룬true�����Ѿ�����false����δ����
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		UINT32 msrNum) override;
#pragma code_seg("PAGE")
	EptHookManager() : cpuCnt(0) { PAGED_CODE(); }
	//���hook
	NTSTATUS AddHook(const EptHookRecord& record);
	//ɾ��hook��pHookOriginVirtAddr��hookλ�õ������ַ
	NTSTATUS RemoveHook(PVOID pHookOriginVirtAddr);
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
#pragma code_seg("PAGE")
	virtual ~EptHookManager() { PAGED_CODE(); Deinit(); }
};


class FunctionCallerManager : public IManager
{
	//ΪEPT HOOK��ת֮��ĺ�������һ�����Ե���ԭ�������ܵ�ָ���
	static PVOID AllocFunctionCallerForHook(PVOID pFunction);
	//�ͷ�ָ���
	static void FreeFunctionCallerForHook(PVOID pFunctionCaller);

	struct FunctionCallerItem
	{
		PVOID pSourceFunction;
		PVOID pFunctionCaller;

		#pragma code_seg()
		FunctionCallerItem() : pSourceFunction(NULL), pFunctionCaller(NULL) {}

		DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(FunctionCallerItem)
	};

	KernelVector<FunctionCallerItem, HOOK_TAG> functionCallerItems;

	//������û���Ѿ������Caller�ڴ��
	SIZE_TYPE FindFunctionCallerItemBySourceFunction(PVOID pSourceFunction);

public:
	#pragma code_seg()
	FunctionCallerManager() : functionCallerItems() {}

	#pragma code_seg()
	virtual NTSTATUS Init() override { return STATUS_SUCCESS; }
	virtual void Deinit() override;
	#pragma code_seg()
	virtual ~FunctionCallerManager() { Deinit(); }

	PVOID GetFunctionCaller(PVOID pSourceFunction);
	void RemoveFunctionCaller(PVOID pSourceFunction);
};

#endif
