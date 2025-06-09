#ifndef HOOK_H
#define HOOK_H

#include "Basic.h"
#include "VTX.h"
#include "PageTable.h"
#include "CasLockers.h"
#include <intrin.h>

bool SetRegsThenVTXCallWrapper(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx);

//配置MSR HOOK参数的CPUID的Function
constexpr UINT32 CONFIGURE_MSR_HOOK_VTXCALL_FUNCTION = 0x400000fe;
constexpr UINT32 READ_MSR_VTXCALL_SUBFUNCTION = 0x00000000;
constexpr UINT32 WRITE_MSR_VTXCALL_SUBFUNCTION = 0x00000001;
constexpr UINT32 GET_CPU_IDX_VTXCALL_SUBFUNCTION = 0x00000002;

constexpr UINT32 HOOK_TAG = MAKE_TAG('h', 'o', 'o', 'k');

//int 3 opcode
constexpr UINT32 EptHookCode = 0xCC;

//一些调用 VMM CPUID处理功能的参数定义
struct MsrHookParameter
{
	//MSR 编号
	UINT32 msrNum;
	//是否启用HOOK，索引是核心索引，代表对应的核心是否启用hook
	bool* coreHookEnabled;
	//Fake value 值数组的指针，索引是核心索引
	PTR_TYPE* pFakeValues;
	//Guest Real value 值数组的指针，索引是核心索引
	PTR_TYPE* pGuestRealValues;
	//Host Real value 值数组的指针，索引是核心索引，如果MSR是Virtualized MSR，此值为NULL
	PTR_TYPE* pHostRealValues;
};

//无效MSR编号常量
const UINT32 INVALID_MSRNUM = (UINT32)-1;

//HOOK MSR_LSTAR 的函数原型，GenericRegisters 的 extraInfo1 是 用户态 rsp 地址
typedef void(*pLStarHookCallback)(GenericRegisters* pRegisters, PVOID param1, PVOID param2, PVOID param3);

//READ_MSR_CPUID_SUBFUNCTION 和 WRITE_MSR_CPUID_SUBFUNCTION 的参数
struct MsrOperationParameter
{
	//MSR 编号
	UINT32 msrNum;
	//MSR 值的内存地址
	PTR_TYPE* pValueInOut;
};

//MSR HOOK 管理器，msrHookCount代表要Hook的MSR的个数
template<SIZE_TYPE msrHookCount>
class MsrHookManager : public IManager, public IMsrInterceptPlugin, public IVmCallInterceptPlugin, public IMsrBackupRestorePlugin
{
private:
	template<SIZE_TYPE msrCnt>
	friend void EnableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager, pLStarHookCallback pCallback, PVOID param1, PVOID param2, PVOID param3);
	//判断MSR是否在VMCB中有字段，支持MSR的虚拟化
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

	//通过MSR编号查找对应的数据
	MsrHookParameter* FindHookParameter(UINT32 msrNum)
	{
		for (MsrHookParameter& param : parameters)
			if (param.msrNum == msrNum)
				return &param;
		return NULL;
	}

	//MSR HOOK 值备份
	MsrHookParameter parameters[msrHookCount];
	//是否已经初始化
	bool inited;
	//CPO核心个数
	ULONG cpuCnt;
	//锁
	ReadWriteLock locker;
public:
	MsrHookManager();
	//设置每个要hook的msr的编号
	void SetHookMsrs(UINT32(&msrNums)[msrHookCount]);
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) override;
	virtual bool HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		UINT32 msrNum) override;
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		UINT32 msrNum) override;
	virtual bool HandleVmCall(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) override;
	//启用 msr hook，msrNum代表编号，realValue 代表真实值，之后对msr的读写都是在欺骗值的内存中，不会影响真实值（只对当前核心有效）
	void EnableMsrHook(UINT32 msrNum, PTR_TYPE realValue);
	//禁用 msr hook，writeFakeValueToMsr代表是否将欺骗值写入msr以还原msr（只对当前核心有效）
	void DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr = true);

	//加载和保存guest的MSR
	virtual void LoadGuestMsrForCpu(UINT32 cpuIdx) override;
	virtual void SaveGuestMsrForCpu(UINT32 cpuIdx) override;

	//加载和保存host的MSR
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
	//给msr参数默认值
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

		//获取CPU核心数
		cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
		//为每个要hook的msr分配值备份空间
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

		//回写欺骗值到每个核心的MSR
		RunOnEachCore(0, cpuCnt, coreAction);

		//释放内存
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
		//清空成员
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

	//根据要hook的msr编号设置msr permission map
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
		//MSR Hook启用且MSR编号匹配则返回欺骗值
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
		//MSR Hook启用且MSR编号匹配则保存新值为欺骗值
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
	//eax为配置MSR HOOK的CPUID编号
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
			这些msr寄存器是由VMCS决定，所以从VMCB中读取
			其他msr则直接读
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
				//如果是登录hook的msr，则从guest msr记录里面取出
				if (pHookParameter != NULL)
				{
					*pOptParam->pValueInOut = pHookParameter->pGuestRealValues[pVirtCpuInfo->otherInfo.cpuIdx];
				}
				//如果MSR编号没有登记HOOK，直接蓝屏
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
			这些msr寄存器是由VMCS决定，所以直接写入VMCB
			其他msr则直接写
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
				//如果是登录hook的msr，则写入guest msr记录里面，在vmm返回时生效
				if (pHookParameter != NULL)
				{
					pHookParameter->pGuestRealValues[pVirtCpuInfo->otherInfo.cpuIdx] = *pOptParam->pValueInOut;
				}
				//如果MSR编号没有登记HOOK，直接蓝屏
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
			//返回当前CPU的索引
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

//MSR_LSTAR HOOK 帮助函数，启用HOOK
//启用IA32_MSR_LSTAR HOOK 使用之前需要调用MsrHookManager::SetHookMsrs注册IA32_MSR_LSTAR
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

//MSR_LSTAR HOOK 帮助函数，禁用HOOK
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

//页表Level3改小页的记录项，如果计数为0，则可以恢复大页
struct SmallPageRecord
{
	//包含level 1 2 3偏移的的物理地址
	PTR_TYPE level3PhyAddr;
	PTR_TYPE refCnt;
#pragma code_seg()
	SmallPageRecord() : level3PhyAddr(INVALID_ADDR), refCnt(0) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(SmallPageRecord)
};

//交换页的记录
struct SwapPageRecord
{
	//原始页面的虚拟地址
	PVOID pOriginVirtAddr;
	//原始页面的物理地址
	PTR_TYPE pOriginPhyAddr;
	//替换页面的虚拟地址
	PVOID pSwapVirtAddr;
	//替换页面的物理地址
	PTR_TYPE pSwapPhyAddr;
	//使用计数
	PTR_TYPE refCnt = 0;
#pragma code_seg()
	SwapPageRecord() : pOriginVirtAddr(NULL), pOriginPhyAddr(INVALID_ADDR), pSwapVirtAddr(NULL), pSwapPhyAddr(INVALID_ADDR), refCnt(0) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(SwapPageRecord)
};

//hook条目记录
struct EptHookRecord
{
	//hook原始虚拟地址
	PVOID pOriginVirtAddr;
	//hook的跳转地址
	PVOID pGotoVirtAddr;
#pragma code_seg()
	EptHookRecord() : pOriginVirtAddr(NULL), pGotoVirtAddr(NULL) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(EptHookRecord)
};

//每个核心的EPT HOOK状态
struct EptHookStatus
{
	enum PremissionStatus
	{
		HookPageNotExecuted,
		HookPageExecuted
	};
	PremissionStatus premissionStatus;
	PTR_TYPE pLastActiveHookPageVirtAddr;
	//核心间共享的数据的拷贝的指针7

	//核心间共享的数据会有两份，一份在EptHookManager中，另一份则由这个指针指向
	//修改HOOK时，先更新EptHookManager中的数据，再拷贝一份EptHookManager中，并将拷贝的指针更新到这个指针中，最后销毁这个指针旧值指向的数据
public:
#pragma code_seg()
	EptHookStatus() : premissionStatus(HookPageNotExecuted), pLastActiveHookPageVirtAddr(NULL) {}
};

//EPT HOOK 核心间共享的数据，主要是HOOK记录、小页记录、交换页记录
class EptHookData
{
public:
	KernelVector<SmallPageRecord, HOOK_TAG> smallPageRecord;
	KernelVector<SwapPageRecord, HOOK_TAG> swapPageRecord;
	KernelVector<EptHookRecord, HOOK_TAG> hookRecords;
	EptHookStatus hookStatus;

	//通过hook的原始虚拟地址查找记录（HookRecord）
	SIZE_TYPE FindHookRecordByOriginVirtAddr(PTR_TYPE pOriginAddr) const;
	//通过物理地址（只带有Level 4 3 2三级偏移）查找小页记录（SmallPageLevel3RefCnt）
	SIZE_TYPE FindSmallPageLevel2RefCntByPhyAddr(PTR_TYPE phyAddr) const;
	//通过hook源物理地址查找交换页记录（SwapPageRefCnt）
	SIZE_TYPE FindSwapPageRefCntByOriginPhyAddr(PTR_TYPE phyAddr) const;
	//通过hook源虚拟地址查找交换页记录（SwapPageRefCnt）
	SIZE_TYPE FindSwapPageRefCntByOriginVirtAddr(PTR_TYPE pOriginAddr) const;
	//通过交换页的虚拟地址查找交换记录（SwapPageRefCnt）
	SIZE_TYPE FindSwapPageRefCntBySwapVirtAddr(PTR_TYPE pSwapAddr) const;

	EptHookData() = default;
	~EptHookData() = default;

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(EptHookData)
};

class EptHookManager : public IManager, public IBreakprointInterceptPlugin, public IEptVInterceptPlugin, public IMsrInterceptPlugin
{
	//CPU核心数
	ULONG cpuCnt;
	//核心间共享数据
	KernelVector<EptHookData, HOOK_TAG> hookData;
	//外部页表管理器的指针
	PageTableManager pageTableManager1;
	//内部页表管理器，每个核心在内部页表和外部页表之间切换，加快EPT HOOK的速度
	PageTableManager pageTableManager2;

	//添加hook
	NTSTATUS AddHookInSignleCore(const EptHookRecord& record, UINT32 idx);
	//删除hook，pHookOriginVirtAddr是hook位置的虚拟地址
	NTSTATUS RemoveHookInSignleCore(PVOID pHookOriginVirtAddr, UINT32 idx);

	friend class FunctionInterface;

public:
	//配置SVMManager
	void SetupVTXManager(VTXManager& vtxManager);
	//HOOK 跳转
	virtual bool HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) override;
	//HOOK页表权限修改
	virtual bool HandleEptViolation(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) override;
	//设置拦截的msr寄存器
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) override;
	//处理拦截的msr读取，true代表已经处理，false代表未处理
#pragma code_seg()
	virtual bool HandleMsrImterceptRead(VirtCpuInfo*, GenericRegisters*, UINT32) override { return false; }
	//处理拦截的Msr写入，true代表已经处理，false代表未处理
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		UINT32 msrNum) override;
#pragma code_seg("PAGE")
	EptHookManager() : cpuCnt(0) { PAGED_CODE(); }
	//添加hook
	NTSTATUS AddHook(const EptHookRecord& record);
	//删除hook，pHookOriginVirtAddr是hook位置的虚拟地址
	NTSTATUS RemoveHook(PVOID pHookOriginVirtAddr);
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
#pragma code_seg("PAGE")
	virtual ~EptHookManager() { PAGED_CODE(); Deinit(); }
};


class FunctionCallerManager : public IManager
{
	//为EPT HOOK跳转之后的函数构造一个可以调用原函数功能的指令块
	static PVOID AllocFunctionCallerForHook(PVOID pFunction);
	//释放指令块
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

	//查找有没有已经分配的Caller内存块
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
