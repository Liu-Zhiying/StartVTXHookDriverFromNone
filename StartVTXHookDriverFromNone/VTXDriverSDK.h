#ifndef VTXDRIVERSDK_H
#define VTXDRIVERSDK_H

#ifndef KERNEL_USAGE
#include <Windows.h>
#else
#include <ntddk.h>
#endif

typedef unsigned int UINT32;
typedef unsigned long long PTR_TYPE;
typedef void* PVOID;
#ifndef NULL
#define NULL 0
#endif

//�����������Ҫ�������Ѿ���������ʹ�õ�ĳЩ�ṹ
//����������ڲ���ʵ�ֽӿ�ΪĿ����Ҫ������Щ�ṹ���Ա����ظ�����
#ifndef NOT_DEFINE_PUBLIC_STRUCT

//����Ϊ���ṩ�Ƿ�ҳ��Ĭ�Ͽ������ƶ����캯���������
#define DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(classname)																\
_Pragma("code_seg()")																												\
classname(const classname&) = default;																								\
_Pragma("code_seg()")																												\
classname(classname&&) = default;																									\
_Pragma("code_seg()")																												\
classname& operator=(const classname&) = default;																					\
_Pragma("code_seg()")																												\
classname& operator=(classname&&) = default;

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

struct GenericRegisters
{
	M128A xmm0;
	M128A xmm1;
	M128A xmm2;
	M128A xmm3;
	M128A xmm4;
	M128A xmm5;
	M128A xmm6;
	M128A xmm7;
	M128A xmm8;
	M128A xmm9;
	M128A xmm10;
	M128A xmm11;
	M128A xmm12;
	M128A xmm13;
	M128A xmm14;
	M128A xmm15;
	UINT64 r15;
	UINT64 r14;
	UINT64 r13;
	UINT64 r12;
	UINT64 r11;
	UINT64 r10;
	UINT64 r9;
	UINT64 r8;
	UINT64 rbp;
	UINT64 rsi;
	UINT64 rdi;
	UINT64 rdx;
	UINT64 rcx;
	UINT64 rbx;
	UINT64 rax;
	UINT64 rflags;
	UINT64 rip;
	UINT64 rsp;
	UINT64 extraInfo1;
	UINT64 extraInfo2;
};

#else

#include "Hook.h"

#endif // NOT_DEFINE_PUBLIC_STRCUT

//����������������ת��VMM����
extern "C" void SetRegsThenVTXCall(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx);

bool SetRegsThenVTXCallWrapper(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx);

//����������������Ӧ�ó�����ô����������ܵ�ͷ�ļ�

//���нӿ�ʵ��ͨ�� CPUID ָ���뱾����ͨѶ����ЩCPUID���ڱ�ʶ�ӿ�ID�������벻Ҫֱ����CPUIDָ��ȥ������Щ�ӿ�
//���ͷ�ļ����ṩ�ӿڰ�װ���������Щ�ӿڵİ�װ
constexpr UINT32 CALL_FUNCTION_INTERFACE_VTXCALL_FUNCTION = 0x400000fc;
constexpr UINT32 NEW_FUNCTION_CALLER_VTXCALL_SUBFUNCTION = 0x00000000;
constexpr UINT32 DEL_FUNCTION_CALLER_VTXCALL_SUBFUNCTION = 0x00000001;
constexpr UINT32 ADD_EPT_HOOK_VTXCALL_SUBFUNCTION = 0x00000002;
constexpr UINT32 DEL_EPT_HOOK_VTXCALL_SUBFUNCTION = 0x00000003;

constexpr UINT32 GUEST_CALL_VMM_VTXCALL_FUNCTION = 0x400000ff;
constexpr UINT32 IS_IN_SVM_VTXCALL_SUBFUNCTION = 0x00000001;

class VTXDriverInterface
{
public:
	//ȷ���Ƿ�ΪR0��ַ
	static constexpr bool IsKernelAddress(PVOID address)
	{
		return ((UINT64)address) & 0xffff000000000000;
	}

	//���SVM�����Ƿ����
	static bool IsInVTX()
	{
		PTR_TYPE regs[4] = { GUEST_CALL_VMM_VTXCALL_FUNCTION, 0, IS_IN_SVM_VTXCALL_SUBFUNCTION, 0 };

		SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);

		return *reinterpret_cast<UINT32*>(&regs[0]) == 'IN' &&
			   *reinterpret_cast<UINT32*>(&regs[1]) == 'TEL' &&
			   *reinterpret_cast<UINT32*>(&regs[2]) == 'VTX';
	}

	//���EPT HOOK��Ŀǰ��R0��
	static bool AddEptHook(const EptHookRecord& record)
	{
		if (!IsKernelAddress(record.pGotoVirtAddr) || !IsKernelAddress(record.pOriginVirtAddr))
			return false;

		PTR_TYPE regs[4] = { CALL_FUNCTION_INTERFACE_VTXCALL_FUNCTION, 0, ADD_EPT_HOOK_VTXCALL_SUBFUNCTION, (PTR_TYPE)&record };

		SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);

		return regs[1];
	}

	//ɾ��EPT HOOK��Ŀǰ��R0��
	static void DelEptHook(PVOID pSourceFunction)
	{
		if (!IsKernelAddress(pSourceFunction))
			return;

		PTR_TYPE regs[4] = { CALL_FUNCTION_INTERFACE_VTXCALL_FUNCTION, 0, DEL_EPT_HOOK_VTXCALL_SUBFUNCTION, (PTR_TYPE)pSourceFunction };

		SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);
	}

	//�����������壨Ŀǰ��R0��
	static PVOID AddFunctionCaller(PVOID pOriginFunction)
	{
		if (!IsKernelAddress(pOriginFunction))
			return NULL;

		PTR_TYPE regs[4] = { CALL_FUNCTION_INTERFACE_VTXCALL_FUNCTION, 0, NEW_FUNCTION_CALLER_VTXCALL_SUBFUNCTION, (PTR_TYPE)pOriginFunction };

		SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);

		return (PVOID)regs[1];
	}

	//ɾ���������壨Ŀǰ��R0��
	static void DelFunctionCaller(PVOID pOriginFunction)
	{
		if (!IsKernelAddress(pOriginFunction))
			return;

		PTR_TYPE regs[4] = { CALL_FUNCTION_INTERFACE_VTXCALL_FUNCTION, 0, DEL_FUNCTION_CALLER_VTXCALL_SUBFUNCTION, (PTR_TYPE)pOriginFunction };

		SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);
	}
};

#endif