#ifndef VTX_H
#define VTX_H

#include "Basic.h"
#include "VMCS.h"

// 传入 #VMEXIT 处理函数，用于处理修改guest寄存器状态
// 也用于 进入虚拟化前后的寄存器备份和恢复
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

typedef struct _VMX_FEATURES
{
	ULONG64 SecondaryControls : 1;  // Secondary controls are enabled
	ULONG64 TrueMSRs : 1;           // True VMX MSR values are supported
	ULONG64 EPT : 1;                // EPT supported by CPU
	ULONG64 VPID : 1;               // VPID supported by CPU
	ULONG64 ExecOnlyEPT : 1;        // EPT translation with execute-only access is supported
	ULONG64 InvSingleAddress : 1;   // IVVPID for single address
	ULONG64 VMFUNC : 1;             // VMFUNC is supported
} VMX_FEATURES, * PVMX_FEATURES;

class IMsrInterceptPlugin;
class ICpuidInterceptPlugin;
class IEptVInterceptPlugin;
class VTXManager;

//SVM 每个核心的虚拟化信息
struct VirtCpuInfo
{
	DECLSPEC_ALIGN(PAGE_SIZE) VMCS guestVmcs;
	DECLSPEC_ALIGN(PAGE_SIZE) VMCS hostVmcs;
	DECLSPEC_ALIGN(PAGE_SIZE) struct
	{
		UINT32 isInVirtualizaion;
		VTXManager* pVTXManager;
		ULONG cpuIdx;
		PVOID pEptPageTablePa;
	} otherInfo;
	DECLSPEC_ALIGN(PAGE_SIZE) struct
	{
		GenericRegisters genericRegisters1;
		GenericRegisters genericRegisters2;
		UINT64 originCr0;
		UINT64 originCr4;
	} regsBackup;
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 stack1[KERNEL_STACK_SIZE];
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 stack2[KERNEL_STACK_SIZE];
};

//MSR拦截插件
class IMsrInterceptPlugin
{
public:
	//设置拦截的msr寄存器
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) = 0;
	//处理拦截的msr读取，true代表已经处理，false代表未处理
	virtual bool HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		UINT32 msrNum) = 0;
	//处理拦截的Msr写入，true代表已经处理，false代表未处理
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		UINT32 msrNum) = 0;

#pragma code_seg()
	virtual ~IMsrInterceptPlugin() {}
};

//MSR 备份恢复插件（用于在VMM加载和退出时备份和加载没有在VMCB中存在guest版本的msr）
class IMsrBackupRestorePlugin
{
public:
	//加载和保存guest的MSR
	virtual void LoadGuestMsrForCpu(UINT32 cpuIdx) = 0;
	virtual void SaveGuestMsrForCpu(UINT32 cpuIdx) = 0;

	//加载和保存host的MSR
	virtual void LoadHostMsrForCpu(UINT32 cpuIdx) = 0;
	virtual void SaveHostMsrForCpu(UINT32 cpuIdx) = 0;

	virtual ~IMsrBackupRestorePlugin() {}
};

//CPUID拦截插件
class ICpuidInterceptPlugin
{
public:
	//处理拦截的cpuid指令，true代表已经处理，false代表未处理
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) = 0;
#pragma code_seg()
	virtual ~ICpuidInterceptPlugin() {}
};

//EPT Violiation拦截插件
class IEptVInterceptPlugin
{
public:
	//处理拦截的NPF事件，true代表已经处理，false代表未处理
	virtual bool HandleEptViolation(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) = 0;
#pragma code_seg()
	virtual ~IEptVInterceptPlugin() {}
};

//VmCall拦截插件
class IVmCallInterceptPlugin
{
public:
	//处理拦截的NPF事件，true代表已经处理，false代表未处理
	virtual bool HandleVmCall(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) = 0;
#pragma code_seg()
	virtual ~IVmCallInterceptPlugin() {}
};

//MTF拦截插件
class IMTFInterceptPlugin
{
public:
	//处理拦截的NPF事件，true代表已经处理，false代表未处理
	virtual bool HandleMTF(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) = 0;
#pragma code_seg()
	virtual ~IMTFInterceptPlugin() {}
};

//BP拦截插件
class IBreakprointInterceptPlugin
{
public:
	//处理拦截的BP事件，true代表已经处理，false代表未处理
	virtual bool HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) = 0;
#pragma code_seg()
	virtual ~IBreakprointInterceptPlugin() {}
};

//UD拦截插件
class IInvalidOpcodeInterceptPlugin
{
public:
	//处理拦截的UD事件，true代表已经处理，false代表未处理
	virtual bool HandleInvalidOpcode(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) = 0;
#pragma code_seg()
	virtual ~IInvalidOpcodeInterceptPlugin() {}
};

//DE拦截插件
class ISingleStepInterceptPlugin
{
public:
	//处理拦截的DE事件，true代表已经处理，false代表未处理
	virtual bool HandleSignleStep(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) = 0;
#pragma code_seg()
	virtual ~ISingleStepInterceptPlugin() {}
};

//EPT页表提供接口
class IEptpProvider
{
public:
	//根据CPUID获取对应的NCR3物理地址
	virtual PVOID GetEptpForCore(UINT32 cpuIdx) = 0;
#pragma code_seg()
	virtual ~IEptpProvider() {}
};

//VMCB的msrpmBasePA指向的内容，全局只需要一份
//这个类负责初始化该资源
class MsrPremissionsMapManager : IManager
{
	PVOID pMsrPremissionsMapVirtAddr;
	PVOID pMsrPremissionsMapPhyAddr;
	IMsrInterceptPlugin* pMsrInterceptPlugin;
public:
#pragma code_seg()
	MsrPremissionsMapManager()
		: pMsrPremissionsMapVirtAddr(NULL), pMsrPremissionsMapPhyAddr(NULL), pMsrInterceptPlugin(NULL)
	{
	}
	void SetPlugin(IMsrInterceptPlugin* _pMsrInterceptPlugin) { PAGED_CODE(); pMsrInterceptPlugin = _pMsrInterceptPlugin; }
	virtual NTSTATUS Init() override;
#pragma code_seg()
	PTR_TYPE GetPhyAddress() const { return (PTR_TYPE)pMsrPremissionsMapPhyAddr; }
#pragma code_seg()
	bool IsInited() const { return pMsrPremissionsMapVirtAddr != NULL; }
	virtual void Deinit() override;
#pragma code_seg()
	virtual ~MsrPremissionsMapManager() { MsrPremissionsMapManager::Deinit(); }
};

enum VTXStatus
{
	//初始值，不表示任何信息
	VTXS_UNUSED = 0x0,
	//非INTEL CPU
	VTXS_NONINTELCPU = 0x1,
	//CPU支持SVM
	VTXS_SUPPORTED = 0x2,
	//VT-X已经启用
	VTXS_ENABLED = 0x4,
	//EPT可用
	VTXS_EPT_ENABLED = 0x10,
	//EPT 支持 仅可执行
	VTXS_EPT_EXECUTE_ONLY = 0x20
};

extern "C" void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters);

class VTXManager : public IManager
{
	VirtCpuInfo** pVirtCpuInfo;
	VMX_FEATURES features;
	UINT32 cpuCnt;
	MsrPremissionsMapManager msrPremissionMap;
	IMsrInterceptPlugin* pMsrInterceptPlugin;
	IMsrBackupRestorePlugin* pMsrBackupRestorePlugin;
	ICpuidInterceptPlugin* pCpuIdInterceptPlugin;
	IEptVInterceptPlugin* pEptVInterceptPlugin;
	IBreakprointInterceptPlugin* pBreakpointInterceptPlugin;
	ISingleStepInterceptPlugin* pSingleStepInterceptPlugin;
	IEptpProvider* pEptpProvider;
	IInvalidOpcodeInterceptPlugin* pInvalidOpcodeInterceptPlugin;
	IMTFInterceptPlugin* pMTFInterceptPlugin;
	IVmCallInterceptPlugin* pVmCallInterreptPlugin;
	bool enableSce;

	friend void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters);

public:
	NTSTATUS EnterVirtualization();
	void LeaveVirtualization();
	//请勿调用该函数，这个函数由VMM自动调用
	void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters);
#pragma code_seg("PAGE")
	VTXManager() : pVirtCpuInfo(NULL), cpuCnt(0), pMsrInterceptPlugin(NULL), pCpuIdInterceptPlugin(NULL), pEptVInterceptPlugin(NULL), pEptpProvider(NULL), pBreakpointInterceptPlugin(NULL), pInvalidOpcodeInterceptPlugin(NULL), pSingleStepInterceptPlugin(NULL), enableSce(true), pMsrBackupRestorePlugin(NULL), features({}), pMTFInterceptPlugin(NULL), pVmCallInterreptPlugin(NULL) { PAGED_CODE(); }
#pragma code_seg("PAGE")
	void SetMsrInterceptPlugin(IMsrInterceptPlugin* _pMsrInterceptPlugin) { PAGED_CODE(); pMsrInterceptPlugin = _pMsrInterceptPlugin; }
#pragma code_seg("PAGE")
	IMsrInterceptPlugin* GetMsrInterceptPlugin() { PAGED_CODE(); return pMsrInterceptPlugin; }
#pragma code_seg("PAGE")
	void SetCpuIdInterceptPlugin(ICpuidInterceptPlugin* _pCpuIdInterceptPlugin) { PAGED_CODE(); pCpuIdInterceptPlugin = _pCpuIdInterceptPlugin; }
#pragma code_seg("PAGE")
	ICpuidInterceptPlugin* GetCpuidInterceptPlugin() { PAGED_CODE(); return pCpuIdInterceptPlugin; }
#pragma code_seg("PAGE")
	void SetEptVInterceptPluginsr(IEptVInterceptPlugin* _pNpfInterrceptPlugin) { PAGED_CODE(); pEptVInterceptPlugin = _pNpfInterrceptPlugin; }
#pragma code_seg("PAGE")
	IEptVInterceptPlugin* GetEptVnterceptPlugin() { PAGED_CODE(); return pEptVInterceptPlugin; }
#pragma code_seg("PAGE")
	void SetEptpProvider(IEptpProvider* _provider) { PAGED_CODE(); pEptpProvider = _provider; }
#pragma code_seg("PAGE")
	IEptpProvider* GetCr3Provider() { PAGED_CODE(); return pEptpProvider; }
#pragma code_seg("PAGE")
	void SetBreakpointPlugin(IBreakprointInterceptPlugin* _pBreakpointInterceptPlugin) { PAGED_CODE(); pBreakpointInterceptPlugin = _pBreakpointInterceptPlugin; }
#pragma code_seg("PAGE")
	IBreakprointInterceptPlugin* GetBreakpointPlugin() { PAGED_CODE(); return pBreakpointInterceptPlugin; }
#pragma code_seg("PAGE")
	void SetVmCallPlugin(IVmCallInterceptPlugin* _pVmCallInterceptPlugin) { PAGED_CODE(); pVmCallInterreptPlugin = _pVmCallInterceptPlugin; }
#pragma code_seg("PAGE")
	IVmCallInterceptPlugin* GetVmCallPlugin() { PAGED_CODE(); return pVmCallInterreptPlugin; }
#pragma code_seg("PAGE")
	IMTFInterceptPlugin* GetMTFPlugin() { PAGED_CODE(); return pMTFInterceptPlugin; }
#pragma code_seg("PAGE")
	void SetMTFPlugin(IMTFInterceptPlugin* _pMTFinterceptPlugin) { PAGED_CODE(); pMTFInterceptPlugin = _pMTFinterceptPlugin; }
#pragma code_seg("PAGE")
	IInvalidOpcodeInterceptPlugin* GetInvalidOpcodePlugin() { PAGED_CODE(); return pInvalidOpcodeInterceptPlugin; }
#pragma code_seg("PAGE")
	void SetInvalidOpcodePlugin(IInvalidOpcodeInterceptPlugin* _pInvalidOpcodeInterceptPlugin) { PAGED_CODE(); pInvalidOpcodeInterceptPlugin = _pInvalidOpcodeInterceptPlugin; }
#pragma code_seg("PAGE")
	void SetSingleStepPlugin(ISingleStepInterceptPlugin* _pDebugInterceptPlugin) { PAGED_CODE(); pSingleStepInterceptPlugin = _pDebugInterceptPlugin; }
#pragma code_seg("PAGE")
	ISingleStepInterceptPlugin* GetSingleStepPlugin() { PAGED_CODE(); return pSingleStepInterceptPlugin; }
#pragma code_seg("PAGE")
	void SetMsrBackupRestorePlugin(IMsrBackupRestorePlugin* _pMsrHookPlugin) { PAGED_CODE(); pMsrBackupRestorePlugin = _pMsrHookPlugin; }
#pragma code_seg("PAGE")
	IMsrBackupRestorePlugin* GetMsrBackupRestorePlugin() { PAGED_CODE(); return pMsrBackupRestorePlugin; }
#pragma code_seg("PAGE")
	void EnanbleSce(bool enable) { PAGED_CODE(); enableSce = enable; }
#pragma code_seg("PAGE")
	bool IsSceEnabled() { PAGED_CODE(); return enableSce; }
	static VTXStatus CheckVTX();
	static VMX_FEATURES CheckFeatures();
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
#pragma code_seg("PAGE")
	virtual ~VTXManager() { PAGED_CODE(); VTXManager::Deinit(); }
};

constexpr UINT32 VTX_MEM_TYPE_UNCACHEABLE = 0;
constexpr UINT32 VTX_MEM_TYPE_WRITEBACK = 6;
constexpr UINT32 VTX_MEM_TYPE_INVALID = 0xFF;

typedef struct _VPID_CTX
{
	ULONG64 VPID : 16;      // VPID to effect
	ULONG64 Reserved : 48;      // Reserved
	ULONG64 Address : 64;      // Linear address
} VPID_CTX, * PVPID_CTX;

typedef struct _EPT_CTX
{
	ULONG64 PEPT;
	ULONG64 High;
} EPT_CTX, * PEPT_CTX;

typedef union _MOV_CR_QUALIFICATION
{
	ULONG_PTR AsUInt64;
	struct
	{
		ULONG ControlRegister : 4;
		ULONG AccessType : 2;
		ULONG LMSWOperandType : 1;
		ULONG Reserved1 : 1;
		ULONG Register : 4;
		ULONG Reserved2 : 4;
		ULONG LMSWSourceData : 16;
		ULONG Reserved3;
	} Fields;
} MOV_CR_QUALIFICATION, * PMOV_CR_QUALIFICATION;

typedef enum _INV_TYPE
{
	INV_INDIV_ADDR = 0,  // Invalidate a specific page
	INV_SINGLE_CONTEXT = 1,  // Invalidate one context (specific VPID)
	INV_ALL_CONTEXTS = 2,  // Invalidate all contexts (all VPIDs)
	INV_SINGLE_CONTEXT_RETAIN_GLOBALS = 3   // Invalidate a single VPID context retaining global mappings
} IVVPID_TYPE, INVEPT_TYPE;

typedef union _VTXAccessRight
{
	struct
	{
		UCHAR Flags1;
		UCHAR Flags2;
		UCHAR Flags3;
		UCHAR Flags4;
	} Bytes;
	struct
	{
		USHORT Type : 4;
		USHORT System : 1;
		USHORT Dpl : 2;
		USHORT Present : 1;

		USHORT Reserved1 : 4;
		USHORT Avl : 1;
		USHORT LongMode : 1;
		USHORT DefaultBit : 1;
		USHORT Granularity : 1;

		USHORT Unusable : 1;
		USHORT Reserved2 : 15;
	} Fields;
	ULONG AccessRights;
} VTXAccessRight;


typedef union _EPT_TABLE_POINTER
{
	ULONG64 AsUInt64;
	struct
	{
		ULONG64 MemoryType : 3;         // EPT Paging structure memory type (0 for UC)
		ULONG64 PageWalkLength : 3;     // Page-walk length
		ULONG64 reserved1 : 6;
		ULONG64 PhysAddr : 40;          // Physical address of the EPT PML4 table
		ULONG64 reserved2 : 12;
	} Fields;
} EPT_TABLE_POINTER, * PEPT_TABLE_POINTER;

typedef union
{
	struct
	{
		UINT64 protectionEnable : 1;
		UINT64 monitorCoprocessor : 1;
		UINT64 emulateFpu : 1;
		UINT64 taskSwitched : 1;
		UINT64 extensionType : 1;
		UINT64 numericError : 1;
		UINT64 reserved1 : 10;
		UINT64 writeProtect : 1;
		UINT64 reserved2 : 1;
		UINT64 alignmentMask : 1;
		UINT64 reserved3 : 10;
		UINT64 notWriteThrough : 1;
		UINT64 cacheDisable : 1;
		UINT64 pagingEnable : 1;
		UINT64 reserved4 : 32;
	} fields;

	UINT64 data;
} CR0;

//获取段描述
VTXAccessRight GetSegmentAttribute(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);
//获取段基地址
UINT64 GetSegmentBaseAddress(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);
//获取段limit，后面加一个2是防止和系统函数冲突，可以直接使用系统函数
UINT32 GetSegmentLimit2(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);

//一系列汇编函数
//源代码在SVM_asm.asm里面
//主要都是寄存器读取操作
extern "C" void _mysgdt(UINT64* pBase, UINT16* pLImit);
extern "C" void _mysidt(UINT64* pBase, UINT16* pLImit);
extern "C" void _mysldt(UINT16* pSelector);
extern "C" void _mystr(UINT16* pSelector);
extern "C" UINT16 _cs_selector();
extern "C" UINT16 _ds_selector();
extern "C" UINT16 _es_selector();
extern "C" UINT16 _fs_selector();
extern "C" UINT16 _gs_selector();
extern "C" UINT16 _ss_selector();

//用于备份和还原寄存器上下文
extern "C" void _save_or_load_regs(GenericRegisters* pRegisters);

extern "C" void _invvpid(IVVPID_TYPE type, PVPID_CTX ctx);

extern "C" void _invept(INVEPT_TYPE type, PEPT_CTX ctx);

void JumpToNextInstruction(PTR_TYPE& rip);

#define SAVE_GUEST_STATUS_FROM_REGS(rflags_val, rsp_val, rip_val)																	\
	UINT64 gdtrBase = 0, idtrBase = 0;																								\
	UINT16 gdtrLimit = 0, idtrLimit = 0;																							\
	UINT16 trSelector = 0, ldtrSelector = 0;																						\
	_mysgdt(&gdtrBase, &gdtrLimit);																									\
	_mysidt(&idtrBase, &idtrLimit);																									\
	_mystr(&trSelector);																											\
	_mysldt(&ldtrSelector);																											\
																																	\
	__vmx_vmwrite(GUEST_CS_SELECTOR, _cs_selector());																				\
	__vmx_vmwrite(GUEST_CS_LIMIT, GetSegmentLimit2(_cs_selector(), gdtrBase));														\
	__vmx_vmwrite(GUEST_CS_AR_BYTES, GetSegmentAttribute(_cs_selector(), gdtrBase).AccessRights);									\
	__vmx_vmwrite(GUEST_CS_BASE, GetSegmentBaseAddress(_cs_selector(), gdtrBase));													\
																																	\
	__vmx_vmwrite(GUEST_SS_SELECTOR, _ss_selector());																				\
	__vmx_vmwrite(GUEST_SS_LIMIT, GetSegmentLimit2(_ss_selector(), gdtrBase));														\
	__vmx_vmwrite(GUEST_SS_AR_BYTES, GetSegmentAttribute(_ss_selector(), gdtrBase).AccessRights);									\
	__vmx_vmwrite(GUEST_SS_BASE, GetSegmentBaseAddress(_ss_selector(), gdtrBase));													\
																																	\
	__vmx_vmwrite(GUEST_DS_SELECTOR, _ds_selector());																				\
	__vmx_vmwrite(GUEST_DS_LIMIT, GetSegmentLimit2(_ds_selector(), gdtrBase));														\
	__vmx_vmwrite(GUEST_DS_AR_BYTES, GetSegmentAttribute(_ds_selector(), gdtrBase).AccessRights);									\
	__vmx_vmwrite(GUEST_DS_BASE, GetSegmentBaseAddress(_ds_selector(), gdtrBase));													\
																																	\
	__vmx_vmwrite(GUEST_ES_SELECTOR, _es_selector());																				\
	__vmx_vmwrite(GUEST_ES_LIMIT, GetSegmentLimit2(_es_selector(), gdtrBase));														\
	__vmx_vmwrite(GUEST_ES_AR_BYTES, GetSegmentAttribute(_es_selector(), gdtrBase).AccessRights);									\
	__vmx_vmwrite(GUEST_ES_BASE, GetSegmentBaseAddress(_es_selector(), gdtrBase));													\
																																	\
	__vmx_vmwrite(GUEST_FS_SELECTOR, _fs_selector());																				\
	__vmx_vmwrite(GUEST_FS_LIMIT, GetSegmentLimit2(_fs_selector(), gdtrBase));														\
	__vmx_vmwrite(GUEST_FS_AR_BYTES, GetSegmentAttribute(_fs_selector(), gdtrBase).AccessRights);									\
	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(IA32_MSR_FS_BASE));																		\
																																	\
	__vmx_vmwrite(GUEST_GS_SELECTOR, _gs_selector());																				\
	__vmx_vmwrite(GUEST_GS_LIMIT, GetSegmentLimit2(_gs_selector(), gdtrBase));														\
	__vmx_vmwrite(GUEST_GS_AR_BYTES, GetSegmentAttribute(_gs_selector(), gdtrBase).AccessRights);									\
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(IA32_MSR_GS_BASE));																		\
																																	\
	__vmx_vmwrite(GUEST_TR_SELECTOR, trSelector);																					\
	__vmx_vmwrite(GUEST_TR_LIMIT, GetSegmentLimit2(trSelector, gdtrBase));															\
	__vmx_vmwrite(GUEST_TR_AR_BYTES, GetSegmentAttribute(trSelector, gdtrBase).AccessRights);										\
	__vmx_vmwrite(GUEST_TR_BASE, GetSegmentBaseAddress(trSelector, gdtrBase));														\
																																	\
	__vmx_vmwrite(GUEST_LDTR_SELECTOR, ldtrSelector);																				\
	__vmx_vmwrite(GUEST_LDTR_LIMIT, GetSegmentLimit2(ldtrSelector, gdtrBase));														\
	__vmx_vmwrite(GUEST_LDTR_AR_BYTES, GetSegmentAttribute(ldtrSelector, gdtrBase).AccessRights);									\
	__vmx_vmwrite(GUEST_LDTR_BASE, GetSegmentBaseAddress(ldtrSelector, gdtrBase));													\
																																	\
	__vmx_vmwrite(GUEST_GDTR_BASE, gdtrBase);																						\
	__vmx_vmwrite(GUEST_GDTR_LIMIT, gdtrLimit);																						\
																																	\
	__vmx_vmwrite(GUEST_IDTR_BASE, idtrBase);																						\
	__vmx_vmwrite(GUEST_IDTR_LIMIT, idtrLimit);																						\
																																	\
	__vmx_vmwrite(CR0_READ_SHADOW, __readcr0());																					\
																																	\
	__vmx_vmwrite(GUEST_CR0, __readcr0());																							\
	__vmx_vmwrite(GUEST_CR3, __readcr3());																							\
																																	\
	__vmx_vmwrite(GUEST_CR4, __readcr4());																							\
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0x2000);																						\
	__vmx_vmwrite(CR4_READ_SHADOW, __readcr4() & ~0x2000);																			\
																																	\
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(IA32_MSR_DBGCTRL));																\
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(IA32_MSR_EFER));																		\
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(IA32_MSR_PAT));																			\
																																	\
	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(IA32_MSR_SYSENTER_CS));																\
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(IA32_MSR_SYSENTER_EIP));															\
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(IA32_MSR_SYSENTER_ESP));															\
																																	\
	__vmx_vmwrite(GUEST_DR7, __readdr(7));																							\
																																	\
	__vmx_vmwrite(GUEST_RSP, (rsp_val));																							\
	__vmx_vmwrite(GUEST_RIP, (rip_val));																							\
	__vmx_vmwrite(GUEST_RFLAGS, (rflags_val));																						\

#endif
