#include "VTX.h"
#include <intrin.h>

bool SetRegsThenVTXCallWrapper(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx);

constexpr UINT32 GUEST_CALL_VMM_VTXCALL_FUNCTION = 0x400000ff;
constexpr UINT32 EXIT_VTX_VTXCALL_SUBFUNCTION = 0x00000000;
constexpr UINT32 IS_IN_VTX_VTXCALL_SUBFUNCTION = 0x00000001;
constexpr UINT32 SVM_TAG = MAKE_TAG('s', 'v', 'm', ' ');
constexpr UINT32 TYPE_MOV_TO_CR = 0;
constexpr UINT32 TYPE_MOV_FROM_CR = 1;

extern "C" void VmEntry();

//
// VMX Exit Reasons

typedef enum _VM_EXIT_REASON
{
	EXIT_REASON_EXCEPTION_NMI = 0,    // Exception or non-maskable interrupt (NMI).
	EXIT_REASON_EXTERNAL_INTERRUPT = 1,    // External interrupt.
	EXIT_REASON_TRIPLE_FAULT = 2,    // Triple fault.
	EXIT_REASON_INIT = 3,    // INIT signal.
	EXIT_REASON_SIPI = 4,    // Start-up IPI (SIPI).
	EXIT_REASON_IO_SMI = 5,    // I/O system-management interrupt (SMI).
	EXIT_REASON_OTHER_SMI = 6,    // Other SMI 
	EXIT_REASON_PENDING_INTERRUPT = 7,    // Interrupt window exiting.
	EXIT_REASON_NMI_WINDOW = 8,    // NMI window exiting.
	EXIT_REASON_TASK_SWITCH = 9,    // Task switch.
	EXIT_REASON_CPUID = 10,   // Guest software attempted to execute CPUID.
	EXIT_REASON_GETSEC = 11,   // Guest software attempted to execute GETSEC.
	EXIT_REASON_HLT = 12,   // Guest software attempted to execute HLT.
	EXIT_REASON_INVD = 13,   // Guest software attempted to execute INVD.
	EXIT_REASON_INVLPG = 14,   // Guest software attempted to execute INVLPG.
	EXIT_REASON_RDPMC = 15,   // Guest software attempted to execute RDPMC.
	EXIT_REASON_RDTSC = 16,   // Guest software attempted to execute RDTSC.
	EXIT_REASON_RSM = 17,   // Guest software attempted to execute RSM in SMM.
	EXIT_REASON_VMCALL = 18,   // Guest software executed VMCALL.
	EXIT_REASON_VMCLEAR = 19,   // Guest software executed VMCLEAR.
	EXIT_REASON_VMLAUNCH = 20,   // Guest software executed VMLAUNCH.
	EXIT_REASON_VMPTRLD = 21,   // Guest software executed VMPTRLD.
	EXIT_REASON_VMPTRST = 22,   // Guest software executed VMPTRST.
	EXIT_REASON_VMREAD = 23,   // Guest software executed VMREAD.
	EXIT_REASON_VMRESUME = 24,   // Guest software executed VMRESUME.
	EXIT_REASON_VMWRITE = 25,   // Guest software executed VMWRITE.
	EXIT_REASON_VMXOFF = 26,   // Guest software executed VMXOFF.
	EXIT_REASON_VMXON = 27,   // Guest software executed VMXON.
	EXIT_REASON_CR_ACCESS = 28,   // Control-register accesses.
	EXIT_REASON_DR_ACCESS = 29,   // Debug-register accesses.
	EXIT_REASON_IO_INSTRUCTION = 30,   // I/O instruction.
	EXIT_REASON_MSR_READ = 31,   // RDMSR. Guest software attempted to execute RDMSR.
	EXIT_REASON_MSR_WRITE = 32,   // WRMSR. Guest software attempted to execute WRMSR.
	EXIT_REASON_INVALID_GUEST_STATE = 33,   // VM-entry failure due to invalid guest state.
	EXIT_REASON_MSR_LOADING = 34,   // VM-entry failure due to MSR loading.
	EXIT_REASON_RESERVED_35 = 35,   // Reserved
	EXIT_REASON_MWAIT_INSTRUCTION = 36,   // Guest software executed MWAIT.
	EXIT_REASOM_MTF = 37,   // VM-exit due to monitor trap flag.
	EXIT_REASON_RESERVED_38 = 38,   // Reserved
	EXIT_REASON_MONITOR_INSTRUCTION = 39,   // Guest software attempted to execute MONITOR.
	EXIT_REASON_PAUSE_INSTRUCTION = 40,   // Guest software attempted to execute PAUSE.
	EXIT_REASON_MACHINE_CHECK = 41,   // VM-entry failure due to machine-check.
	EXIT_REASON_RESERVED_42 = 42,   // Reserved
	EXIT_REASON_TPR_BELOW_THRESHOLD = 43,   // TPR below threshold. Guest software executed MOV to CR8.
	EXIT_REASON_APIC_ACCESS = 44,   // APIC access. Guest software attempted to access memory at a physical address on the APIC-access page.
	EXIT_REASON_VIRTUALIZED_EIO = 45,   // EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in the EOIexit bitmap
	EXIT_REASON_XDTR_ACCESS = 46,   // Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT.
	EXIT_REASON_TR_ACCESS = 47,   // Guest software attempted to execute LLDT, LTR, SLDT, or STR.
	EXIT_REASON_EPT_VIOLATION = 48,   // An attempt to access memory with a guest-physical address was disallowed by the configuration of the EPT paging structures.
	EXIT_REASON_EPT_MISCONFIG = 49,   // An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry.
	EXIT_REASON_INVEPT = 50,   // Guest software attempted to execute INVEPT.
	EXIT_REASON_RDTSCP = 51,   // Guest software attempted to execute RDTSCP.
	EXIT_REASON_PREEMPT_TIMER = 52,   // VMX-preemption timer expired. The preemption timer counted down to zero.
	EXIT_REASON_INVVPID = 53,   // Guest software attempted to execute INVVPID.
	EXIT_REASON_WBINVD = 54,   // Guest software attempted to execute WBINVD
	EXIT_REASON_XSETBV = 55,   // Guest software attempted to execute XSETBV.
	EXIT_REASON_APIC_WRITE = 56,   // Guest completed write to virtual-APIC.
	EXIT_REASON_RDRAND = 57,   // Guest software attempted to execute RDRAND.
	EXIT_REASON_INVPCID = 58,   // Guest software attempted to execute INVPCID.
	EXIT_REASON_VMFUNC = 59,   // Guest software attempted to execute VMFUNC.
	EXIT_REASON_RESERVED_60 = 60,   // Reserved
	EXIT_REASON_RDSEED = 61,   // Guest software attempted to executed RDSEED and exiting was enabled.
	EXIT_REASON_RESERVED_62 = 62,   // Reserved
	EXIT_REASON_XSAVES = 63,   // Guest software attempted to executed XSAVES and exiting was enabled.
	EXIT_REASON_XRSTORS = 64,   // Guest software attempted to executed XRSTORS and exiting was enabled.

	VMX_MAX_GUEST_VMEXIT = 65
} VM_EXIT_REASON_ENUM;

//GDT表项，参考https://wiki.osdev.org/Global_Descriptor_Table#System_Segment_Descriptor
//照抄https://github.com/tandasat/SimpleSvm
typedef struct _SEGMENT_DESCRIPTOR
{
	union
	{
		UINT64 AsUInt64;
		struct
		{
			UINT16 LimitLow;        // [0:15] 
			UINT16 BaseLow;         // [16:31]
			UINT32 BaseMiddle : 8;  // [32:39]
			UINT32 Type : 4;        // [40:43]
			UINT32 System : 1;      // [44]
			UINT32 Dpl : 2;         // [45:46]
			UINT32 Present : 1;     // [47]
			UINT32 LimitHigh : 4;   // [48:51]
			UINT32 Avl : 1;         // [52]
			UINT32 LongMode : 1;    // [53]
			UINT32 DefaultBit : 1;  // [54]
			UINT32 Granularity : 1; // [55]
			UINT32 BaseHigh : 8;    // [56:63]	
		} Fields;
	};
	//这一部分是我自己添加，其余部分和git项目一样
	//这一部分是否存在看Type成员，X64强制平坦段，对于代码段和数据段这一部分不存在
	//对于门段(gate segment)和系统段(system segment)才有这些成员，而且定义各有不同，具体参考CPU手册
	//这里我需要获取系统段(TSS LDT)的基址
	struct
	{
		UINT32 BaseHigh4Byte;
		UINT32 Reserved;
	} OptionalField;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

//这个结构见这个网址 https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
//里面对 MASM .PUSHFRAME 指令的行为分析
typedef struct _MACHINE_FRAME
{
	UINT64 Rip;
	UINT64 Cs;
	UINT64 EFlags;
	UINT64 OldRsp;
	UINT64 Ss;
} MACHINE_FRAME, * PMACHINE_FRAME;
typedef union _IA32_VTX_BASIC_MSR
{
	ULONG64 AsUInt64;
	struct
	{
		ULONG32 RevisionIdentifier : 31;   // [0-30]
		ULONG32 Reserved1 : 1;             // [31]
		ULONG32 RegionSize : 12;           // [32-43]
		ULONG32 RegionClear : 1;           // [44]
		ULONG32 Reserved2 : 3;             // [45-47]
		ULONG32 SupportedIA64 : 1;         // [48]
		ULONG32 SupportedDualMoniter : 1;  // [49]
		ULONG32 MemoryType : 4;            // [50-53]
		ULONG32 VmExitReport : 1;          // [54]
		ULONG32 VTXCapabilityHint : 1;     // [55]
		ULONG32 Reserved3 : 8;             // [56-63]
	} Fields;
} IA32_VTX_BASIC_MSR, * PIA32_VTX_BASIC_MSR;

typedef union _IA32_VTX_PROCBASED_CTLS_MSR
{
	ULONG64 AsUInt64;
	struct
	{
		ULONG64 Reserved0 : 32;                // [0-31]
		ULONG64 Reserved1 : 2;                 // [32 + 0-1]
		ULONG64 InterruptWindowExiting : 1;    // [32 + 2]
		ULONG64 UseTSCOffseting : 1;           // [32 + 3]
		ULONG64 Reserved2 : 3;                 // [32 + 4-6]
		ULONG64 HLTExiting : 1;                // [32 + 7]
		ULONG64 Reserved3 : 1;                 // [32 + 8]
		ULONG64 INVLPGExiting : 1;             // [32 + 9]
		ULONG64 MWAITExiting : 1;              // [32 + 10]
		ULONG64 RDPMCExiting : 1;              // [32 + 11]
		ULONG64 RDTSCExiting : 1;              // [32 + 12]
		ULONG64 Reserved4 : 2;                 // [32 + 13-14]
		ULONG64 CR3LoadExiting : 1;            // [32 + 15]
		ULONG64 CR3StoreExiting : 1;           // [32 + 16]
		ULONG64 Reserved5 : 2;                 // [32 + 17-18]
		ULONG64 CR8LoadExiting : 1;            // [32 + 19]
		ULONG64 CR8StoreExiting : 1;           // [32 + 20]
		ULONG64 UseTPRShadowExiting : 1;       // [32 + 21]
		ULONG64 NMIWindowExiting : 1;          // [32 + 22]
		ULONG64 MovDRExiting : 1;              // [32 + 23]
		ULONG64 UnconditionalIOExiting : 1;    // [32 + 24]
		ULONG64 UseIOBitmaps : 1;              // [32 + 25]
		ULONG64 Reserved6 : 1;                 // [32 + 26]
		ULONG64 MonitorTrapFlag : 1;           // [32 + 27]
		ULONG64 UseMSRBitmaps : 1;             // [32 + 28]
		ULONG64 MONITORExiting : 1;            // [32 + 29]
		ULONG64 PAUSEExiting : 1;              // [32 + 30]
		ULONG64 ActivateSecondaryControl : 1;  // [32 + 31]  Does VTX_PROCBASED_CTLS2_MSR exist
	} Fields;
} IA32_VTX_PROCBASED_CTLS_MSR, * PIA32_VTX_PROCBASED_CTLS_MSR;

typedef union _IA32_VTX_PROCBASED_CTLS2_MSR
{
	ULONG64 AsUInt64;
	struct
	{
		ULONG64 Reserved0 : 32;                 // [0-31]
		ULONG64 VirtualizeAPICAccesses : 1;     // [32 + 0]
		ULONG64 EnableEPT : 1;                  // [32 + 1]
		ULONG64 DescriptorTableExiting : 1;     // [32 + 2]
		ULONG64 EnableRDTSCP : 1;               // [32 + 3]
		ULONG64 VirtualizeX2APICMode : 1;       // [32 + 4]
		ULONG64 EnableVPID : 1;                 // [32 + 5]
		ULONG64 WBINVDExiting : 1;              // [32 + 6]
		ULONG64 UnrestrictedGuest : 1;          // [32 + 7]
		ULONG64 APICRegisterVirtualization : 1; // [32 + 8]
		ULONG64 VirtualInterruptDelivery : 1;   // [32 + 9]
		ULONG64 PAUSELoopExiting : 1;           // [32 + 10]
		ULONG64 RDRANDExiting : 1;              // [32 + 11]
		ULONG64 EnableINVPCID : 1;              // [32 + 12]
		ULONG64 EnableVMFunctions : 1;          // [32 + 13]
		ULONG64 VMCSShadowing : 1;              // [32 + 14]
		ULONG64 Reserved1 : 1;                  // [32 + 15]
		ULONG64 RDSEEDExiting : 1;              // [32 + 16]
		ULONG64 Reserved2 : 1;                  // [32 + 17]
		ULONG64 EPTViolation : 1;               // [32 + 18]
		ULONG64 Reserved3 : 1;                  // [32 + 19]
		ULONG64 EnableXSAVESXSTORS : 1;         // [32 + 20]
	} Fields;
} IA32_VTX_PROCBASED_CTLS2_MSR, * PIA32_VTX_PROCBASED_CTLS2_MSR;

typedef union _IA32_FEATURE_CONTROL_MSR
{
	ULONG64 AsUInt64;
	struct
	{
		ULONG64 Lock : 1;                // [0]
		ULONG64 EnableSMX : 1;           // [1]
		ULONG64 EnableVTXon : 1;         // [2]
		ULONG64 Reserved2 : 5;           // [3-7]
		ULONG64 EnableLocalSENTER : 7;   // [8-14]
		ULONG64 EnableGlobalSENTER : 1;  // [15]
		ULONG64 Reserved3a : 16;         //
		ULONG64 Reserved3b : 32;         // [16-63]
	} Fields;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

typedef union _IA32_VTX_EPT_VPID_CAP_MSR
{
	ULONG64 AsUInt64;
	struct
	{
		ULONG64 ExecuteOnly : 1;                // Bit 0 defines if the EPT implementation supports execute-only translation
		ULONG64 Reserved1 : 31;                 // Undefined
		ULONG64 Reserved2 : 8;                  // Undefined
		ULONG64 IndividualAddressInvVpid : 1;   // Bit 40 defines if type 0 INVVPID instructions are supported
		ULONG64 Reserved3 : 23;
	} Fields;
} IA32_VTX_EPT_VPID_CAP_MSR, * PIA32_VTX_EPT_VPID_CAP_MSR;

typedef union _VTX_PIN_BASED_CONTROLS
{
	ULONG32 AsUInt32;
	struct
	{
		ULONG32 ExternalInterruptExiting : 1;    // [0]
		ULONG32 Reserved1 : 2;                   // [1-2]
		ULONG32 NMIExiting : 1;                  // [3]
		ULONG32 Reserved2 : 1;                   // [4]
		ULONG32 VirtualNMIs : 1;                 // [5]
		ULONG32 ActivateVTXPreemptionTimer : 1;  // [6]
		ULONG32 ProcessPostedInterrupts : 1;     // [7]
	} Fields;
} VTX_PIN_BASED_CONTROLS, * PVTX_PIN_BASED_CONTROLS;

typedef union _VTX_CPU_BASED_CONTROLS
{
	ULONG32 AsUInt32;
	struct
	{
		ULONG32 Reserved1 : 2;                 // [0-1]
		ULONG32 InterruptWindowExiting : 1;    // [2]
		ULONG32 UseTSCOffseting : 1;           // [3]
		ULONG32 Reserved2 : 3;                 // [4-6]
		ULONG32 HLTExiting : 1;                // [7]
		ULONG32 Reserved3 : 1;                 // [8]
		ULONG32 INVLPGExiting : 1;             // [9]
		ULONG32 MWAITExiting : 1;              // [10]
		ULONG32 RDPMCExiting : 1;              // [11]
		ULONG32 RDTSCExiting : 1;              // [12]
		ULONG32 Reserved4 : 2;                 // [13-14]
		ULONG32 CR3LoadExiting : 1;            // [15]
		ULONG32 CR3StoreExiting : 1;           // [16]
		ULONG32 Reserved5 : 2;                 // [17-18]
		ULONG32 CR8LoadExiting : 1;            // [19]
		ULONG32 CR8StoreExiting : 1;           // [20]
		ULONG32 UseTPRShadowExiting : 1;       // [21]
		ULONG32 NMIWindowExiting : 1;          // [22]
		ULONG32 MovDRExiting : 1;              // [23]
		ULONG32 UnconditionalIOExiting : 1;    // [24]
		ULONG32 UseIOBitmaps : 1;              // [25]
		ULONG32 Reserved6 : 1;                 // [26]
		ULONG32 MonitorTrapFlag : 1;           // [27]
		ULONG32 UseMSRBitmaps : 1;             // [28]
		ULONG32 MONITORExiting : 1;            // [29]
		ULONG32 PAUSEExiting : 1;              // [30]
		ULONG32 ActivateSecondaryControl : 1;  // [31]
	} Fields;
} VTX_CPU_BASED_CONTROLS, * PVTX_CPU_BASED_CONTROLS;

typedef union _VTX_SECONDARY_CPU_BASED_CONTROLS
{
	ULONG32 AsUInt32;
	struct
	{
		ULONG32 VirtualizeAPICAccesses : 1;      // [0]
		ULONG32 EnableEPT : 1;                   // [1]
		ULONG32 DescriptorTableExiting : 1;      // [2]
		ULONG32 EnableRDTSCP : 1;                // [3]
		ULONG32 VirtualizeX2APICMode : 1;        // [4]
		ULONG32 EnableVPID : 1;                  // [5]
		ULONG32 WBINVDExiting : 1;               // [6]
		ULONG32 UnrestrictedGuest : 1;           // [7]
		ULONG32 APICRegisterVirtualization : 1;  // [8]
		ULONG32 VirtualInterruptDelivery : 1;    // [9]
		ULONG32 PAUSELoopExiting : 1;            // [10]
		ULONG32 RDRANDExiting : 1;               // [11]
		ULONG32 EnableINVPCID : 1;               // [12]
		ULONG32 EnableVMFunctions : 1;           // [13]
		ULONG32 VMCSShadowing : 1;               // [14]
		ULONG32 Reserved1 : 1;                   // [15]
		ULONG32 RDSEEDExiting : 1;               // [16]
		ULONG32 Reserved2 : 1;                   // [17]
		ULONG32 EPTViolation : 1;                // [18]
		ULONG32 Reserved3 : 1;                   // [19]
		ULONG32 EnableXSAVESXSTORS : 1;          // [20]
	} Fields;
} VTX_SECONDARY_CPU_BASED_CONTROLS, * PVTX_SECONDARY_CPU_BASED_CONTROLS;

typedef union _VTX_VM_EXIT_CONTROLS
{
	ULONG32 AsUInt32;
	struct
	{
		ULONG32 Reserved1 : 2;                    // [0-1]
		ULONG32 SaveDebugControls : 1;            // [2]
		ULONG32 Reserved2 : 6;                    // [3-8]
		ULONG32 HostAddressSpaceSize : 1;         // [9]
		ULONG32 Reserved3 : 2;                    // [10-11]
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;    // [12]
		ULONG32 Reserved4 : 2;                    // [13-14]
		ULONG32 AcknowledgeInterruptOnExit : 1;   // [15]
		ULONG32 Reserved5 : 2;                    // [16-17]
		ULONG32 SaveIA32_PAT : 1;                 // [18]
		ULONG32 LoadIA32_PAT : 1;                 // [19]
		ULONG32 SaveIA32_EFER : 1;                // [20]
		ULONG32 LoadIA32_EFER : 1;                // [21]
		ULONG32 SaveVTXPreemptionTimerValue : 1;  // [22]
	} Fields;
} VTX_VM_EXIT_CONTROLS, * PVTX_VM_EXIT_CONTROLS;

typedef union _VTX_VM_ENTER_CONTROLS
{
	ULONG32 AsUInt32;
	struct
	{
		ULONG32 Reserved1 : 2;                       // [0-1]
		ULONG32 LoadDebugControls : 1;               // [2]
		ULONG32 Reserved2 : 6;                       // [3-8]
		ULONG32 IA32eModeGuest : 1;                  // [9]
		ULONG32 EntryToSMM : 1;                      // [10]
		ULONG32 DeactivateDualMonitorTreatment : 1;  // [11]
		ULONG32 Reserved3 : 1;                       // [12]
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;       // [13]
		ULONG32 LoadIA32_PAT : 1;                    // [14]
		ULONG32 LoadIA32_EFER : 1;                   // [15]
	} Fields;
} VTX_VM_ENTER_CONTROLS, * PVTX_VM_ENTER_CONTROLS;

typedef enum _INTERRUPT_TYPE
{
	INTERRUPT_EXTERNAL = 0,
	INTERRUPT_NMI = 2,
	INTERRUPT_HARDWARE_EXCEPTION = 3,
	INTERRUPT_SOFTWARE = 4,
	INTERRUPT_PRIVILIGED_EXCEPTION = 5,
	INTERRUPT_SOFTWARE_EXCEPTION = 6,
	INTERRUPT_OTHER_EVENT = 7
} INTERRUPT_TYPE;

typedef union _INTERRUPT_INJECT_INFO_FIELD
{
	ULONG32 AsUInt32;
	struct
	{
		ULONG32 Vector : 8;
		ULONG32 Type : 3;
		ULONG32 DeliverErrorCode : 1;
		ULONG32 Reserved : 19;
		ULONG32 Valid : 1;
	} Fields;
} INTERRUPT_INJECT_INFO_FIELD, * PINTERRUPT_INJECT_INFO_FIELD;

typedef union _INTERRUPT_INFO_FIELD
{
	ULONG32 AsUInt32;
	struct
	{
		ULONG32 Vector : 8;
		ULONG32 Type : 3;
		ULONG32 ErrorCodeValid : 1;
		ULONG32 NMIUnblocking : 1;
		ULONG32 Reserved : 18;
		ULONG32 Valid : 1;
	} Fields;
} INTERRUPT_INFO_FIELD, * PINTERRUPT_INFO_FIELD;

//这个函数完全照抄https://github.com/tandasat/SimpleSvmU
//原函数名字是SvGetSegmentAccessRight
//获取段寄存器Attribute
#pragma code_seg("PAGE")
VTXAccessRight GetSegmentAttribute(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
	PAGED_CODE();
	PSEGMENT_DESCRIPTOR descriptor = NULL;
	VTXAccessRight attribute = {};

	//关于段选择子的结构参考https://wiki.osdev.org/Segment_Selector
	//低3bit是标志，这里不管基址是LDT的情况，这个函数设计就是假设基址是GDT
	descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
		GdtBase + (SegmentSelector & ~0x7));

	attribute.Fields.Type = descriptor->Fields.Type;
	attribute.Fields.System = descriptor->Fields.System;
	attribute.Fields.Dpl = descriptor->Fields.Dpl;
	attribute.Fields.Present = descriptor->Fields.Present;
	attribute.Fields.Avl = descriptor->Fields.Avl;
	attribute.Fields.LongMode = descriptor->Fields.LongMode;
	attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
	attribute.Fields.Granularity = descriptor->Fields.Granularity;
	attribute.Fields.Reserved1 = 0;
	attribute.Fields.Reserved2 = 0;

	attribute.Fields.Unusable = ~attribute.Fields.Present;

	return attribute;
}

//获取段寄存器Base
#pragma code_seg("PAGE")
UINT64 GetSegmentBaseAddress(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
	PAGED_CODE();
	PSEGMENT_DESCRIPTOR descriptor;
	UINT64 baseAddress = 0;

	descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
		GdtBase + (SegmentSelector & ~0x7));

	baseAddress |= descriptor->Fields.BaseLow;
	baseAddress |= ((UINT64)descriptor->Fields.BaseMiddle) << 16;
	baseAddress |= ((UINT64)descriptor->Fields.BaseHigh) << 24;
	if (!descriptor->Fields.System)
		baseAddress |= ((UINT64)descriptor->OptionalField.BaseHigh4Byte) << 32;

	return baseAddress;
}

//获取段寄存器Limit
#pragma code_seg("PAGE")
UINT32 GetSegmentLimit2(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
	PAGED_CODE();
	PSEGMENT_DESCRIPTOR descriptor;
	UINT32 limit = 0;

	descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
		GdtBase + (SegmentSelector & ~0x7));

	limit |= descriptor->Fields.LimitLow;
	limit |= ((UINT64)descriptor->Fields.LimitHigh) << 16;

	/*
		获取段描述符中的 limit 字段：段描述符中的 limit 字段是 20 位的值，分为高 4 位和低 16 位。
		检查粒度（G）位：
			如果 G = 0，limit 的单位是字节，范围是 1B 到 1MB。
			如果 G = 1，limit 的单位是 4KB，范围是 4KB 到 4GB。
		计算 limit：
			当 G = 0 时，limit 的计算公式为： {Limit} = {Low 16 bits} + ({High 4 bits} << 16)
			当 G = 1 时，limit 的计算公式为： {Limit} = (({Low 16 bits} + ({High 4 bits} << 16))) << 12) + 0xFFF
	*/

	if (descriptor->Fields.Granularity)
	{
		limit <<= 12;
		limit |= 0xfff;
	}

	return limit;
}

//初始化KTRAP_FRAME结构体
#pragma code_seg()
extern "C" void FillMachineFrame(MACHINE_FRAME& machineFrame, const GenericRegisters& guestRegistars, const VirtCpuInfo& virtCpuInfo)
{
	UNREFERENCED_PARAMETER(guestRegistars);
	UNREFERENCED_PARAMETER(virtCpuInfo);
	UNREFERENCED_PARAMETER(machineFrame);
	machineFrame = {};

	PTR_TYPE value = 0;

	__vmx_vmread(GUEST_RIP, &value);
	machineFrame.Rip = value;
	__vmx_vmread(GUEST_CS_SELECTOR, &value);
	machineFrame.Cs = value;
	__vmx_vmread(GUEST_SS_SELECTOR, &value);
	machineFrame.Ss = value;
	__vmx_vmread(GUEST_RSP, &value);
	machineFrame.OldRsp = value;
	__vmx_vmread(GUEST_RFLAGS, &value);
	machineFrame.EFlags = value;
}

//#VMEXIT处理函数
#pragma code_seg()
extern "C" void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters)
{
	UNREFERENCED_PARAMETER(pGuestRegisters);
	PTR_TYPE value = 0;

	__vmx_vmread(GUEST_RIP, &value);
	pGuestRegisters->rip = value;
	__vmx_vmread(GUEST_RSP, &value);
	pGuestRegisters->rsp = value;
	__vmx_vmread(GUEST_RFLAGS, &value);
	pGuestRegisters->rflags = value;

	pGuestRegisters->extraInfo1 = 0;
	pGuestRegisters->extraInfo2 = 0;

	IMsrBackupRestorePlugin* pMsrHookPlugin = pVirtCpuInfo->otherInfo.pVTXManager->pMsrBackupRestorePlugin;

	//如果 MSR 拦截插件存在，进入VM之后保存Guest和恢复Host的MSR
	if (pMsrHookPlugin != NULL)
	{
		pMsrHookPlugin->SaveGuestMsrForCpu(pVirtCpuInfo->otherInfo.cpuIdx);
		pMsrHookPlugin->LoadHostMsrForCpu(pVirtCpuInfo->otherInfo.cpuIdx);
	}

	//转发到VTXanager::VmExitHandler函数
	pVirtCpuInfo->otherInfo.pVTXManager->VmExitHandler(pVirtCpuInfo, pGuestRegisters);

	//如果 MSR 拦截插件存在，退出VM之前恢复Guest和保存Host的MSR
	if (pMsrHookPlugin != NULL)
	{
		pMsrHookPlugin->SaveHostMsrForCpu(pVirtCpuInfo->otherInfo.cpuIdx);
		pMsrHookPlugin->LoadGuestMsrForCpu(pVirtCpuInfo->otherInfo.cpuIdx);
	}

	if (!pVirtCpuInfo->regsBackup.genericRegisters1.extraInfo1)
	{
		__vmx_vmwrite(GUEST_RIP, pGuestRegisters->rip);
		__vmx_vmwrite(GUEST_RSP, pGuestRegisters->rsp);
		__vmx_vmwrite(GUEST_RFLAGS, pGuestRegisters->rflags);
	}

	pGuestRegisters->extraInfo2 = (UINT64)pGuestRegisters->rip;
}

//获取CPU生产商的字符串
#pragma code_seg("PAGE")
void CPUString(char* outputString)
{
	PAGED_CODE();
	UINT32 cpuid_result[4] = {};
	__cpuidex((int*)cpuid_result, 0, 0);
	memcpy(outputString, &cpuid_result[1], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32), &cpuid_result[3], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32) * 2, &cpuid_result[2], sizeof(UINT32));
	outputString[3 * sizeof(UINT32)] = 0;
}

//分配MSR拦截标志位map
#pragma code_seg("PAGE")
NTSTATUS MsrPremissionsMapManager::Init()
{
	PAGED_CODE();
	if (IsInited())
		return STATUS_SUCCESS;

	//LOW MSR = 0000,0000h ~ 0000,1FFFh
	//HIGH MSR = C000,0000h ~ C000,1FFFh

	constexpr UINT32 LOW_MSR_READ_BYTE_OFFSET = 0;
	constexpr UINT32 HIGH_MSR_READ_BYTE_OFFSET = 1024;
	constexpr UINT32 LOW_MSR_WRITE_BYTE_OFFSET = 2048;
	constexpr UINT32 HIGH_MSR_WRITE_BYTE_OFFSET = 3072;
	constexpr UINT32 BITS_PER_BYTE = 8;
	constexpr UINT32 HIGH_MSR_BASE = 0xC0000000;

	RTL_BITMAP bitmapHeader = {};

	//分配物理连续内存
	pMsrPremissionsMapVirtAddr = AllocContiguousMem(1ULL * PAGE_SIZE, SVM_TAG);
	if (pMsrPremissionsMapVirtAddr == NULL)
	{
		KdPrint(("MsrPremissionsMapManager::Init(): Memory not enough!\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//初始化内存的值
	RtlInitializeBitMap(&bitmapHeader, (PULONG)pMsrPremissionsMapVirtAddr, PAGE_SIZE * CHAR_BIT);
	RtlClearAllBits(&bitmapHeader);

	constexpr UINT32 IA32_MSR_FEATURE_CONTROL_READ_OFFSET = LOW_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_FEATURE_CONTROL;

	RtlSetBit(&bitmapHeader, IA32_MSR_FEATURE_CONTROL_READ_OFFSET);

	constexpr UINT32 DEFAULT_MSR_WRITE_INTERCEPT_WRITE_BEGIN_OFFSET = LOW_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_VTX_BASIC;
	constexpr UINT32 NUMBER_DEFAULT_MSR_WRITE_INTERCEPT = IA32_MSR_VTX_ENTRY_CTLS - IA32_MSR_VTX_BASIC;

	RtlSetBits(&bitmapHeader, DEFAULT_MSR_WRITE_INTERCEPT_WRITE_BEGIN_OFFSET, NUMBER_DEFAULT_MSR_WRITE_INTERCEPT);

	constexpr UINT32 IA32_MSR_VTX_VMFUNC_WRITE_OFFSET = LOW_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_VTX_VMFUNC;

	RtlSetBit(&bitmapHeader, IA32_MSR_VTX_VMFUNC_WRITE_OFFSET);

	constexpr UINT32 IA32_MSR_EFER_READ_OFFSET = HIGH_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_EFER - HIGH_MSR_BASE;
	constexpr UINT32 IA32_MSR_EFER_WRITE_OFFSET = HIGH_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_EFER - HIGH_MSR_BASE;

	RtlSetBit(&bitmapHeader, IA32_MSR_EFER_READ_OFFSET);
	RtlSetBit(&bitmapHeader, IA32_MSR_EFER_WRITE_OFFSET);

	constexpr UINT32 IA32_MSR_PAT_READ_OFFSET = LOW_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_PAT;
	constexpr UINT32 IA32_MSR_PAT_WRITE_OFFSET = LOW_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_PAT;

	RtlSetBit(&bitmapHeader, IA32_MSR_PAT_READ_OFFSET);
	RtlSetBit(&bitmapHeader, IA32_MSR_PAT_WRITE_OFFSET);

	constexpr UINT32 IA32_MSR_FS_BASE_READ_OFFSET = HIGH_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_FS_BASE - HIGH_MSR_BASE;
	constexpr UINT32 IA32_MSR_FS_BASE_WRITE_OFFSET = HIGH_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_FS_BASE - HIGH_MSR_BASE;

	RtlSetBit(&bitmapHeader, IA32_MSR_FS_BASE_READ_OFFSET);
	RtlSetBit(&bitmapHeader, IA32_MSR_FS_BASE_WRITE_OFFSET);

	constexpr UINT32 IA32_MSR_GS_BASE_READ_OFFSET = HIGH_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_GS_BASE - HIGH_MSR_BASE;
	constexpr UINT32 IA32_MSR_GS_BASE_WRITE_OFFSET = HIGH_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_GS_BASE - HIGH_MSR_BASE;

	RtlSetBit(&bitmapHeader, IA32_MSR_GS_BASE_READ_OFFSET);
	RtlSetBit(&bitmapHeader, IA32_MSR_GS_BASE_WRITE_OFFSET);

	constexpr UINT32 IA32_MSR_SYSENTER_CS_READ_OFFSET = LOW_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_SYSENTER_CS;
	constexpr UINT32 IA32_MSR_SYSENTER_CS_WRITE_OFFSET = LOW_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_SYSENTER_CS;

	RtlSetBit(&bitmapHeader, IA32_MSR_SYSENTER_CS_READ_OFFSET);
	RtlSetBit(&bitmapHeader, IA32_MSR_SYSENTER_CS_WRITE_OFFSET);

	constexpr UINT32 IA32_MSR_SYSENTER_ESP_READ_OFFSET = LOW_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_SYSENTER_ESP;
	constexpr UINT32 IA32_MSR_SYSENTER_ESP_WRITE_OFFSET = LOW_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_SYSENTER_ESP;

	RtlSetBit(&bitmapHeader, IA32_MSR_SYSENTER_ESP_READ_OFFSET);
	RtlSetBit(&bitmapHeader, IA32_MSR_SYSENTER_ESP_WRITE_OFFSET);

	constexpr UINT32 IA32_MSR_SYSENTER_EIP_READ_OFFSET = LOW_MSR_READ_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_SYSENTER_EIP;
	constexpr UINT32 IA32_MSR_SYSENTER_EIP_WRITE_OFFSET = LOW_MSR_WRITE_BYTE_OFFSET * BITS_PER_BYTE + IA32_MSR_SYSENTER_EIP;

	RtlSetBit(&bitmapHeader, IA32_MSR_SYSENTER_EIP_READ_OFFSET);
	RtlSetBit(&bitmapHeader, IA32_MSR_SYSENTER_EIP_WRITE_OFFSET);

	//如果MSR拦截插件存在，让插件设置拦截标志位
	if (pMsrInterceptPlugin != NULL)
		pMsrInterceptPlugin->SetMsrPremissionMap(bitmapHeader);

	//获取物理地址
	pMsrPremissionsMapPhyAddr = (PVOID)MmGetPhysicalAddress(pMsrPremissionsMapVirtAddr).QuadPart;
	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void MsrPremissionsMapManager::Deinit()
{
	PAGED_CODE();
	if (pMsrPremissionsMapVirtAddr != NULL)
	{
		FreeContigousMem(pMsrPremissionsMapVirtAddr, SVM_TAG);
		pMsrPremissionsMapVirtAddr = NULL;
		pMsrPremissionsMapPhyAddr = NULL;
	}
}

#pragma code_seg("PAGE")
VTXStatus VTXManager::CheckVTX()
{
	PAGED_CODE();

	char cpuString[13] = {};
	CPUString(cpuString);

	if (strcmp(cpuString, "GenuineIntel"))
		return VTXStatus::VTXS_NONINTELCPU;

	int cpuid[4] = {};
	__cpuid(cpuid, 1);

	UINT32 result = VTXStatus::VTXS_UNUSED;

	if ((cpuid[2] & (1UL << VTX_BIT_IN_ECX_OFFSET)))
		result |= VTXStatus::VTXS_SUPPORTED;

	IA32_FEATURE_CONTROL_MSR Control = { 0 };
	Control.AsUInt64 = __readmsr(IA32_MSR_FEATURE_CONTROL);

	// BIOS lock check
	if (!Control.Fields.Lock)
	{
		Control.Fields.Lock = TRUE;
		Control.Fields.EnableVTXon = TRUE;
		__writemsr(IA32_MSR_FEATURE_CONTROL, Control.AsUInt64);

		result |= VTXStatus::VTXS_ENABLED;
	}
	else if (Control.Fields.EnableVTXon)
	{
		result |= VTXStatus::VTXS_ENABLED;
	}

	IA32_VTX_BASIC_MSR basic = { 0 };
	IA32_VTX_PROCBASED_CTLS_MSR ctl = { 0 };
	IA32_VTX_PROCBASED_CTLS2_MSR ctl2 = { 0 };
	IA32_VTX_EPT_VPID_CAP_MSR vpidcap = { 0 };

	ctl.AsUInt64 = __readmsr(IA32_MSR_VTX_PROCBASED_CTLS);

	if (ctl.Fields.ActivateSecondaryControl)
	{
		ctl2.AsUInt64 = __readmsr(IA32_MSR_VTX_PROCBASED_CTLS2);

		if (ctl2.Fields.EnableEPT)
		{
			result |= VTXStatus::VTXS_EPT_ENABLED;

			vpidcap.AsUInt64 = __readmsr(IA32_MSR_VTX_EPT_VPID_CAP);

			if (vpidcap.Fields.ExecuteOnly)
				result |= VTXStatus::VTXS_EPT_EXECUTE_ONLY;
		}
	}

	return (VTXStatus)result;
}

#pragma code_seg("PAGE")
VMX_FEATURES VTXManager::CheckFeatures()
{
	PAGED_CODE();
	VMX_FEATURES result = {};

	IA32_VTX_BASIC_MSR basic = { 0 };
	IA32_VTX_PROCBASED_CTLS_MSR ctl = { 0 };
	IA32_VTX_PROCBASED_CTLS2_MSR ctl2 = { 0 };
	IA32_VTX_EPT_VPID_CAP_MSR vpidcap = { 0 };

	// True MSRs
	basic.AsUInt64 = __readmsr(IA32_MSR_VTX_BASIC);
	result.TrueMSRs = basic.Fields.VTXCapabilityHint;

	// Secondary control
	ctl.AsUInt64 = __readmsr(IA32_MSR_VTX_PROCBASED_CTLS);
	result.SecondaryControls = ctl.Fields.ActivateSecondaryControl;

	if (ctl.Fields.ActivateSecondaryControl)
	{
		// EPT, VPID, VMFUNC
		ctl2.AsUInt64 = __readmsr(IA32_MSR_VTX_PROCBASED_CTLS2);
		result.EPT = ctl2.Fields.EnableEPT;
		result.VPID = ctl2.Fields.EnableVPID;
		result.VMFUNC = ctl2.Fields.EnableVMFunctions;

		if (ctl2.Fields.EnableEPT)
		{
			// Execute only
			vpidcap.AsUInt64 = __readmsr(IA32_MSR_VTX_EPT_VPID_CAP);
			result.ExecOnlyEPT = vpidcap.Fields.ExecuteOnly;
			result.InvSingleAddress = vpidcap.Fields.IndividualAddressInvVpid;
		}
	}

	return result;
}

#pragma code_seg("PAGE")
NTSTATUS VTXManager::Init()
{
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;
	UINT32 idx = 0;

	do
	{
		//检查是否支持AMD-V
		VTXStatus svmStatus = CheckVTX();

		status = STATUS_INSUFFICIENT_RESOURCES;

		//虚拟化硬件检查
		if (svmStatus & VTXStatus::VTXS_NONINTELCPU)
		{
			KdPrint(("VTXManager::Init(): Not Intel Processor!\n"));
			break;
		}

		if (!(svmStatus & VTXStatus::VTXS_SUPPORTED))
		{
			KdPrint(("VTXManager::Init(): VTX feature is not supported!\n"));
			break;
		}

		if (!(svmStatus & VTXStatus::VTXS_ENABLED))
		{
			KdPrint(("VTXManager::Init(): VTX feature is not enabled!\n"));
			break;
		}

		//如果提供了EPT页表而且SVM不支持EPT，那么提示不支持EPT
		if (!(svmStatus & VTXStatus::VTXS_EPT_ENABLED) && pEptpProvider != NULL)
		{
			KdPrint(("VTXManager::Init(): EPT feature is not enabled!\n"));
			break;
		}

		features = CheckFeatures();

		msrPremissionMap.SetPlugin(pMsrInterceptPlugin);

		//为每一个CPU分配进入虚拟化必备的资源
		//这里先初始化每个CPU的资源指针
		cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
		pVirtCpuInfo = (VirtCpuInfo**)AllocNonPagedMem(cpuCnt * sizeof(VirtCpuInfo*), SVM_TAG);

		if (pVirtCpuInfo == NULL)
		{
			KdPrint(("VTXManager::Init(): Cpu virtualization memory failed!\n"));
			break;
		}

		status = msrPremissionMap.Init();
		if (!NT_SUCCESS(status))
		{
			KdPrint(("VTXManager::Init(): MSR premission map init failed!\n"));
			break;
		}

		status = STATUS_SUCCESS;

		//为每个CPU分配进入虚拟化所需的内存
		for (idx = 0; idx < cpuCnt; ++idx)
		{
			pVirtCpuInfo[idx] = (VirtCpuInfo*)AllocNonPagedMem(sizeof(VirtCpuInfo), SVM_TAG);
			if (pVirtCpuInfo[idx] == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(pVirtCpuInfo[idx], sizeof(VirtCpuInfo));
			pVirtCpuInfo[idx]->otherInfo.pVTXManager = this;
			pVirtCpuInfo[idx]->otherInfo.cpuIdx = idx;
		}

		if (!NT_SUCCESS(status))
		{
			KdPrint(("VTXManager::Init(): CPU Virtualization resource init failed!\n"));
			break;
		}

		//进入虚拟化
		status = EnterVirtualization();

		if (!NT_SUCCESS(status))
		{
			KdPrint(("VTXManager::Init(): Can not enter virtualization!\n"));
			break;
		}

	} while (false);

	if (!NT_SUCCESS(status))
		Deinit();

	return status;
}

#pragma code_seg("PAGE")
void VTXManager::Deinit()
{
	PAGED_CODE();
	if (pVirtCpuInfo != NULL && cpuCnt)
	{
		LeaveVirtualization();

		for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
		{
			FreeNonPagedMem(pVirtCpuInfo[idx], SVM_TAG);
			pVirtCpuInfo[idx] = NULL;
		}
		FreeNonPagedMem(pVirtCpuInfo, SVM_TAG);
		pVirtCpuInfo = NULL;
		cpuCnt = 0;
	}
	msrPremissionMap.Deinit();
}

#pragma code_seg("PAGE")
NTSTATUS VTXManager::EnterVirtualization()
{
	PAGED_CODE();

	auto enterVirtualizationCore = [this](UINT32 cpuIdx) -> NTSTATUS
		{
			IA32_VTX_BASIC_MSR VTXBasic = {};
			VTXBasic.AsUInt64 = __readmsr(IA32_MSR_VTX_BASIC);

			// Ensure the the VMCS can fit into a single page
			if (VTXBasic.Fields.RegionSize > PAGE_SIZE)
			{
				KdPrint(("VTXManager::EnterVirtualization(): CPU %d: VMCS region doesn't fit into one page\n", cpuIdx));
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			_save_or_load_regs(&pVirtCpuInfo[cpuIdx]->regsBackup.genericRegisters2);

			if (!pVirtCpuInfo[cpuIdx]->otherInfo.isInVirtualizaion)
			{
				//标记已经进入过虚拟化
				pVirtCpuInfo[cpuIdx]->otherInfo.isInVirtualizaion = TRUE;

				//备份因为要进入虚拟化而改写的寄存器
				pVirtCpuInfo[cpuIdx]->regsBackup.originCr0 = __readcr0();
				pVirtCpuInfo[cpuIdx]->regsBackup.originCr4 = __readcr4();

				pVirtCpuInfo[cpuIdx]->guestVmcs.RevisionId = VTXBasic.Fields.RevisionIdentifier;
				pVirtCpuInfo[cpuIdx]->hostVmcs.RevisionId = VTXBasic.Fields.RevisionIdentifier;

				UINT64 newCr0 = pVirtCpuInfo[cpuIdx]->regsBackup.originCr0;
				UINT64 newCr4 = pVirtCpuInfo[cpuIdx]->regsBackup.originCr4;

				newCr0 &= __readmsr(IA32_MSR_VTX_CR0_FIXED1);
				newCr0 |= __readmsr(IA32_MSR_VTX_CR0_FIXED0);

				newCr4 &= __readmsr(IA32_MSR_VTX_CR4_FIXED1);
				newCr4 |= __readmsr(IA32_MSR_VTX_CR4_FIXED0);

				__writecr0(newCr0);
				__writecr4(newCr4);

				PHYSICAL_ADDRESS phyHostVmcs = MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->hostVmcs);
				PHYSICAL_ADDRESS phyGuestVmcs = MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->guestVmcs);

				if (__vmx_on((PULONG64)&phyHostVmcs))
				{
					KdPrint(("VTXManager::EnterVirtualization(): CPU %d: __vmx_on failed\n", cpuIdx));
					return STATUS_INSUFFICIENT_RESOURCES;
				}

				if (__vmx_vmclear((PULONG64)&phyGuestVmcs))
				{
					KdPrint(("VTXManager::EnterVirtualization(): CPU %d: __vmx_vmclear failed\n", cpuIdx));
					return STATUS_INSUFFICIENT_RESOURCES;
				}

				if (__vmx_vmptrld((PULONG64)&phyGuestVmcs))
				{
					KdPrint(("VTXManager::EnterVirtualization(): CPU %d: __vmx_vmptrld failed\n", cpuIdx));
					return STATUS_INSUFFICIENT_RESOURCES;
				}

				VTX_VM_ENTER_CONTROLS vmEnterCtlRequested = { 0 };
				VTX_VM_EXIT_CONTROLS vmExitCtlRequested = { 0 };
				VTX_PIN_BASED_CONTROLS vmPinCtlRequested = { 0 };
				VTX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };
				VTX_SECONDARY_CPU_BASED_CONTROLS vmCpuCtl2Requested = { 0 };
				ULONG exceptionBitmap = 0;

				auto adjustVTXValue = [](UINT32 originValue, UINT64 adjustValue) -> UINT32
					{
						originValue &= ((adjustValue >> 32) & 0xffffffff);
						originValue |= (adjustValue & 0xffffffff);
						return originValue;
					};

				//vmPinCtlRequested.Fields.NMIExiting = true;

				// As we exit back into the guest, make sure to exist in x64 mode as well.
				vmEnterCtlRequested.Fields.IA32eModeGuest = TRUE;
				//vmEnterCtlRequested.Fields.LoadIA32_EFER = TRUE;
				//vmEnterCtlRequested.Fields.LoadIA32_PAT = TRUE;

				// If any interrupts were pending upon entering the hypervisor, acknowledge
				// them when we're done. And make sure to enter us in x64 mode at all times
				vmExitCtlRequested.Fields.AcknowledgeInterruptOnExit = TRUE;
				vmExitCtlRequested.Fields.HostAddressSpaceSize = TRUE;
				vmExitCtlRequested.Fields.SaveDebugControls = TRUE;
				vmExitCtlRequested.Fields.SaveIA32_EFER = TRUE;
				vmExitCtlRequested.Fields.SaveIA32_PAT = TRUE;
				//vmExitCtlRequested.Fields.LoadIA32_EFER = TRUE;
				//vmExitCtlRequested.Fields.LoadIA32_PAT = TRUE;

				// In order for our choice of supporting RDTSCP and XSAVE/RESTORES above to
				// actually mean something, we have to request secondary controls. We also
				// want to activate the MSR bitmap in order to keep them from being caught.
				vmCpuCtlRequested.Fields.UseMSRBitmaps = TRUE;
				vmCpuCtlRequested.Fields.ActivateSecondaryControl = TRUE;
				//vmCpuCtlRequested.Fields.INVLPGExiting = FALSE;
				//vmCpuCtlRequested.Fields.UseTSCOffseting = TRUE;
				//vmCpuCtlRequested.Fields.RDTSCExiting = TRUE;

				// VPID caches must be invalidated on CR3 change
				if (features.VPID)
				{
					vmCpuCtlRequested.Fields.CR3LoadExiting = TRUE;
					vmCpuCtl2Requested.Fields.EnableVPID = TRUE;
					__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, 100);
				}

				vmCpuCtl2Requested.Fields.EnableINVPCID = TRUE;
				vmCpuCtl2Requested.Fields.EnableVMFunctions = TRUE;

				if (pEptpProvider != NULL)
				{
					EPT_TABLE_POINTER EPTP = {};

					EPTP.Fields.PhysAddr = (PTR_TYPE)pEptpProvider->GetEptpForCore(cpuIdx) >> 12;
					EPTP.Fields.PageWalkLength = 3;
					EPTP.Fields.MemoryType = VTX_MEM_TYPE_UNCACHEABLE;

					__vmx_vmwrite(EPT_POINTER, EPTP.AsUInt64);

					vmCpuCtl2Requested.Fields.EnableEPT = TRUE;
				}

				//启用无限制客户机模式
				vmCpuCtl2Requested.AsUInt32 |= (1UL << 31);

				// Enable support for RDTSCP and XSAVES/XRESTORES in the guest. Windows 10
				// makes use of both of these instructions if the CPU supports it. By using
				// VTXpAdjustMsr, these options will be ignored if this processor does
				// not actually support the instructions to begin with.
				vmCpuCtl2Requested.Fields.EnableRDTSCP = TRUE;
				vmCpuCtl2Requested.Fields.EnableXSAVESXSTORS = TRUE;

				// Begin by setting the link pointer to the required value for 4KB VMCS.
				__vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);

				__vmx_vmwrite(
					PIN_BASED_VM_EXEC_CONTROL,
					adjustVTXValue(vmPinCtlRequested.AsUInt32, features.TrueMSRs ? __readmsr(IA32_MSR_VTX_TRUE_PINBASED_CTLS) : __readmsr(IA32_MSR_VTX_PINBASED_CTLS))
				);
				__vmx_vmwrite(
					CPU_BASED_VM_EXEC_CONTROL,
					adjustVTXValue(vmCpuCtlRequested.AsUInt32, features.TrueMSRs ? __readmsr(IA32_MSR_VTX_TRUE_PROCBASED_CTLS) : __readmsr(IA32_MSR_VTX_PROCBASED_CTLS))
				);
				__vmx_vmwrite(
					SECONDARY_VM_EXEC_CONTROL,
					adjustVTXValue(vmCpuCtl2Requested.AsUInt32, __readmsr(IA32_MSR_VTX_PROCBASED_CTLS2))
				);
				__vmx_vmwrite(
					VM_EXIT_CONTROLS,
					adjustVTXValue(vmExitCtlRequested.AsUInt32, features.TrueMSRs ? __readmsr(IA32_MSR_VTX_TRUE_EXIT_CTLS) : __readmsr(IA32_MSR_VTX_EXIT_CTLS))
				);
				__vmx_vmwrite(
					VM_ENTRY_CONTROLS,
					adjustVTXValue(vmEnterCtlRequested.AsUInt32, features.TrueMSRs ? __readmsr(IA32_MSR_VTX_TRUE_ENTRY_CTLS) : __readmsr(IA32_MSR_VTX_ENTRY_CTLS))
				);

				__vmx_vmwrite(MSR_BITMAP, msrPremissionMap.GetPhyAddress());

				if (pBreakpointInterceptPlugin != NULL)
					exceptionBitmap |= (1U << BP_EXCEPTION_VECTOR_INDEX);

				if (pSingleStepInterceptPlugin != NULL)
					exceptionBitmap |= (1U << DB_EXCEPTION_VECTOR_INDEX);

				if (pInvalidOpcodeInterceptPlugin != NULL)
					exceptionBitmap |= (1U << UD_EXCEPTION_VECTOR_INDEX);

				__vmx_vmwrite(EXCEPTION_BITMAP, exceptionBitmap);

				{
					SAVE_GUEST_STATUS_FROM_REGS(pVirtCpuInfo[cpuIdx]->regsBackup.genericRegisters2.rflags, (PTR_TYPE)pVirtCpuInfo[cpuIdx]->stack2 + sizeof pVirtCpuInfo[cpuIdx]->stack2 - sizeof(PTR_TYPE), pVirtCpuInfo[cpuIdx]->regsBackup.genericRegisters2.rip);
				}

				__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
				__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);

				{
					UINT64 gdtrBase = 0, idtrBase = 0;
					UINT16 gdtrLimit = 0, idtrLimit = 0;
					UINT16 trSelector = 0, ldtrSelector = 0;
					_mysgdt(&gdtrBase, &gdtrLimit);
					_mysidt(&idtrBase, &idtrLimit);
					_mystr(&trSelector);
					_mysldt(&ldtrSelector);

					__vmx_vmwrite(HOST_CR0, newCr0);
					__vmx_vmwrite(HOST_CR3, __readcr3());
					__vmx_vmwrite(HOST_CR4, newCr4);

					__vmx_vmwrite(HOST_CS_SELECTOR, _cs_selector() & ~RPL_MASK);
					__vmx_vmwrite(HOST_SS_SELECTOR, _ss_selector() & ~RPL_MASK);
					__vmx_vmwrite(HOST_DS_SELECTOR, _ds_selector() & ~RPL_MASK);
					__vmx_vmwrite(HOST_ES_SELECTOR, _es_selector() & ~RPL_MASK);
					__vmx_vmwrite(HOST_FS_SELECTOR, _fs_selector() & ~RPL_MASK);
					__vmx_vmwrite(HOST_GS_SELECTOR, _gs_selector() & ~RPL_MASK);
					__vmx_vmwrite(HOST_TR_SELECTOR, trSelector & ~RPL_MASK);

					__vmx_vmwrite(HOST_FS_BASE, __readmsr(IA32_MSR_FS_BASE));
					__vmx_vmwrite(HOST_GS_BASE, __readmsr(IA32_MSR_GS_BASE));
					__vmx_vmwrite(HOST_TR_BASE, GetSegmentBaseAddress(trSelector, gdtrBase));
					__vmx_vmwrite(HOST_IDTR_BASE, idtrBase);
					__vmx_vmwrite(HOST_GDTR_BASE, gdtrBase);

					__vmx_vmwrite(HOST_SYSENTER_CS, __readmsr(IA32_MSR_SYSENTER_CS));
					__vmx_vmwrite(HOST_SYSENTER_EIP, __readmsr(IA32_MSR_SYSENTER_EIP));
					__vmx_vmwrite(HOST_SYSENTER_ESP, __readmsr(IA32_MSR_SYSENTER_ESP));

					__vmx_vmwrite(HOST_RSP, (PTR_TYPE)(pVirtCpuInfo[cpuIdx]->stack1 + sizeof pVirtCpuInfo[cpuIdx]->stack1 - sizeof(PTR_TYPE) * 2 - 0x40));
					__vmx_vmwrite(HOST_RIP, (PTR_TYPE)VmEntry);

					PTR_TYPE* pParams = (PTR_TYPE*)(pVirtCpuInfo[cpuIdx]->stack1 + sizeof pVirtCpuInfo[cpuIdx]->stack1 - sizeof(PTR_TYPE) * 2 - 0x40);
					pParams[0] = (PTR_TYPE)&pVirtCpuInfo[cpuIdx]->regsBackup.genericRegisters1;
					pParams[1] = (PTR_TYPE)pVirtCpuInfo[cpuIdx];

					pParams = (PTR_TYPE*)(pVirtCpuInfo[cpuIdx]->stack2 + sizeof pVirtCpuInfo[cpuIdx]->stack2 - sizeof(PTR_TYPE));
					pParams[0] = (PTR_TYPE)&pVirtCpuInfo[cpuIdx]->regsBackup.genericRegisters2;
				}

				PTR_TYPE value = 0;
				__vmx_vmread(GUEST_IA32_EFER, &value);

				if (!enableSce)
					value &= ~(1ULL << SCE_ENABLE_OFFSET);
				else
					value |= (1ULL << SCE_ENABLE_OFFSET);

				__vmx_vmwrite(GUEST_IA32_EFER, value);

				//如何MSR HOOK插件存在，进入VM之前保存Guest和Host的MSR
				if (pMsrBackupRestorePlugin != NULL)
				{
					pMsrBackupRestorePlugin->SaveGuestMsrForCpu(cpuIdx);
					pMsrBackupRestorePlugin->SaveHostMsrForCpu(cpuIdx);
				}

				__vmx_vmlaunch();

				PTR_TYPE errCode = 0;
				__vmx_vmread(VM_INSTRUCTION_ERROR, &errCode);
				KdPrint(("VTXManager::EnterVirtualization(): CPU %u: __vmx_vmlaunch failed, error code = %LLu\n", cpuIdx, errCode));

				__vmx_off();

				return STATUS_INSUFFICIENT_RESOURCES;
			}

			return STATUS_SUCCESS;
		};

	return RunOnEachCore(0, cpuCnt, enterVirtualizationCore);
}

#pragma code_seg("PAGE")
void VTXManager::LeaveVirtualization()
{
	PAGED_CODE();

	//调用CPUID指令通知VMM退出
	auto coreAction = [this](UINT32 idx) -> NTSTATUS
		{
			if (pVirtCpuInfo[idx] != NULL)
			{
				PTR_TYPE regs[4] = { GUEST_CALL_VMM_VTXCALL_FUNCTION,0,EXIT_VTX_VTXCALL_SUBFUNCTION,0 };

				//如果已经进入虚拟化，则按照核心退出虚拟化
				if (pVirtCpuInfo[idx]->otherInfo.isInVirtualizaion)
				{
					SetRegsThenVTXCallWrapper(&regs[0], &regs[1], &regs[2], &regs[3]);
					pVirtCpuInfo[idx]->otherInfo.isInVirtualizaion = FALSE;
				}
			}
			return STATUS_SUCCESS;
		};

	RunOnEachCore(0, cpuCnt, coreAction);
}

#pragma code_seg()
void JumpToNextInstruction(PTR_TYPE& rip)
{
	PTR_TYPE value = 0;
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &value);
	rip += value;
}

/// <summary>
/// Inject interrupt or exception into guest
/// </summary>
/// <param name="InterruptType">INterrupt type</param>
/// <param name="Vector">IDT index</param>
/// <param name="WriteLength">Intruction length skip</param>
#pragma code_seg()
VOID VmxInjectEvent(INTERRUPT_TYPE InterruptType, UINT32 Vector, PTR_TYPE WriteLength)
{
	INTERRUPT_INJECT_INFO_FIELD InjectEvent = { 0 };

	InjectEvent.Fields.Vector = Vector;
	InjectEvent.Fields.Type = InterruptType;
	InjectEvent.Fields.DeliverErrorCode = 0;
	InjectEvent.Fields.Valid = 1;

	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, InjectEvent.AsUInt32);
	if (WriteLength > 0)
		__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, WriteLength);
}

#pragma code_seg()
void VTXManager::VmExitHandler(VirtCpuInfo* pVMMVirtCpuInfo, GenericRegisters* pGuestRegisters)
{
	PTR_TYPE exitReason = 0;
	__vmx_vmread(VM_EXIT_REASON, &exitReason);

	switch ((VM_EXIT_REASON_ENUM)exitReason)
	{
	case EXIT_REASON_EXCEPTION_NMI:
	{
		INTERRUPT_INFO_FIELD event = { 0 };
		PTR_TYPE errorCode = 0;
		PTR_TYPE instructionLength = 0;
		PTR_TYPE value = 0;
		__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instructionLength);

		__vmx_vmread(VM_EXIT_INTR_INFO, &value);
		event.AsUInt32 = (UINT32)value;
		__vmx_vmread(VM_EXIT_INTR_ERROR_CODE, &errorCode);
		if (event.Fields.ErrorCodeValid)
			__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, errorCode);

		switch (event.Fields.Type)
		{
		case INTERRUPT_NMI:
		{
			VmxInjectEvent(INTERRUPT_NMI, NMI_EXCEPTION_VECTOR_INDEX, 0);
			break;
		}
		case INTERRUPT_HARDWARE_EXCEPTION:
		{
			VmxInjectEvent((INTERRUPT_TYPE)event.Fields.Type, event.Fields.Vector, instructionLength);
			break;
		}

		case INTERRUPT_SOFTWARE_EXCEPTION:
		{
			switch (event.Fields.Vector)
			{
			case BP_EXCEPTION_VECTOR_INDEX:
			{
				if (pBreakpointInterceptPlugin != NULL && pBreakpointInterceptPlugin->HandleBreakpoint(pVMMVirtCpuInfo, pGuestRegisters))
					break;

				VmxInjectEvent(INTERRUPT_SOFTWARE_EXCEPTION, BP_EXCEPTION_VECTOR_INDEX, instructionLength);
				break;
			}
			case UD_EXCEPTION_VECTOR_INDEX:
			{
				if (pInvalidOpcodeInterceptPlugin != NULL && pInvalidOpcodeInterceptPlugin->HandleInvalidOpcode(pVMMVirtCpuInfo, pGuestRegisters))
					break;

				VmxInjectEvent(INTERRUPT_SOFTWARE_EXCEPTION, UD_EXCEPTION_VECTOR_INDEX, instructionLength);
				break;
			}
			case DB_EXCEPTION_VECTOR_INDEX:
			{
				if (pSingleStepInterceptPlugin != NULL && pSingleStepInterceptPlugin->HandleSignleStep(pVMMVirtCpuInfo, pGuestRegisters))
					break;

				VmxInjectEvent(INTERRUPT_SOFTWARE_EXCEPTION, DB_EXCEPTION_VECTOR_INDEX, instructionLength);
				break;
			}
			default:
			{
				VmxInjectEvent((INTERRUPT_TYPE)event.Fields.Type, event.Fields.Vector, instructionLength);
				break;
			}
			}
			break;
		}
		default:
		{
			VmxInjectEvent((INTERRUPT_TYPE)event.Fields.Type, event.Fields.Vector, instructionLength);
			break;
		}
		}
		break;
	}
	case EXIT_REASON_TRIPLE_FAULT:
	{
		PTR_TYPE value = 0;
		__vmx_vmread(GUEST_LINEAR_ADDRESS, &value);
		__debugbreak();
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;
	}
	case EXIT_REASON_CPUID:
	{
		JumpToNextInstruction(pGuestRegisters->rip);

		if (pCpuIdInterceptPlugin != NULL && pCpuIdInterceptPlugin->HandleCpuid(pVMMVirtCpuInfo, pGuestRegisters))
			break;

		int cpuInfo[4] = {};
		__cpuidex(cpuInfo, (int)pGuestRegisters->rax, (int)pGuestRegisters->rcx);

		if (pGuestRegisters->rax == 1)
			cpuInfo[3] &= ~(1U << VTX_BIT_IN_ECX_OFFSET);

		pGuestRegisters->rax = cpuInfo[0];
		pGuestRegisters->rbx = cpuInfo[1];
		pGuestRegisters->rcx = cpuInfo[2];
		pGuestRegisters->rdx = cpuInfo[3];
		break;
	}
	case EXIT_REASON_INVD:
	case EXIT_REASON_WBINVD:
	{
		JumpToNextInstruction(pGuestRegisters->rip);
		__wbinvd();
		break;
	}
	case EXIT_REASON_RDTSC:
	{
		JumpToNextInstruction(pGuestRegisters->rip);
		ULARGE_INTEGER tsc = { 0 };
		tsc.QuadPart = __rdtsc();
		pGuestRegisters->rdx = tsc.HighPart;
		pGuestRegisters->rax = tsc.LowPart;
		break;
	}
	case EXIT_REASON_CR_ACCESS:
	{
		JumpToNextInstruction(pGuestRegisters->rip);

		auto getRegPtr = [](GenericRegisters& guestRegisters, UINT32 regIdx) -> PTR_TYPE*
			{
				switch (regIdx)
				{
				case 0: return &guestRegisters.rax;
				case 1: return &guestRegisters.rcx;
				case 2: return &guestRegisters.rdx;
				case 3: return &guestRegisters.rbx;
				case 4: return &guestRegisters.rsp;
				case 5: return &guestRegisters.rbp;
				case 6: return &guestRegisters.rsi;
				case 7: return &guestRegisters.rdi;
				case 8: return &guestRegisters.r8;
				case 9: return &guestRegisters.r9;
				case 10: return &guestRegisters.r10;
				case 11: return &guestRegisters.r11;
				case 12: return &guestRegisters.r12;
				case 13: return &guestRegisters.r13;
				case 14: return &guestRegisters.r14;
				case 15: return &guestRegisters.r15;
				default: return NULL;
				}
			};

		MOV_CR_QUALIFICATION data = {};
		__vmx_vmread(EXIT_QUALIFICATION, (size_t*)&data);
		PTR_TYPE* regPtr = getRegPtr(*pGuestRegisters, data.Fields.Register);
		VPID_CTX ctx = {};

		switch (data.Fields.AccessType)
		{
		case TYPE_MOV_TO_CR:
		{
			switch (data.Fields.ControlRegister)
			{
			case 0:
			{
				__vmx_vmwrite(GUEST_CR0, *regPtr);
				__vmx_vmwrite(CR0_READ_SHADOW, *regPtr);
				break;
			}
			case 3:
			{

				PTR_TYPE cr4 = 0;
				__vmx_vmread(GUEST_CR4, &cr4);

				if ((cr4 & 0x20000) && (*regPtr & (1ull << 63)))
					*regPtr &= ~(1ull << 63);

				__vmx_vmwrite(GUEST_CR3, *regPtr);
				break;
			}
			case 4:
			{
				__vmx_vmwrite(GUEST_CR4, *regPtr);
				__vmx_vmwrite(CR4_READ_SHADOW, *regPtr);

				break;
			}
			default:
			{
				__debugbreak();
				KeBugCheck(MANUALLY_INITIATED_CRASH);
				break;
			}
			}

			if (features.VPID)
				_invvpid(INV_ALL_CONTEXTS, &ctx);

			break;
		}
		case TYPE_MOV_FROM_CR:
		{
			switch (data.Fields.ControlRegister)
			{
			case 0:
			{
				__vmx_vmread(GUEST_CR0, regPtr);
				break;
			}
			case 3:
			{
				__vmx_vmread(GUEST_CR3, regPtr);
				break;
			}
			case 4:
			{
				__vmx_vmread(GUEST_CR4, regPtr);
				break;
			}
			default:
			{
				__debugbreak();
				KeBugCheck(MANUALLY_INITIATED_CRASH);
				break;
			}
			}
			break;
		}
		default:
		{
			__debugbreak();
			KeBugCheck(MANUALLY_INITIATED_CRASH);
			break;
		}
		}
		break;
	}
	case EXIT_REASON_INVALID_GUEST_STATE:
	case EXIT_REASON_MSR_LOADING:
	case EXIT_REASON_MACHINE_CHECK:
	case EXIT_REASON_EPT_MISCONFIG:
	case EXIT_REASON_NMI_WINDOW:
	{
		__debugbreak();
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;
	}
	case EXIT_REASON_RDTSCP:
	{
		JumpToNextInstruction(pGuestRegisters->rip);
		unsigned int tscAux = 0;
		ULARGE_INTEGER tsc = { 0 };
		tsc.QuadPart = __rdtscp(&tscAux);
		pGuestRegisters->rdx = tsc.HighPart;
		pGuestRegisters->rax = tsc.LowPart;
		pGuestRegisters->rcx = tscAux;
		break;
	}
	case EXIT_REASON_XSETBV:
	{
		JumpToNextInstruction(pGuestRegisters->rip);
		_xsetbv((ULONG)pGuestRegisters->rcx, pGuestRegisters->rdx << 32 | pGuestRegisters->rax);
		break;
	}
	case EXIT_REASON_VMCALL:
	{
		if (pVmCallInterreptPlugin != NULL && pVmCallInterreptPlugin->HandleVmCall(pVMMVirtCpuInfo, pGuestRegisters))
			break;

		bool handled = false;

		switch ((UINT32)pGuestRegisters->rax)
		{
		case GUEST_CALL_VMM_VTXCALL_FUNCTION:
		{
			switch ((UINT32)pGuestRegisters->rcx)
			{
			case EXIT_VTX_VTXCALL_SUBFUNCTION:
			{
				handled = true;

				JumpToNextInstruction(pGuestRegisters->rip);

				//如果不是从内核模式调用退出则忽略
				if (!IsKernelAddress((PVOID)pGuestRegisters->rip))
					break;

				PTR_TYPE value = 0;
				__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &value);

				//通过
				//设置pGuestRegisters->extraInfo1为&pVMMVirtCpuInfo->regsBackup.genericRegisters1 和 
				//设置pGuestRegisters->extraInfo2为pVMMVirtCpuInfo->guestVmcb.controlFields.nRip
				//告知_run_svm_vmrun退出vmm
				pGuestRegisters->extraInfo1 = (UINT64)&pVMMVirtCpuInfo->regsBackup.genericRegisters1;

				__vmx_off();

				__writecr0(pVMMVirtCpuInfo->regsBackup.originCr0);
				__writecr4(pVMMVirtCpuInfo->regsBackup.originCr4);

				break;
			}
			case IS_IN_VTX_VTXCALL_SUBFUNCTION:
			{
				handled = true;

				JumpToNextInstruction(pGuestRegisters->rip);

				*reinterpret_cast<UINT32*>(&pGuestRegisters->rax) = 'IN';
				*reinterpret_cast<UINT32*>(&pGuestRegisters->rbx) = 'TEL';
				*reinterpret_cast<UINT32*>(&pGuestRegisters->rcx) = 'VTX';

				break;
			}
			default:
				break;
			}
		}
		}

		if (handled)
			break;

		__debugbreak();
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;
	}
	case EXIT_REASON_MSR_READ:
	{
		ULONG32 msrNum = (ULONG32)pGuestRegisters->rcx;

		if (pMsrInterceptPlugin != NULL && pMsrInterceptPlugin->HandleMsrImterceptRead(pVMMVirtCpuInfo, pGuestRegisters, msrNum))
			break;

		JumpToNextInstruction(pGuestRegisters->rip);

		LARGE_INTEGER msrValue = { 0 };

		switch (msrNum)
		{
		case IA32_MSR_FS_BASE:
		{
			__vmx_vmread(GUEST_FS_BASE, (size_t*)&msrValue.QuadPart);
			break;
		}
		case IA32_MSR_GS_BASE:
		{
			__vmx_vmread(GUEST_GS_BASE, (size_t*)&msrValue.QuadPart);
			break;
		}
		case IA32_MSR_PAT:
		{
			__vmx_vmread(GUEST_IA32_PAT, (size_t*)&msrValue.QuadPart);
			break;
		}
		case IA32_MSR_EFER:
		{
			__vmx_vmread(GUEST_IA32_EFER, (size_t*)&msrValue.QuadPart);
			break;
		}
		case IA32_MSR_SYSENTER_CS:
		{
			__vmx_vmread(GUEST_SYSENTER_CS, (size_t*)&msrValue.QuadPart);
			break;
		}
		case IA32_MSR_SYSENTER_EIP:
		{
			__vmx_vmread(GUEST_SYSENTER_EIP, (size_t*)&msrValue.QuadPart);
			break;
		}
		case IA32_MSR_SYSENTER_ESP:
		{
			__vmx_vmread(GUEST_SYSENTER_ESP, (size_t*)&msrValue.QuadPart);
			break;
		}
		// Report VMX as locked
		case IA32_MSR_FEATURE_CONTROL:
		{
			msrValue.QuadPart = __readmsr(msrNum);
			PIA32_FEATURE_CONTROL_MSR pMSR = (PIA32_FEATURE_CONTROL_MSR)&msrValue.QuadPart;
			pMSR->Fields.EnableVTXon = FALSE;
			pMSR->Fields.Lock = TRUE;
			break;
		}
		default:
		{
			msrValue.QuadPart = __readmsr(msrNum);
			break;
		}
		}
		*reinterpret_cast<UINT32*>(&pGuestRegisters->rax) = msrValue.LowPart;
		*reinterpret_cast<UINT32*>(&pGuestRegisters->rdx) = msrValue.HighPart;
		break;
	}
	case EXIT_REASON_MSR_WRITE:
	{
		ULONG32 msrNum = (ULONG32)pGuestRegisters->rcx;

		if (pMsrInterceptPlugin != NULL && pMsrInterceptPlugin->HandleMsrInterceptWrite(pVMMVirtCpuInfo, pGuestRegisters, msrNum))
			break;

		JumpToNextInstruction(pGuestRegisters->rip);

		LARGE_INTEGER msrValue = { 0 };

		msrValue.LowPart = (ULONG32)pGuestRegisters->rax;
		msrValue.HighPart = (ULONG32)pGuestRegisters->rdx;

		switch (msrNum)
		{
		case IA32_MSR_FS_BASE:
		{
			__vmx_vmwrite(GUEST_FS_BASE, msrValue.QuadPart);
			break;
		}
		case IA32_MSR_GS_BASE:
		{
			__vmx_vmwrite(GUEST_GS_BASE, msrValue.QuadPart);
			break;
		}
		case IA32_MSR_PAT:
		{
			__vmx_vmwrite(GUEST_IA32_PAT, msrValue.QuadPart);
			break;
		}
		case IA32_MSR_EFER:
		{
			__vmx_vmwrite(GUEST_IA32_EFER, msrValue.QuadPart);
			break;
		}
		case IA32_MSR_SYSENTER_CS:
		{
			__vmx_vmwrite(GUEST_SYSENTER_CS, msrValue.QuadPart);
			break;
		}
		case IA32_MSR_SYSENTER_EIP:
		{
			__vmx_vmwrite(GUEST_SYSENTER_EIP, msrValue.QuadPart);
			break;
		}
		case IA32_MSR_SYSENTER_ESP:
		{
			__vmx_vmwrite(GUEST_SYSENTER_ESP, msrValue.QuadPart);
			break;
		}

		case IA32_MSR_VTX_BASIC:
		case IA32_MSR_VTX_PINBASED_CTLS:
		case IA32_MSR_VTX_PROCBASED_CTLS:
		case IA32_MSR_VTX_EXIT_CTLS:
		case IA32_MSR_VTX_ENTRY_CTLS:
		case IA32_MSR_VTX_MISC:
		case IA32_MSR_VTX_CR0_FIXED0:
		case IA32_MSR_VTX_CR0_FIXED1:
		case IA32_MSR_VTX_CR4_FIXED0:
		case IA32_MSR_VTX_CR4_FIXED1:
		case IA32_MSR_VTX_VMCS_ENUM:
		case IA32_MSR_VTX_PROCBASED_CTLS2:
		case IA32_MSR_VTX_EPT_VPID_CAP:
		case IA32_MSR_VTX_TRUE_PINBASED_CTLS:
		case IA32_MSR_VTX_TRUE_PROCBASED_CTLS:
		case IA32_MSR_VTX_TRUE_EXIT_CTLS:
		case IA32_MSR_VTX_TRUE_ENTRY_CTLS:
		case IA32_MSR_VTX_VMFUNC:
			break;

		default:
			__writemsr(msrNum, msrValue.QuadPart);
		}
		break;
	}
	case EXIT_REASON_EPT_VIOLATION:
	{
		if (pEptVInterceptPlugin != NULL && pEptVInterceptPlugin->HandleEptViolation(pVMMVirtCpuInfo, pGuestRegisters))
			break;

		__debugbreak();
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;
	}
	case EXIT_REASOM_MTF:
	{
		if (pMTFInterceptPlugin != NULL && pMTFInterceptPlugin->HandleMTF(pVMMVirtCpuInfo, pGuestRegisters))
			break;

		__debugbreak();
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;
	}
	case EXIT_REASON_INVEPT:
	{
		JumpToNextInstruction(pGuestRegisters->rip);

		EPT_CTX ctx = {};
		_invept(INV_ALL_CONTEXTS, &ctx);
		break;
	}
	case EXIT_REASON_INVLPG:
	case EXIT_REASON_INVPCID:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_INVVPID:
	case EXIT_REASON_EXTERNAL_INTERRUPT:
	case EXIT_REASON_INIT:
	case EXIT_REASON_SIPI:
	case EXIT_REASON_IO_SMI:
	case EXIT_REASON_OTHER_SMI:
	case EXIT_REASON_PENDING_INTERRUPT:
	case EXIT_REASON_TASK_SWITCH:
	case EXIT_REASON_GETSEC:
	case EXIT_REASON_HLT:
	case EXIT_REASON_RDPMC:
	case EXIT_REASON_RSM:
	case EXIT_REASON_DR_ACCESS:
	case EXIT_REASON_IO_INSTRUCTION:
	case EXIT_REASON_RESERVED_35:
	case EXIT_REASON_MWAIT_INSTRUCTION:
	case EXIT_REASON_RESERVED_38:
	case EXIT_REASON_MONITOR_INSTRUCTION:
	case EXIT_REASON_PAUSE_INSTRUCTION:
	case EXIT_REASON_RESERVED_42:
	case EXIT_REASON_TPR_BELOW_THRESHOLD:
	case EXIT_REASON_APIC_ACCESS:
	case EXIT_REASON_VIRTUALIZED_EIO:
	case EXIT_REASON_XDTR_ACCESS:
	case EXIT_REASON_TR_ACCESS:
	case EXIT_REASON_PREEMPT_TIMER:
	case EXIT_REASON_APIC_WRITE:
	case EXIT_REASON_RDRAND:
	case EXIT_REASON_VMFUNC:
	case EXIT_REASON_RESERVED_60:
	case EXIT_REASON_RDSEED:
	case EXIT_REASON_RESERVED_62:
	case EXIT_REASON_XSAVES:
	case EXIT_REASON_XRSTORS:
	default:
	{
		PTR_TYPE instructionLength = 0;
		__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instructionLength);
		VmxInjectEvent(INTERRUPT_SOFTWARE_EXCEPTION, UD_EXCEPTION_VECTOR_INDEX, instructionLength);
		return;
	}
	}

	if (pGuestRegisters->rflags & (1ULL << EFLAGS_TF_OFFSET))
	{
		PTR_TYPE instructionLength = 0;
		__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instructionLength);
		VmxInjectEvent(INTERRUPT_SOFTWARE_EXCEPTION, DB_EXCEPTION_VECTOR_INDEX, instructionLength);
	}
}