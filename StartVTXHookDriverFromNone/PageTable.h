#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

#include "Basic.h"
#include "VTX.h"
#include <intrin.h>

constexpr ULONG PT_TAG = MAKE_TAG('p', 't', 'm', ' ');

typedef union
{
	struct
	{
		UINT64 readAccess : 1;
		UINT64 writeAccess : 1;
		UINT64 executeAccess : 1;
		UINT64 memoryType : 3;
		UINT64 ignorePat : 1;
		UINT64 largePage : 1;
		UINT64 accessed : 1;
		UINT64 dirty : 1;
		UINT64 userModeExecute : 1;
		UINT64 reserved1 : 1;
		UINT64 pageFrameNumber : 36;
		UINT64 reserved2 : 9;
		UINT64 verifyGuestPaging : 1;
		UINT64 pagingWriteAccess : 1;
		UINT64 reserved3 : 1;
		UINT64 supervisorShadowStack : 1;
		UINT64 reserved4 : 2;
		UINT64 suppressVe : 1;
	} fields;
	UINT64 data;
} EptEntry;

struct EptPageTable
{
	typedef EptEntry EntryType;
	EptEntry entries[0x200];
};

/// <summary>
/// Exit qualification for EPT violation
/// </summary>
typedef union _EPT_VIOLATION_DATA
{
	ULONG64 AsUInt64;
	struct
	{
		ULONG64 Read : 1;           // Read access
		ULONG64 Write : 1;          // Write access
		ULONG64 Execute : 1;        // Execute access
		ULONG64 PTERead : 1;        // PTE entry has read access
		ULONG64 PTEWrite : 1;       // PTE entry has write access
		ULONG64 PTEExecute : 1;     // PTE entry has execute access
		ULONG64 Reserved1 : 1;      // 
		ULONG64 GuestLinear : 1;    // GUEST_LINEAR_ADDRESS field is valid
		ULONG64 FailType : 1;       // 
		ULONG64 Reserved2 : 3;      // 
		ULONG64 NMIBlock : 1;       // NMI unblocking due to IRET
		ULONG64 Reserved3 : 51;     // 
	} Fields;
} EPT_VIOLATION_DATA, * PEPT_VIOLATION_DATA;

typedef union
{
	struct
	{
		UINT64 variableRangeCount : 8;
		UINT64 fixedRangeSupported : 1;
		UINT64 reserved1 : 1;
		UINT64 wcSupported : 1;
		UINT64 smrrSupported : 1;
		UINT64 reserved2 : 52;
	} fields;
	UINT64 data;
} IA32MtrrCapabilities;

typedef union
{
	struct
	{
		UINT64 defaultMemoryType : 3;
		UINT64 reserved1 : 7;
		UINT64 fixedRangeMtrrEnable : 1;
		UINT64 mtrrEnable : 1;
		UINT64 reserved2 : 52;
	} fields;
	UINT64 data;
} IA32MtrrDefType;

typedef union
{
	struct
	{
		UINT64 type : 8;
		UINT64 reserved1 : 4;
		UINT64 pageFrameNumber : 36;
		UINT64 reserved2 : 16;
	} fields;
	UINT64 data;
} IA32MtrrPhysBase;

typedef union
{
	struct
	{
		UINT64 reserved1 : 11;
		UINT64 valid : 1;
		UINT64 pageFrameNumber : 36;
		UINT64 reserved2 : 16;
	} flelds;
	UINT64 data;
} IA32MtrrPhysMask;

struct MtrrData {
	IA32MtrrCapabilities cap;
	IA32MtrrDefType defType;

	// fixed-range MTRRs
	struct {
		// TODO: implement
	} fixed;

	struct {
		IA32MtrrPhysBase base;
		IA32MtrrPhysMask mask;
	} variable[64];

	UINT32 varCount;
};

MtrrData ReadMtrrData();

//�����EPTҳ���¼��Ŀ
struct PageTableRecord
{
	PTR_TYPE pVirtAddr;
	PTR_TYPE pPhyAddr;
#pragma code_seg()
	PageTableRecord() : pVirtAddr(NULL), pPhyAddr(NULL) {}
#pragma code_seg()
	PageTableRecord(PTR_TYPE _pVirtAddr, PTR_TYPE _pPhyAddr) : pVirtAddr(_pVirtAddr), pPhyAddr(_pPhyAddr) {}
#pragma code_seg()
	~PageTableRecord() {}
};

//EPTҳ���¼������¼���з�����ʼ����EPTҳ��������ַ�������ַ
//ʹ�ü򵥵Ĺ�ϣ��ʵ�֣���ѯ�ٶȻ��һЩ
template<SIZE_TYPE bucketCnt>
class PageTableRecordBacket
{
	KernelVector<PageTableRecord, PT_TAG> data[bucketCnt];

	static SIZE_TYPE GetBucketIdx(PTR_TYPE pa)
	{
		return (pa >> 12) % bucketCnt;
	}

public:
#pragma code_seg()
	PageTableRecordBacket() {}
	//�ƶ�����Ϳ���
#pragma code_seg()
	PageTableRecordBacket(PageTableRecordBacket&& other)
	{
		*this = static_cast<PageTableRecordBacket&&>(other);
	}
#pragma code_seg()
	PageTableRecordBacket& operator=(PageTableRecordBacket&& other)
	{
		if (&other != this)
		{
			for (SIZE_TYPE i = 0; i < bucketCnt; i++)
				data[i] = static_cast<KernelVector<PageTableRecord, PT_TAG>&&>(other.data[i]);
		}
		return *this;
	}
	//��Ŀ����
#pragma code_seg()
	SIZE_TYPE Length() const
	{
		SIZE_TYPE result = 0;
		for (auto& bucket : data)
			result += bucket.Length();
		return result;
	}
	//�����Ŀ
#pragma code_seg()
	void PushBack(const PageTableRecord& record)
	{
		data[GetBucketIdx(record.pPhyAddr)].PushBack(record);
	}
	//ͨ�������ַѰ����Ŀ����
#pragma code_seg()
	PTR_TYPE FindVaFromPa(PTR_TYPE pa) const
	{
		const KernelVector<PageTableRecord, PT_TAG>& bucket = data[GetBucketIdx(pa)];
		for (SIZE_TYPE idx = 0; idx < bucket.Length(); ++idx)
		{
			if (bucket[idx].pPhyAddr == pa)
				return bucket[idx].pVirtAddr;
		}
		return (PTR_TYPE)INVALID_ADDR;
	}
	//ɾ��������Ŀ
#pragma code_seg()
	void Clear()
	{
		for (auto& bucket : data)
			bucket.Clear();
	}
	//ͨ��������ȡ��Ŀ��ֻ����
#pragma code_seg()
	const PageTableRecord& operator[](SIZE_TYPE idx) const
	{
		KernelVector<PageTableRecord>* pBucket = NULL;
		SIZE_TYPE cnt = 0;
		for (auto& bucket : data)
		{
			if (cnt > idx)
				break;
			if (idx - cnt < bucket.Length())
			{
				pBucket = &bucket;
				break;
			}
			cnt += bucket.Length();
		}
		if (pBucket == NULL)
		{
			__debugbreak();
			KeBugCheck(MEMORY_MANAGEMENT);
		}
		return (*pBucket)[idx - cnt];
	}
	//ͨ��������ȡ��Ŀ����д��
#pragma code_seg()
	PageTableRecord& operator[](SIZE_TYPE idx)
	{
		KernelVector<PageTableRecord, PT_TAG>* pBucket = NULL;
		SIZE_TYPE cnt = 0;
		for (auto& bucket : data)
		{
			if (cnt > idx)
				break;
			if (idx - cnt < bucket.Length())
			{
				pBucket = &bucket;
				break;
			}
			cnt += bucket.Length();
		}
		if (pBucket == NULL)
		{
			__debugbreak();
			KeBugCheck(MEMORY_MANAGEMENT);
		}
		return (*pBucket)[idx - cnt];
	}
	//ͨ�������ַɾ����Ŀ
#pragma code_seg()
	bool RemoveByPa(PTR_TYPE pa)
	{
		SIZE_TYPE idx = GetBucketIdx(pa);
		KernelVector<PageTableRecord, PT_TAG>& bucket = data[idx];
		for (SIZE_TYPE i = 0; i < bucket.Length(); ++i)
		{
			if (bucket[i].pPhyAddr == pa)
			{
				bucket.Remove(i);
				return true;
			}
		}
		return false;
	}
};

using PageTableRecords3 = PageTableRecordBacket<0x1>;
using PageTableRecords2 = PageTableRecordBacket<0x10>;
using PageTableRecords1 = PageTableRecordBacket<0x40>;

class CoreEptPageTableManager;

//ҳ�������
class PageTableManager : public IManager, public IEptVInterceptPlugin, public IEptpProvider, public IMsrInterceptPlugin
{
public:
	//ҳ����Ŀ����������������дֻ�ǲ���дlambda���ʽ��������������һ��lambda���ʽ
	class EntrySetter
	{
		PageTableManager* pageTableManager;
	public:
#pragma code_seg()
		EntrySetter(PageTableManager* _pageTableManager) : pageTableManager(_pageTableManager) { PAGED_CODE(); NT_ASSERT(pageTableManager != NULL); }
#pragma code_seg()
		void operator()(EptEntry* pEntry, PTR_TYPE pfn, bool isLargePage, UINT32 level) const {
			{
				NT_ASSERT(level <= 4 && level >= 1);

				EptEntry permission = {};
				permission.data = pageTableManager->GetDefaultPermission(level);

				permission.fields.pageFrameNumber = pfn;
				permission.fields.largePage = isLargePage;

				*pEntry = permission;
			}
		}
	};

	friend class EptHookManager;

private:
	PTR_TYPE pSystemPxe;
	CoreEptPageTableManager* corePageTables;
	SIZE_TYPE pageTableCnt;
	EptEntry defaultPermissionLevel4;
	EptEntry defaultPermissionLevel3;
	EptEntry defaultPermissionLevel2;
	EptEntry defaultPermissionLevel1;
	EntrySetter entrySetter;
public:
#pragma code_seg("PAGE")
	PageTableManager() : pSystemPxe(NULL), corePageTables(NULL), pageTableCnt(0), entrySetter(this)
	{
		PAGED_CODE();

		//����Ĭ��Ȩ��
		defaultPermissionLevel3 = {};
		defaultPermissionLevel3.fields.readAccess = true;
		defaultPermissionLevel3.fields.writeAccess = true;
		defaultPermissionLevel3.fields.executeAccess = true;
		defaultPermissionLevel3.fields.memoryType = VTX_MEM_TYPE_UNCACHEABLE;

		defaultPermissionLevel4 = defaultPermissionLevel1 = defaultPermissionLevel2 = defaultPermissionLevel3;
	}
	//�������ص�msr�Ĵ���
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) override;
	//�������ص�msr��ȡ��true�����Ѿ�����false����δ����
	#pragma code_seg()
	virtual bool HandleMsrImterceptRead(VirtCpuInfo*, GenericRegisters*, UINT32) override { return false; }
	//�������ص�Msrд�룬true�����Ѿ�����false����δ����
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		UINT32 msrNum) override;
	void SetDefaultPermission(UINT64 permission, UINT32 level);
	UINT64 GetDefaultPermission(UINT32 level) const;
	virtual bool HandleEptViolation(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters) override;
	virtual PVOID GetEptpForCore(UINT32 cpuIdx) override;
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
#pragma code_seg()
	CoreEptPageTableManager* GetCoreEptPageTables() { return corePageTables; }
	SIZE_TYPE GetCoreEptPageTablesCnt() const { return pageTableCnt; }
#pragma code_seg("PAGE")
	virtual ~PageTableManager() { PAGED_CODE(); Deinit(); }
};

//ÿ�����ĵ�EPTҳ�������
class CoreEptPageTableManager
{
	//����ҳ��������ַ
	PTR_TYPE pEptPageTableVa;
	//����ҳ��������ַ
	PTR_TYPE pEptPageTablePa;
	PageTableRecords3 level3Records;
	PageTableRecords2 level2Records;
	PageTableRecords1 level1Records;
	PageTableManager::EntrySetter* pEntrySetter;

	void CoreEptPageTableManager::UpdateMemoryTypeSub(EptPageTable* pPsageTable, UINT32 level, const MtrrData& mtrrs);

public:
	//ɾ��Ĭ�Ϲ���
	CoreEptPageTableManager() = delete;
	//ʹ��PageTableManager::EntrySetter���죬PageTableManager::EntrySetter��������ҳ���Ĭ��Ȩ��
	CoreEptPageTableManager(PageTableManager::EntrySetter* _pEntrySetter) : pEptPageTableVa(INVALID_ADDR), pEntrySetter(_pEntrySetter), pEptPageTablePa(INVALID_ADDR) {}
	//�ƶ�����
#pragma code_seg()
	CoreEptPageTableManager(CoreEptPageTableManager&& other)
	{
		*this = static_cast<CoreEptPageTableManager&&>(other);
	}
	//�ƶ�����
#pragma	code_seg()
	CoreEptPageTableManager& operator=(CoreEptPageTableManager&& other)
	{
		if (&other != this)
		{
			pEntrySetter = other.pEntrySetter;
			pEptPageTableVa = other.pEptPageTableVa;
			level3Records = static_cast<PageTableRecords3&&>(other.level3Records);
			level2Records = static_cast<PageTableRecords2&&>(other.level2Records);
			level1Records = static_cast<PageTableRecords1&&>(other.level1Records);
			other.pEptPageTableVa = INVALID_ADDR;
		}
		return *this;
	}
#pragma code_seg("PAGE")
	~CoreEptPageTableManager() { PAGED_CODE(); Deinit(); }
	//ӳ��ȱҳ����
	NTSTATUS FixPageFault(PTR_TYPE startAddr, PTR_TYPE endAddr, bool usingLargePage);
	//isUsing Ϊ false ����ԭ��ҳ
	NTSTATUS UsingSmallPage(PTR_TYPE phyAddr, bool isUsing);
	//Сҳӳ�亯������ͬ��FixPageFault(begPhyAddr, endPhyAddr, false)
	NTSTATUS MapSmallPageByPhyAddr(PTR_TYPE begPhyAddr, PTR_TYPE endPhyAddr);
	//����Сҳ�����������ַ
	NTSTATUS SwapSmallPagePpn(PTR_TYPE phyAddr1, PTR_TYPE phyAddr2, UINT32 level);
	//��ȡָ�������ַ��Ӧ��EPTҳ�������PPN��Ӧ�������ַ
	NTSTATUS GetEptFinalAddrForPhyAddr(PTR_TYPE phyAddr, PTR_TYPE& pEptFinalAddr, PTR_TYPE& level);
	//�޸�������ײ�ҳ���Ȩ��
	void ChangeAllEndLevelPageTablePermession(EptEntry entry);
	//�޸��ض�ҳ���ֵ
	NTSTATUS ChangePageTableEntryPermession(PTR_TYPE pa, EptEntry entry, UINT32 level);
	void Deinit();
	NTSTATUS BuildEptPageTable();
#pragma code_seg()
	PTR_TYPE GetEptPageTableVa() const { return pEptPageTableVa; }
	PTR_TYPE GetEptPageTablePa() const { return pEptPageTablePa; }
	//ͨ�������ַҲҳ����Ѱ��ҳ���������ַ
	PVOID FindPageTableByPhyAddr(PTR_TYPE pa, UINT32 level) const;
	//����MTRR����EPTҳ����ڴ�����
	void UpdateMemoryType();
};

//��ѯ��ǰCR3������ҳ���������ַ
void GetSysPXEVirtAddr(PTR_TYPE* pPxeOut, PTR_TYPE pxePhyAddr);

#endif
