#ifndef KERNEL_DPC_WORKER_H
#define KERNEL_DPC_WORKER_H

#include "ArgPack.h"
#include "Basic.h"

constexpr UINT32 threadTag = 'THRE';

class KernelDpcWorker
{
	const static UINT32 NOT_SPECTIFY_PROCESSOR = 0xFFFFFFFF;

	HANDLE hThread;
	KDPC dpc;
	LONG isEnd;
	UINT64 returnValue;

	template<typename ArgPackT, typename Func>
	#pragma code_seg()
	struct Pack
	{
		KernelDpcWorker* _this;
		ArgPackT argPack;
		Func func;
		Pack(ArgPackT&& _argPack, Func&& _func) : argPack(static_cast<ArgPackT&&>(_argPack)), func(static_cast<Func&&>(_func)), _this(NULL) {}
	};

	
	template<typename Pack>
	#pragma code_seg()
	static void ThreadEntry(_In_ struct _KDPC* Dpc,
		_In_opt_ PVOID DeferredContext,
		_In_opt_ PVOID SystemArgument1,
		_In_opt_ PVOID SystemArgument2)
	{
		UNREFERENCED_PARAMETER(DeferredContext);
		UNREFERENCED_PARAMETER(SystemArgument2);
		UNREFERENCED_PARAMETER(Dpc);

		Pack* pack = (Pack*)SystemArgument1;
		if (pack != NULL)
		{
			pack->_this->returnValue = UnpackArgsAndCall::UnpackAndCall<UINT64>(pack->func, pack->argPack);
			CallDestroyer<Pack>(pack);
			FreeNonPagedMem(pack, threadTag);
			InterlockedAdd((volatile LONG*)&pack->_this->isEnd, 1);
		}
	}

	KernelDpcWorker(const KernelDpcWorker&) = delete;
	KernelDpcWorker& operator=(const KernelDpcWorker&) = delete;

public:
	#pragma code_seg()
	KernelDpcWorker() : hThread(NULL), returnValue(NULL), isEnd(0) {}

	template<typename ArgPackT, typename Func>
	#pragma code_seg()
	KernelDpcWorker(UINT32 cpuIdx, Func&& func, ArgPackT&& argPack) : hThread(NULL), returnValue(NULL), isEnd(0)
	{
		Pack<ArgPackT, Func>* pack = (Pack<ArgPackT, Func>*)AllocNonPagedMem(sizeof(Pack<ArgPackT, Func>), threadTag);

		if (pack == NULL)
			KeBugCheck(MEMORY_MANAGEMENT);

		new (pack) Pack<ArgPackT, Func>(static_cast<ArgPackT&&>(argPack), static_cast<Func&&>(func));

		pack->_this = this;

		KeInitializeDpc(&dpc, ThreadEntry<Pack<ArgPackT, Func>>, pack);

		if (cpuIdx != -1)
			KeSetTargetProcessorDpc(&dpc, (UCHAR)cpuIdx);

		KeInsertQueueDpc(&dpc, pack, NULL);
	}

	#pragma code_seg()
	LONG ExecuteIsEnd()
	{
		return InterlockedCompareExchange(&isEnd, 1, 1);
	}

	#pragma code_seg()
	KernelDpcWorker(KernelDpcWorker&& other)
	{
		*this = static_cast<KernelDpcWorker&&>(other);
	}

	#pragma code_seg()
	KernelDpcWorker& operator=(KernelDpcWorker&& other)
	{
		if (this == &other)
			return *this;
		hThread = other.hThread;
		other.hThread = NULL;
		returnValue = other.returnValue;
		returnValue = NULL;
		isEnd = other.isEnd;
		isEnd = NULL;
		returnValue = other.returnValue;
		returnValue = 0;
		dpc = other.dpc;
		dpc = {};
		return *this;
	}

	#pragma code_seg()
	UINT64 GetReturnValue() { return returnValue; }

	#pragma code_seg()
	HANDLE GetHandle() { return hThread; }
};

class KernelDpcWorkerFactory
{
	template<typename OriginType>
	class GetRReferenceType
	{
	public:
		using RReferenceType = OriginType&&;
	};

	template<typename OriginType>
	class GetPointerType
	{
	public:
		using PointerType = OriginType*;
	};

public:
	template<typename Func, typename ...Args>
	#pragma code_seg()
	static auto CreateKernelDpcWorker(UINT32 cpuIndx, Func&& func, Args... args)
	{
		auto argPack = PackArgs::pack(args...);
		return KernelDpcWorker(cpuIndx,
			static_cast<GetRReferenceType<decltype(func)>::RReferenceType>(func),
			static_cast<GetRReferenceType<decltype(argPack)>::RReferenceType>(argPack));
	}
};


#endif
