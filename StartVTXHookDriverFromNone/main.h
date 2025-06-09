#ifndef MAIN_H
#define MAIN_H

#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include <intrin.h>
#include "VTX.h"
#include "Hook.h"
#include "PageTable.h"
#include "Basic.h"

//二选一取消注释，测试驱动的两个功能
#define TEST_EPT_HOOK
//#define TEST_MSR_HOOK

//是否测试NPT HOOK删除
//#define TEST_NPT_HOOK_REMOVE

class GlobalManager : public IManager
{
	VTXManager vtxManager;
#if defined(TEST_EPT_HOOK)
	EptHookManager eptHookManager;
	FunctionCallerManager functionCallerManager;
#else
	MsrHookManager<1> msrHookManager;
#endif
public:

#if defined(TEST_EPT_HOOK)
	void HookApi();
#else
	void SetMsrHookParameters();
	void EnableMsrHook();
#endif
	
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual ~GlobalManager();
};

#endif
