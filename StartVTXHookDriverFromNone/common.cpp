#include "Basic.h"

#define EXCEPTION_ILLEGAL_INSTRUCTION       STATUS_ILLEGAL_INSTRUCTION

extern "C" void SetRegsThenVTXCall(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx);

bool SetRegsThenVTXCallWrapper(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx)
{
	__try
	{
		SetRegsThenVTXCall(rax, rbx, rcx, rdx);
		return true;
	}
	__except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		return false;
	}
}
