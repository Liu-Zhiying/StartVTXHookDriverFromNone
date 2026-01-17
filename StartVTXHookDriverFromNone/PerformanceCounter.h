#ifndef PERFORMANCE_COUNTER_H
#define PERFORMANCE_COUNTER_H

#include "Basic.h"


template<typename Func>
class PerformanceCounter
{
	LARGE_INTEGER begTime = {};
	LARGE_INTEGER endTime = {};
	LARGE_INTEGER frequency = {};
	Func& func;

public:

	PerformanceCounter(Func& _func) : func(_func)
	{
		begTime = KeQueryPerformanceCounter(&frequency);
	}

	~PerformanceCounter()
	{
		endTime = KeQueryPerformanceCounter(NULL);
		func(begTime, endTime, frequency);
	}
};

#endif
