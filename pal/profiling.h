#ifndef __PROFILING_H__
#define __PROFILING_H__

#include <bottlecap/profiling.h>

#ifdef BOTTLE_CAP_PROFILE

void profiling_record(const char* function, unsigned long type, const char* description);
timing_point_t* profiling_get();
unsigned int profiling_count();

#define profiling_start(x) profiling_record(__FUNCTION__, PROFILE_ENTER,  x)
#define profiling_stop(x) profiling_record(__FUNCTION__, PROFILE_EXIT,   x)
#define profiling_lap(x) profiling_record(__FUNCTION__, PROFILE_INSIDE, x)

#define MAX_TIMING_POINTS 512

#else //BOTTLE_CAP_PROFILE

#define profiling_record(function, type, desc)
#define profiling_get() NULL
#define profiling_count() 0

#define profiling_start(x)
#define profiling_stop(x)
#define profiling_lap(x)

#endif //BOTTLE_CAP_PROFILE

#endif /* __PROFILING_H__ */

