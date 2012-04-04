#ifndef __BOTTLECAP_PROFILING_H__
#define __BOTTLECAP_PROFILING_H__

#include <stdint.h>

enum {
	PROFILE_NULL = 0,
	PROFILE_ENTER,
	PROFILE_EXIT,
	PROFILE_INSIDE,
};

typedef struct {
	const char* function;
	const char* description;
	unsigned long type;
	uint32_t timestamp;
} timing_point_t;

#endif /* __BOTTLECAP_PROFILING_H__ */

