#ifdef BOTTLE_CAP_PROFILE

#include "profiling.h"

#ifndef MAX_TIMING_POINTS
#define MAX_TIMING_POINTS 512
#endif  //MAX_TIMING_POINTS

static timing_point_t timing_points[MAX_TIMING_POINTS];

static timing_point_t* next = timing_points;

//XXX: assumes 32-bit
static inline uint64_t rdtsc(void) __attribute__((always_inline));
static inline uint64_t rdtsc(void) {
	uint64_t temp;
	asm volatile ("rdtsc"
			: "=A" (temp) //output
			: //input
			: //clobber
	);
	return temp;
}

void profiling_record(const char* function, unsigned long type, const char* description) __attribute__((aligned(64)));
void profiling_record(const char* function, unsigned long type, const char* description) {
	if(next >= timing_points + MAX_TIMING_POINTS)
		return;

	timing_point_t* cur = next++;

	cur->function = function;
	cur->description = description;
	cur->type = type;
	cur->timestamp = (uint32_t)(rdtsc() >> 6ULL);
}

unsigned int profiling_count() {
	return next - timing_points;
}

timing_point_t* profiling_get() {
	return timing_points;
}

#endif //BOTTLE_CAP_PROFILE

