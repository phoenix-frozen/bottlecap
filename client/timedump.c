#include <stdio.h>
#include <assert.h>

#include <bottlecap/bottlecalls.h>
#include <bottlecap/errors.h>
#include <bottlecap/profiling.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "params.h"

static char* profiling_types[] = {
	"PROFILE_NULL",
	"PROFILE_ENTER",
	"PROFILE_EXIT",
	"PROFILE_INSIDE",
};

#define PROF_TYPE(i) profiling_types[i]

#define PROF_STRING(i) (((i) == NULL) ? "" : (char*)(((uint32_t)pal) + ((uint32_t)(i))))

int do_real_work(void) {
	//bring in timing points
	//XXX: warning, 32-bit assumption
	timing_point_t* data_in;
	int size;
	if((size = pm_get_addr(BOTTLE_PROFILING, (char**)&data_in)) <= 0) {
		printf("BOTTLECAP: Could not get timing data\n");
		return -EINVAL;
	}

	assert((size % sizeof(timing_point_t)) == 0);
	size = size / sizeof(timing_point_t);

	//mmap pal.bin
	int fd_in = open("pal.bin", O_RDONLY);
	if(fd_in == -1) {
		printf("Couldn't open pal.bin\n");
		return -1;
	}
	struct stat sb;
	if(fstat(fd_in, &sb) == -1) {
		printf("Couldn't stat flicker.out\n");
		return -1;
	}
	void* pal = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd_in, 0);
	if(pal == NULL || pal == MAP_FAILED) {
		printf("Couldn't mmap flicker.out\n");
		return -1;
	}
	close(fd_in);

	printf("PAL at %p\n", pal);

	for(int i = 0; i < size; i++) {
		printf("PROF %s: %s (%s) %p\n",
				PROF_STRING(data_in[i].function),
				PROF_STRING(data_in[i].description),
				PROF_TYPE(data_in[i].type),
				(void*)data_in[i].timestamp);
	}

	return 0;
}
