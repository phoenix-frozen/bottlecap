#include <stdio.h>

#include <bottlecap/bottlecalls.h>

#include "params.h"

int do_real_work(void) {
	// Get the return code from a bottlecap run
	int32_t* errcode;
	if(pm_get_addr(BOTTLE_CALL, (char**)&errcode) != sizeof(*errcode))
		return -1;

	printf("Run returned: %d\n", *errcode);

	return 0;
}
