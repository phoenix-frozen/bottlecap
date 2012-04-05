#include <stdio.h>
#include <assert.h>

#include <bottlecap/bottlecalls.h>
#include <bottlecap/errors.h>

#include "params.h"

int do_real_work(void) {
	/* Set up attestation parameters
	 */

	//call number
	uint32_t call = 0;
	if(pm_append(BOTTLE_CALL, (char*)&call, sizeof(call)) != sizeof(call)) {
		printf("unable to append call number\n");
		return -ENOMEM;
	}

	//bring in bottle header and copy
	char* data_in;
	int size;
	if((size = pm_get_addr(BOTTLE_HEADER, &data_in)) <= 0) {
		printf("BOTTLECAP: Could not get header\n");
		return -EINVAL;
	}
	if(pm_append(BOTTLE_HEADER, data_in, size) != size) {
		printf("unable to append header\n");
		return -ENOMEM;
	}

	//bring in bottle table and copy
	if((size = pm_get_addr(BOTTLE_TABLE, &data_in)) <= 0) {
		printf("BOTTLECAP: Could not get table\n");
		return -EINVAL;
	}
	if(pm_append(BOTTLE_TABLE, data_in, size) != size) {
		printf("unable to append table\n");
		return -ENOMEM;
	}

	//slot number
	if((size = pm_get_addr(BOTTLE_INDEX, &data_in)) != sizeof(uint32_t)) {
		printf("BOTTLECAP: Could not get slot\n");
		return -EINVAL;
	}
	if(pm_append(BOTTLE_SLOTCOUNT, data_in, size) != size) {
		printf("unable to append slot\n");
		return -ENOMEM;
	}

	return 0;
}

