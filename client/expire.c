#include <stdio.h>
#include <assert.h>

#include <bottlecap/bottlecalls.h>
#include <bottlecap/errors.h>

#include "params.h"

int do_real_work(void) {
	/* Allocate and encrypt a cap for future tests.
	 */

	//now generate the approprate stuff
	uint32_t call = BOTTLE_EXPIRE;

	//call number
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

	//expiry
	uint64_t expiry = 1002;
	if(pm_append(BOTTLE_EXPIRY, (char*)&expiry, sizeof(expiry)) != sizeof(expiry)) {
		printf("BOTTLECAP: Could not append expiry\n");
		return -EINVAL;
	}

	return 0;
}

