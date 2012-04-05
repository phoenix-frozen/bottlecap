#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <bottlecap/bottlecalls.h>
#include <bottlecap/errors.h>
#include <bottlecap/bottlecap.h>

#include "params.h"

static int generate_aes_key(aeskey_t* key) {
	assert(key != NULL);

	//printf("TEST Generated key: 0x");
	for(int i = 0; i < 4; i++) {
		key->dwords[i] = (uint32_t)rand();
		//printf("%08x", key->dwords[i]);
	}
	//printf("\n");
	return ESUCCESS;
}

int do_real_work(void) {
	/* Set up attestation parameters
	 */

	//call number
	uint32_t call = BOTTLE_CAP_ATTEST;
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
	if(pm_append(BOTTLE_INDEX, data_in, size) != size) {
		printf("unable to append slot\n");
		return -ENOMEM;
	}

	//rights
	uint32_t urights = 0;
	if(pm_append(BOTTLE_CALL, (char*)&urights, sizeof(urights)) != sizeof(urights)) {
		printf("unable to append urights\n");
		return -ENOMEM;
	}

	//nonce
	uint128_t nonce;
	generate_aes_key(&nonce);
	if(pm_append(BOTTLE_NONCE, (char*)&nonce, sizeof(nonce)) != sizeof(nonce)) {
		printf("BOTTLECAP: Could not append nonce\n");
		return -EINVAL;
	}

	//expiry
	uint64_t expiry = 1000;
	if(pm_append(BOTTLE_EXPIRY, (char*)&expiry, sizeof(expiry)) != sizeof(expiry)) {
		printf("BOTTLECAP: Could not append expiry\n");
		return -EINVAL;
	}

	return 0;
}

