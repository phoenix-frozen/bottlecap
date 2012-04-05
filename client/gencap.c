#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <bottlecap/bottlecap.h>
#include <bottlecap/errors.h>
#include <bottlecap/bottlecalls.h>

#include <polarssl/aes.h>
#include <polarssl/sha1.h>

#include "params.h"

//generate a 128-bit AES key
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
	/* Allocate and encrypt a cap for future tests.
	 */
	int rv;

	//fetch the key and keyblob
	aeskey_t* key;
	if(pm_get_addr(BOTTLE_KEY, (char**)&key) != sizeof(*key))
		return -1;
	tpm_aeskey_t* keyblob;
	if(pm_get_addr(BOTTLE_KEYBLOB, (char**)&keyblob) != sizeof(*keyblob))
		return -1;

	//allocate a new cap
	cap_t plaincap = { {
		.magic_top = CAP_MAGIC_TOP,
			.magic_bottom = CAP_MAGIC_BOTTOM,
			.expiry = 1001,
			.oid = 0xdeadbeefcafebabeULL,
			.issuer = *key,
	} };

	//... allocate the cryptcap, IV...
	tpm_encrypted_cap_t cryptcap;
	rv = generate_aes_key(&(cryptcap.iv));
	assert(rv == 0);
	uint128_t iv = cryptcap.iv;

	//...and encrypt it
	aes_context ctx;
	size_t iv_off = 0;
	rv = aes_setkey_enc(&ctx, key->bytes, BOTTLE_KEY_SIZE);
	assert(rv == 0);
	rv = aes_crypt_cfb128(&ctx, AES_ENCRYPT, sizeof(plaincap), &iv_off, iv.bytes, plaincap.bytes, cryptcap.cap.bytes);
	assert(rv == 0);
	sha1_hmac(key->bytes, sizeof(*key), cryptcap.cap.bytes, sizeof(cryptcap.cap), cryptcap.hmac);
	cryptcap.key = *keyblob;

	//-----------------------
	// HARD WORK IS NOW DONE
	//-----------------------

	//now generate the approprate stuff
	uint32_t call = BOTTLE_CAP_ADD;

	//call number
	int pm_append(int paramType, char *paramData, int paramSize);
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

	//output cryptcap
	if(pm_append(BOTTLE_CRYPTCAP, (char*)&cryptcap, sizeof(cryptcap)) != sizeof(cryptcap)) {
		printf("unable to append cryptcap\n");
		return -ENOMEM;
	}

	return 0;
}

