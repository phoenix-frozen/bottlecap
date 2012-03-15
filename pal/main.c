#include <stdio.h>

#include "bottle.h"
#include "bottlecap.h"


#ifdef BOTTLE_CAP_TEST
#include <stdlib.h>
#include <assert.h>
#include <aes.h>

#include "cap.h"
#include "tpm_crypto.h"

static void* guaranteed_allocate(size_t size) {
	void* temp = malloc(size);
	assert(temp != NULL);
	return temp;
}
#define malloc guaranteed_allocate

static bottle_t* generate_test_data() {
	bottle_t* bottle = malloc(sizeof(bottle_t));
	bottle->header = malloc(sizeof(*(bottle->header)));
	bottle->table = malloc(PAGE_SIZE);

	bottle->header->flags = 0;
	bottle->header->size  = PAGE_SIZE / sizeof(cap_t);

	return bottle;
}

//generate a 128-bit AES key
static int generate_aes_key(aeskey_t* key) {
	assert(key != NULL);

	printf("TEST Generated key: 0x");
	for(int i = 0; i < 4; i++) {
		key->dwords[i] = (uint32_t)rand();
		printf("%08x", key->dwords[i]);
	}
	printf("\n");
	return ESUCCESS;
}

#endif //BOTTLE_CAP_TEST

int main(void) {
#ifndef BOTTLE_CAP_TEST
	printf("Hello from main() (PAL)\n");

	return 0;
#else //BOTTLE_CAP_TEST
	int rv;
	uint32_t slots;

	printf("Hello from main(), test edition.\n");

	printf("A bottle_t is %d bytes, or %d bits.\n", sizeof(bottle_t), 8 * sizeof(bottle_t));
	printf("A bottle_header_t is %d bytes, or %d bits.\n", sizeof(bottle_header_t), 8 * sizeof(bottle_header_t));
	printf("A cap_t is %d bytes, or %d bits.\n", sizeof(cap_t), 8 * sizeof(cap_t));

	//allocate a new bottle
	bottle_t* bottle = generate_test_data();
	printf("bottle: %p\n\n", bottle);

	//call the init functions
	rv = bottle_init(*bottle);
	printf("bottle_init(%p): %d\n\n", bottle, rv);
	assert(rv == 0);

	//a few test functions to make sure crypto works
	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_expire(*bottle, 1000, &slots);
	printf("bottle_expire(%p, 1000, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	//allocate a new cap...
	tpm_encrypted_cap_t newcap = {
		.cap = {
			.magic_top = CAP_MAGIC_TOP,
			.magic_bottom = CAP_MAGIC_BOTTOM,
			.expiry = 1001,
			.oid = 0xdeadbeefcafebabeULL,
		},
	};
	//... generate its keys...
	//TODO: NDEBUG bug!
	assert(generate_aes_key(&(newcap.key.aeskey)) == 0);
	assert(generate_aes_key(&(newcap.cap.key)) == 0);
	assert(generate_aes_key(&(newcap.cap.issuer)) == 0);

	//...encrypt it...
	aes_context ctx;
	aeskey_t iv = newcap.key.aeskey;
	size_t iv_off = 0;
	//TODO: NDEBUG bug!
	assert(aes_setkey_enc(&ctx, newcap.key.aeskey.bytes, BOTTLE_KEY_SIZE) == 0);
	assert(do_cap_crypto(&ctx, AES_ENCRYPT, &iv_off, &iv, &(newcap.cap)) == 0);

	//... and add it in
	slots = 0;
	rv = bottle_cap_add(*bottle, &newcap, &slots);
	printf("bottle_cap_add(%p, %p, %u): %d\n\n", bottle, &newcap, slots, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_expire(*bottle, 1000, &slots);
	printf("bottle_expire(%p, 1000, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_expire(*bottle, 1001, &slots);
	printf("bottle_expire(%p, 1001, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	//add in the cap again
	slots = 0;
	rv = bottle_cap_add(*bottle, &newcap, &slots);
	printf("bottle_cap_add(%p, %p, %u): %d\n\n", bottle, &newcap, slots, rv);
	assert(rv == 0);

	rv = bottle_cap_delete(*bottle, slots);
	printf("bottle_cap_delete(%p, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n\n", bottle, slots, rv);
	assert(rv == 0);

	printf("All tests succeeded. Goodbye from main(), test edition.\n");

	return 0;
#endif //BOTTLE_CAP_TEST
}
