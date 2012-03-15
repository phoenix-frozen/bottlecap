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
	uint32_t freeslots;
	uint32_t slot;

	printf("Hello from main(), test edition.\n\n");

	printf("A bottle_t is %d bytes, or %d bits.\n", sizeof(bottle_t), 8 * sizeof(bottle_t));
	printf("A bottle_header_t is %d bytes, or %d bits.\n", sizeof(bottle_header_t), 8 * sizeof(bottle_header_t));
	printf("A cap_t is %d bytes, or %d bits.\n\n", sizeof(cap_t), 8 * sizeof(cap_t));

	//allocate a new bottle
	bottle_t* bottle = generate_test_data();
	printf("bottle: %p\n", bottle);

	//call the init functions
	rv = bottle_init(*bottle);
	printf("bottle_init(%p): %d\n\n", bottle, rv);
	assert(rv == 0);

	/* Test suite 1:
	 * Basic bottle state functions on an empty bottle
	 * to check that crypto is working.
	 */
	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	freeslots = slots;
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_expire(*bottle, 1000, &slots);
	printf("bottle_expire(%p, 1000, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	printf("freeslots = %u\n", freeslots);
	printf("End of test suite 1.");

	/* Intermission 1:
	 * Allocate and encrypt a cap for future tests.
	 */
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

	/* Test suite 2:
	 * Add a cap, and delete it.
	 */
	slot = 0;
	rv = bottle_cap_add(*bottle, &newcap, &slot);
	printf("bottle_cap_add(%p, %p, %u): %d\n", bottle, &newcap, slot, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 1);

	rv = bottle_cap_delete(*bottle, slot);
	printf("bottle_cap_delete(%p, %u): %d\n", bottle, slot, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	printf("End of test suite 2.\n\n");

	/* Test suite 3:
	 * Add a cap, and then check expiry works correctly.
	 */
	slot = 0;
	rv = bottle_cap_add(*bottle, &newcap, &slot);
	printf("bottle_cap_add(%p, %p, %u): %d\n", bottle, &newcap, slot, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 1);

	slots = 0;
	rv = bottle_expire(*bottle, 1000, &slots);
	printf("bottle_expire(%p, 1000, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 1);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 1);

	slots = 0;
	rv = bottle_expire(*bottle, 1001, &slots);
	printf("bottle_expire(%p, 1001, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	printf("End of test suite 3.\n\n");

	/* Test suite 4:
	 * Add multiple caps, and then expire them all.
	 */
	for(int i = 0; i < 3; i++) {
		slots = 0;
		rv = bottle_cap_add(*bottle, &newcap, &slots);
		printf("bottle_cap_add(%p, %p, %u): %d\n", bottle, &newcap, slots, rv);
		assert(rv == 0);
	}

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 3);

	slots = 0;
	rv = bottle_expire(*bottle, 1000, &slots);
	printf("bottle_expire(%p, 1000, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 3);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 3);

	slots = 0;
	rv = bottle_expire(*bottle, 1001, &slots);
	printf("bottle_expire(%p, 1001, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	slots = 0;
	rv = bottle_query_free_slots(*bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	printf("End of test suite 4.\n\n");

	printf("All tests succeeded. Goodbye from main(), test edition.\n");

	return 0;
#endif //BOTTLE_CAP_TEST
}
