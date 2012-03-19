#include <stdio.h>

#include <bottlecap/errors.h>
#include <bottlecap/bottlecap.h>
#include <bottlecap/bottle.h>

#ifndef BOTTLE_CAP_TEST

#include <params.h>
#include <util.h>

int main(void) {
	log_event(LOG_LEVEL_VERBOSE, "Hello from main() (PAL)\n");
	log_event(LOG_LEVEL_VERBOSE, "%d bytes available for output\n", pm_avail());

	return 0;
}

#else //BOTTLE_CAP_TEST

#include <stdlib.h>
#include <assert.h>

#include <aes.h>
#include <sha1.h>
#include <util.h>

#include <bottlecap/cap.h>
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

#define START_TESTS() int testcount = 1;
#define START_TEST_SUITE(s) printf("\nStarting test suite %d: %s\n\n", testcount, (s));
#define END_TEST_SUITE() printf("\nEnd of test suite %d.\n\n", testcount++);

int main(void) {
	int rv;
	uint32_t slots;
	uint32_t freeslots;
	uint32_t slot;

	printf("Hello from main(), test edition.\n\n");

	printf("A bottle_t is %d bytes, or %d bits.\n", sizeof(bottle_t), 8 * sizeof(bottle_t));
	printf("A bottle_header_t is %d bytes, or %d bits.\n", sizeof(bottle_header_t), 8 * sizeof(bottle_header_t));
	printf("A cap_t is %d bytes, or %d bits.\n", sizeof(cap_t), 8 * sizeof(cap_t));
	printf("A bottle may contain at most %d slots.\n\n", PAGE_SIZE / sizeof(cap_t));

	//variables for AES later
	aes_context ctx;
	aeskey_t iv;
	size_t iv_off;

	//allocate a new bottle
	bottle_t* bottle = generate_test_data();
	freeslots = bottle->header->size;
	printf("bottle: %p\n", bottle);

	//call the init functions
	rv = bottle_init(bottle);
	printf("bottle_init(%p): %d\n\n", bottle, rv);
	assert(rv == 0);

	START_TESTS();

	/* Test suite 1:
	 * Basic bottle state functions on an empty bottle
	 * to check that crypto is working.
	 */
	START_TEST_SUITE("basic bottle functionality");

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	slots = 0;
	rv = bottle_expire(bottle, 1000, &slots);
	printf("bottle_expire(%p, 1000, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	printf("freeslots = %u\n", freeslots);

	END_TEST_SUITE();

	/* Intermission 1:
	 * Allocate and encrypt a cap for future tests.
	 */
	//allocate a new cap...
	cap_t plaincap = { {
		.magic_top = CAP_MAGIC_TOP,
		.magic_bottom = CAP_MAGIC_BOTTOM,
		.expiry = 1001,
		.oid = 0xdeadbeefcafebabeULL,
	} };
	//... generate its issuer key
	//TODO: NDEBUG bug!
	assert(generate_aes_key(&(plaincap.issuer)) == 0);

	//... allocate the cryptcap, key, and IV...
	tpm_encrypted_cap_t cryptcap = {
		.cap = plaincap,
	};
	//TODO: NDEBUG bug!
	assert(generate_aes_key(&(cryptcap.key.aeskey)) == 0);
	assert(generate_aes_key(&(cryptcap.iv)) == 0);

	//...and encrypt it
	iv = cryptcap.iv;
	iv_off = 0;
	//TODO: NDEBUG bug!
	assert(aes_setkey_enc(&ctx, cryptcap.key.aeskey.bytes, BOTTLE_KEY_SIZE) == 0);
	assert(do_cap_crypto(&ctx, AES_ENCRYPT, &iv_off, &iv, &(cryptcap.cap)) == 0);

	/* Test suite 2:
	 * Add a cap, and delete it.
	 */
	START_TEST_SUITE("single cap add/delete");

	slot = 0;
	rv = bottle_cap_add(bottle, &cryptcap, &slot);
	printf("bottle_cap_add(%p, %p, %u): %d\n", bottle, &cryptcap, slot, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 1);

	rv = bottle_cap_delete(bottle, slot);
	printf("bottle_cap_delete(%p, %u): %d\n", bottle, slot, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	END_TEST_SUITE();

	/* Test suite 3:
	 * Add a cap, and then check expiry works correctly.
	 */
	START_TEST_SUITE("single cap add/expire");

	slot = 0;
	rv = bottle_cap_add(bottle, &cryptcap, &slot);
	printf("bottle_cap_add(%p, %p, %u): %d\n", bottle, &cryptcap, slot, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 1);

	slots = 0;
	rv = bottle_expire(bottle, 1000, &slots);
	printf("bottle_expire(%p, 1000, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 1);

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 1);

	slots = 0;
	rv = bottle_expire(bottle, 1001, &slots);
	printf("bottle_expire(%p, 1001, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	END_TEST_SUITE();

	/* Test suite 4:
	 * Add multiple caps, and then expire them all.
	 */
	START_TEST_SUITE("multiple cap add/expire");

	for(int i = 0; i < 3; i++) {
		slots = 0;
		rv = bottle_cap_add(bottle, &cryptcap, &slots);
		printf("bottle_cap_add(%p, %p, %u): %d\n", bottle, &cryptcap, slots, rv);
		assert(rv == 0);
	}

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 3);

	slots = 0;
	rv = bottle_expire(bottle, 1000, &slots);
	printf("bottle_expire(%p, 1000, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 3);

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 3);

	slots = 0;
	rv = bottle_expire(bottle, 1001, &slots);
	printf("bottle_expire(%p, 1001, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	END_TEST_SUITE();

	/* Test suite 5:
	 * Add a cap, do an attestation, and check the results.
	 */
	START_TEST_SUITE("single cap add & attest");

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	slot = 0;
	rv = bottle_cap_add(bottle, &cryptcap, &slot);
	printf("bottle_cap_add(%p, %p, %u): %d\n", bottle, &cryptcap, slot, rv);
	assert(rv == 0);

	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots + 1);

	//setup for attestation, including generating proof and nonce
	cap_attestation_block_t attest_block;
	uint128_t nonce;
	assert(generate_aes_key(&(nonce)) == 0);

	//do the attestation
	rv = bottle_cap_attest(bottle, slot, nonce, 1001, 0, &attest_block);
	printf("bottle_cap_export(%p, %u, 0x%llx%llx, %llu, %p, %p): %d\n", bottle, slot, nonce.qwords[0], nonce.qwords[1], 1001ULL, (void*)0, &attest_block, rv);
	assert(rv == 0);

	//check the plaintext values
	rv = memcmp(attest_block.nonce.bytes, nonce.bytes, sizeof(nonce));
	assert(rv == 0);
	assert(attest_block.expiry == 1001);
	assert(attest_block.urights == 0);

	//check the hash calculation
	sha1hash_t sha1data;
	//XXX: warning, this pointer arithmetic may assume little-endian
	sha1_buffer((unsigned char*)&attest_block, sizeof(attest_block.nonce) + sizeof(attest_block.authdata), sha1data);
	rv = memcmp(sha1data, attest_block.signature.hash, sizeof(sha1data));
	assert(rv == 0);

	//decrypt the encrypted block
	//TODO: NDEBUG bug!
	cap_attestation_block_t decrypted_attest_block;
	iv_off = 0;
	assert(aes_setkey_enc(&ctx, plaincap.issuer.bytes, BOTTLE_KEY_SIZE) == 0);
	iv = nonce;
	assert(aes_crypt_cfb128(&ctx, AES_DECRYPT, sizeof(decrypted_attest_block.authdata), &iv_off, iv.bytes, attest_block.authdata.bytes, decrypted_attest_block.authdata.bytes) == 0);

	//check all the results
	assert(decrypted_attest_block.authdata.oid == plaincap.oid);
	assert(decrypted_attest_block.authdata.expiry == attest_block.expiry);
	assert(decrypted_attest_block.authdata.urights == attest_block.urights);
	assert(decrypted_attest_block.authdata.padding_1 == 0);
	assert(decrypted_attest_block.authdata.padding_2 == 0);

	END_TEST_SUITE();

	/* Test suite 6:
	 * Call unimplemented functions, and make sure they return ENOSYS.
	 */
	START_TEST_SUITE("unimplemented functions");

	rv = bottle_destroy(bottle);
	printf("bottle_destroy(%p): %d\n", bottle, rv);
	assert(rv == -ENOTSUP);

	rv = bottle_export(bottle, NULL, NULL);
	printf("bottle_export(%p, %p, %p): %d\n", bottle, NULL, NULL, rv);
	assert(rv == -ENOSYS);

	rv = bottle_import(bottle, NULL);
	printf("bottle_import(%p, %p): %d\n", bottle, NULL, rv);
	assert(rv == -ENOSYS);

	rv = bottle_cap_export(bottle, 0, NULL, 0, NULL);
	printf("bottle_cap_export(%p, %u, %p, %d, %p): %d\n", bottle, 0, NULL, 0, NULL, rv);
	assert(rv == -ENOSYS);

	END_TEST_SUITE();

	printf("All tests succeeded. Emptying bottle\n");

	//empty the bottle again
	slots = 0;
	rv = bottle_expire(bottle, 1001, &slots);
	printf("bottle_expire(%p, 1001, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	//sanity check
	slots = 0;
	rv = bottle_query_free_slots(bottle, &slots);
	printf("bottle_query_free_slots(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);
	assert(freeslots == slots);

	printf("Bottle empty. Outputting bottle to file.\n");

	FILE* file = fopen("bottle.out", "w");
	assert(file != NULL);

	int params[2] = {0, sizeof(bottle_header_t) + 8};
	fwrite(params, sizeof(int), 2, file);
	fwrite(bottle->header, sizeof(bottle_header_t), 1, file);
	params[1] = sizeof(cap_t) * bottle->header->size;
	fwrite(params, sizeof(int), 2, file);
	fwrite(params, sizeof(int), 2, file);
	fwrite(bottle->table, sizeof(cap_t), bottle->header->size, file);

	printf("Done. Goodbye from main(), test edition.\n");

	return 0;
}

#endif //BOTTLE_CAP_TEST
