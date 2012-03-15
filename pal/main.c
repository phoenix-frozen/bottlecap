#include <stdio.h>

#include "bottle.h"
#include "bottlecap.h"


#ifdef BOTTLE_CAP_TEST
#include <stdlib.h>
#include <assert.h>
#include <aes.h>
#include <sha1.h>

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
	printf("End of test suite 1.\n\n");

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

	//... keep a plaintext copy...
	cap_t plaincap = newcap.cap;

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

	/* Test suite 5:
	 * Add a cap, do an attestation, and check the results.
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

	//setup for attestation, including generating proof and nonce
	cap_attestation_block_t attest_block;
	assert(sizeof(attest_block.authdata) == sizeof(attest_block.authdata.bytes));
	uint128_t nonce;
	uint128_t proof;
	assert(generate_aes_key(&(nonce)) == 0);
	assert(generate_aes_key(&(proof)) == 0);

	//do the attestation
	rv = bottle_cap_attest(*bottle, slot, nonce, proof, 1001, 0, &attest_block);
	printf("bottle_cap_export(%p, %u, 0x%llx%llx, 0x%llx%llx, %llu, %p, %p): %d\n", bottle, slot, nonce.qwords[0], nonce.qwords[1], proof.qwords[0], proof.qwords[1], 1001ULL, (void*)0, &attest_block, rv);
	assert(rv == 0);

	//check the plaintext values
	rv = memcmp(attest_block.nonce.bytes, nonce.bytes, sizeof(nonce));
	assert(rv == 0);
	assert(attest_block.expiry == 1001);
	assert(attest_block.urights == 0);

	//check the hash calculation
	sha1hash_t sha1data;
	sha1_buffer((unsigned char*)&attest_block, sizeof(attest_block.nonce) + sizeof(attest_block.authdata), sha1data);
	rv = memcmp(sha1data, attest_block.signature.hash, sizeof(sha1data));
	assert(rv == 0);

	//decrypt the encrypted block
	cap_attestation_block_t decrypted_attest_block;
	iv_off = 0;
	assert(aes_setkey_enc(&ctx, plaincap.key.bytes, BOTTLE_KEY_SIZE) == 0);
	iv = nonce;
	assert(aes_crypt_cfb128(&ctx, AES_DECRYPT, sizeof(decrypted_attest_block.authdata), &iv_off, iv.bytes, attest_block.authdata.bytes, decrypted_attest_block.authdata.bytes) == 0);

	//also decrypt the proof
	uint128_t plainproof;
	iv_off = 0;
	assert(aes_setkey_enc(&ctx, plaincap.issuer.bytes, BOTTLE_KEY_SIZE) == 0);
	iv = nonce;
	assert(aes_crypt_cfb128(&ctx, AES_DECRYPT, sizeof(plainproof), &iv_off, iv.bytes, proof.bytes, plainproof.bytes) == 0);

	//check all the results
	rv = memcmp(plainproof.bytes, decrypted_attest_block.authdata.proof.bytes, sizeof(plainproof));
	assert(rv == 0);
	assert(decrypted_attest_block.authdata.oid == plaincap.oid);
	assert(decrypted_attest_block.authdata.expiry == attest_block.expiry);
	assert(decrypted_attest_block.authdata.urights == attest_block.urights);
	assert(decrypted_attest_block.authdata.padding_1 == 0);
	assert(decrypted_attest_block.authdata.padding_2 == 0);

	printf("End of test suite 5.\n\n");

	/* Test suite 6:
	 * Call unimplemented functions, and make sure they return ENOSYS.
	 */
	rv = bottle_destroy(*bottle);
	printf("bottle_destroy(%p): %d\n", bottle, rv);
	assert(rv == -ENOTSUP);

	rv = bottle_export(*bottle, NULL, NULL);
	printf("bottle_export(%p, %p, %p): %d\n", bottle, NULL, NULL, rv);
	assert(rv == -ENOSYS);

	rv = bottle_import(*bottle, NULL);
	printf("bottle_import(%p, %p): %d\n", bottle, NULL, rv);
	assert(rv == -ENOSYS);

	rv = bottle_cap_export(*bottle, 0, NULL, 0, NULL);
	printf("bottle_cap_export(%p, %u, %p, %d, %p): %d\n", bottle, 0, NULL, 0, NULL, rv);
	assert(rv == -ENOSYS);

	printf("End of test suite 6.\n\n");

	printf("All tests succeeded. Goodbye from main(), test edition.\n");

	return 0;
#endif //BOTTLE_CAP_TEST
}
