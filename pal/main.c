#include <stdio.h>

#include <bottlecap/errors.h>
#include <bottlecap/bottlecap.h>
#include <bottlecap/bottle.h>

#include <bottlecap/bottlecalls.h>

#ifndef BOTTLE_CAP_TEST

#include <params.h>
#include <util.h>

#include "profiling.h"
#include "misc.h"

static int do_bottle_cap(void) {
	profiling_start(NULL);

	log_event(LOG_LEVEL_VERBOSE, "BOTTLECAP: Hello from main() (PAL)\n");
	log_event(LOG_LEVEL_VERBOSE, "BOTTLECAP: %d bytes available for output\n", pm_avail());

	bottle_t bottle;
	int temp;

	//reserve output error code
	int32_t* rv = (int32_t*)pm_reserve(BOTTLE_CALL, sizeof(int32_t));
	if(rv == NULL) {
		log_event(LOG_LEVEL_ERROR, "BOTTLECAP: No space for output!\n");
		return -ENOMEM;
	}

	//bring in call number
	int32_t* call;
	if((temp = pm_get_addr(BOTTLE_CALL, (char**)&call)) != sizeof(int32_t)) {
		log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not get call number: %d\n", temp);
		*rv = -EINVAL;
		return *rv;
	}

	//allocate header output space
	bottle.header = (bottle_header_t*)pm_reserve(BOTTLE_HEADER, sizeof(bottle_header_t));
	if(bottle.header == NULL) {
		log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not allocate header\n");
		*rv = -ENOMEM;
		return *rv;
	}

	//bring in bottle header and copy
	// allow no or invalid input header if we're initting; just generate default values
	bottle_header_t* header_in;
	if((temp = pm_get_addr(BOTTLE_HEADER, (char**)&header_in)) != sizeof(bottle_header_t)) {
		if(*call == BOTTLE_INIT) {
			log_event(LOG_LEVEL_VERBOSE, "BOTTLECAP: Could not get header: %d (headers are %d) [non-fatal in INIT]\n", temp, sizeof(bottle_header_t));
			header_in = NULL;
		} else {
			log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not get header: %d (headers are %d)\n", temp, sizeof(bottle_header_t));
			*rv = -EINVAL;
			goto main_final_exit;
		}
	}
	if(header_in == NULL) {
		log_event(LOG_LEVEL_VERBOSE, "BOTTLECAP: Generating default header for INIT\n", temp, sizeof(bottle_header_t));
		bottle.header->flags = 0;
		bottle.header->size = MAX_TABLE_LENGTH;
	} else {
		if(header_in->size > MAX_TABLE_LENGTH) {
			log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Header specified invalid table size\n");
			*rv = -ENOMEM;
			goto main_final_exit;
		}
		memcpy(bottle.header, header_in, sizeof(bottle_header_t));
	}

	//XXX: header has now been allocated. from here on in, exits must go to main_zero_header

	//allocate table output space
	bottle.table = (cap_t*)pm_reserve(BOTTLE_TABLE, sizeof(cap_t) * bottle.header->size);
	if(bottle.table == NULL) {
		log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not allocate table\n");
		*rv = -ENOMEM;
		goto main_zero_header;
	}

	//XXX: table has now been allocated. from here on in, exits must go to main_zero_table

	//check if we're initting; if not, bring in table and copy to output
	if(*call != BOTTLE_INIT) {
		cap_t* table_in;
		if(pm_get_addr(BOTTLE_TABLE, (char**)&table_in) != bottle.header->size * sizeof(cap_t)) {
			log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not get table\n");
			*rv = -EINVAL;
			goto main_zero_table;
		}
		memcpy(bottle.table, table_in, bottle.header->size * sizeof(cap_t));
	}

	log_event(LOG_LEVEL_VERBOSE, "BOTTLECAP: Dispatching call %d...\n", *call);

	profiling_lap("begin dispatch");

	//main dispatch table
	switch (*call) {
		case BOTTLE_INIT:
			{
				*rv = bottle_init(&bottle);
				break;
			}

		case BOTTLE_DESTROY:
			{
				*rv = bottle_destroy(&bottle);
				break;
			}

		case BOTTLE_QUERY_FREE_SLOTS:
			{
				uint32_t* slots = (uint32_t*)pm_reserve(BOTTLE_SLOTCOUNT, sizeof(uint32_t));
				if(slots == NULL) {
					log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not allocate slotcount\n");
					*rv = -ENOMEM;
					break;
				}

				*rv = bottle_query_free_slots(&bottle, slots);
				break;
			}

		case BOTTLE_EXPIRE:
			{
				uint64_t* expiry;
				if(pm_get_addr(BOTTLE_EXPIRY, (char**)&expiry) != sizeof(uint64_t)) {
					log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not get expiry\n");
					*rv = -EINVAL;
					break;
				}

				uint32_t* slots = (uint32_t*)pm_reserve(BOTTLE_SLOTCOUNT, sizeof(uint32_t));
				if(slots == NULL) {
					log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not allocate slotcount\n");
					*rv = -ENOMEM;
					break;
				}

				*rv = bottle_expire(&bottle, *expiry, slots);
				break;
			}

		case BOTTLE_CAP_ADD:
			{
				tpm_encrypted_cap_t* cap;
				if(pm_get_addr(BOTTLE_CRYPTCAP, (char**)&cap) != sizeof(tpm_encrypted_cap_t)) {
					log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not get cap\n");
					*rv = -EINVAL;
					break;
				}

				uint32_t* slot = (uint32_t*)pm_reserve(BOTTLE_INDEX, sizeof(uint32_t));
				if(slot == NULL) {
					log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not allocate index\n");
					*rv = -ENOMEM;
					break;
				}

				*rv = bottle_cap_add(&bottle, cap, slot);
				break;
			}

		case BOTTLE_CAP_DELETE:
			{
				uint32_t* slot;
				if(pm_get_addr(BOTTLE_INDEX, (char**)&slot) != sizeof(uint32_t)) {
					log_event(LOG_LEVEL_ERROR, "BOTTLECAP: Could not get slot index\n");
					*rv = -EINVAL;
					break;
				}

				*rv = bottle_cap_delete(&bottle, *slot);
				break;
			}

		case BOTTLE_EXPORT:
		case BOTTLE_IMPORT:
		case BOTTLE_CAP_EXPORT:
		case BOTTLE_NULL:
		default:
			*rv = -ENOSYS;
			break;
	}

	profiling_lap("dispatched; zero");
	log_event(LOG_LEVEL_VERBOSE, "BOTTLECAP: Dispatch complete. Return value %d\n", *rv);

	//if our call wasn't successful, zero the output buffers
	if(*rv != ESUCCESS) {
main_zero_table:
		memset(bottle.table, 0, bottle.header->size * sizeof(cap_t));
main_zero_header:
		memset(bottle.header, 0, sizeof(bottle_header_t));
	}

main_final_exit:
	log_event(LOG_LEVEL_VERBOSE, "BOTTLECAP: Returning to reality.\n");

	profiling_stop(NULL);

	return *rv;
}

int main(void) {
	int rv = do_bottle_cap();

#ifdef BOTTLE_CAP_PROFILE
	unsigned int profiling_output_size = sizeof(timing_point_t) * profiling_count();
	timing_point_t* profiling_output = (timing_point_t*)pm_reserve(BOTTLE_PROFILING, profiling_output_size);
	if(profiling_output != NULL)
		memcpy(profiling_output, profiling_get(), profiling_output_size );
#endif //BOTTLE_CAP_PROFILE

	return rv;
}


#else //BOTTLE_CAP_TEST

#include <stdlib.h>
#include <assert.h>

#include <util.h>
#include <polarssl/sha1.h>
#include <polarssl/aes.h>

#include <bottlecap/crypto.h>
#include <bottlecap/cap.h>

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
	bottle_t* bottle;

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
	bottle = generate_test_data();
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
	rv = generate_aes_key(&(plaincap.issuer));
	assert(rv == 0);

	//... allocate the cryptcap, key, and IV...
	tpm_encrypted_cap_t cryptcap;
	aeskey_t key;
	rv = generate_aes_key(&key);
	assert(rv == 0);
	memcpy(cryptcap.key.sealed_data, key.bytes, sizeof(key));
	rv = generate_aes_key(&(cryptcap.iv));
	assert(rv == 0);

	//...and encrypt it
	iv = cryptcap.iv;
	iv_off = 0;
	rv = aes_setkey_enc(&ctx, key.bytes, BOTTLE_KEY_SIZE);
	assert(rv == 0);
	rv = aes_crypt_cfb128(&ctx, AES_ENCRYPT, sizeof(plaincap), &iv_off, iv.bytes, plaincap.bytes, cryptcap.cap.bytes);
	assert(rv == 0);
	sha1_hmac(key.bytes, sizeof(key), cryptcap.cap.bytes, sizeof(cryptcap.cap), cryptcap.hmac);

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
	printf("bottle_cap_attest(%p, %u, 0x%llx%llx, %llu, %p, %p): %d\n", bottle, slot, nonce.qwords[0], nonce.qwords[1], 1001ULL, (void*)0, &attest_block, rv);
	assert(rv == 0);

	//check the plaintext values
	printf("checking attestation values...\n");
	rv = memcmp(attest_block.nonce.bytes, nonce.bytes, sizeof(nonce));
	printf("\tnonce: memcmp(%p, %p, %d): %d\n", attest_block.nonce.bytes, nonce.bytes, sizeof(nonce), rv);
	assert(rv == 0);
	printf("\texpiry: %lld/%lld\n", 1001ULL, attest_block.expiry);
	assert(attest_block.expiry == 1001);
	printf("\turights: %p/%p\n", (void*)0, (void*)attest_block.urights);
	assert(attest_block.urights == 0);

	//check the HMAC calculation
	sha1hash_t sha1data;
	sha1_hmac(plaincap.issuer.bytes, sizeof(plaincap.issuer.bytes), attest_block.authdata.bytes, sizeof(attest_block.authdata), sha1data);
	rv = memcmp(sha1data, attest_block.hmac, sizeof(sha1data));
	printf("\thmac: memcmp(%p, %p, %d): %d\n", sha1data, attest_block.hmac, sizeof(sha1data), rv);
	assert(rv == 0);

	//decrypt the encrypted block
	cap_attestation_block_t decrypted_attest_block;
	iv_off = 0;
	rv = aes_setkey_enc(&ctx, plaincap.issuer.bytes, BOTTLE_KEY_SIZE);
	assert(rv == 0);
	iv = nonce;
	rv = aes_crypt_cfb128(&ctx, AES_DECRYPT, sizeof(decrypted_attest_block.authdata), &iv_off, iv.bytes, attest_block.authdata.bytes, decrypted_attest_block.authdata.bytes);
	assert(rv == 0);

	//check all the results
	printf("\tcrypt_oid: %lld/%lld\n", decrypted_attest_block.authdata.oid, plaincap.oid);
	assert(decrypted_attest_block.authdata.oid == plaincap.oid);
	printf("\tcrypt_expiry: %lld/%lld\n", decrypted_attest_block.authdata.expiry, attest_block.expiry);
	assert(decrypted_attest_block.authdata.expiry == attest_block.expiry);
	printf("\tcrypt_urights: %p/%p\n", (void*)decrypted_attest_block.authdata.urights, (void*)attest_block.urights);
	assert(decrypted_attest_block.authdata.urights == attest_block.urights);
	printf("\tcrypt_amagic: 0x%16llx/0x%16llx\n", ATTEST_MAGIC, decrypted_attest_block.authdata.amagic);
	assert(ATTEST_MAGIC == decrypted_attest_block.authdata.amagic);
	printf("\tcrypt_cmagic: %p/%p\n", (void*)CAP_MAGIC_TOP, (void*)decrypted_attest_block.authdata.cmagic);
	assert(CAP_MAGIC_TOP == decrypted_attest_block.authdata.cmagic);

	END_TEST_SUITE();

	/* Test suite 6:
	 * Call unimplemented functions, and make sure they return ENOSYS.
	 */
	START_TEST_SUITE("unimplemented functions");

	rv = bottle_destroy(bottle);
	printf("bottle_destroy(%p): %d\n", bottle, rv);
	assert(rv == -ENOTSUP);

#if 0
	rv = bottle_export(bottle, NULL, NULL);
	printf("bottle_export(%p, %p, %p): %d\n", bottle, NULL, NULL, rv);
	assert(rv == -ENOSYS);

	rv = bottle_import(bottle, NULL);
	printf("bottle_import(%p, %p): %d\n", bottle, NULL, rv);
	assert(rv == -ENOSYS);

	rv = bottle_cap_export(bottle, 0, NULL, 0, NULL);
	printf("bottle_cap_export(%p, %u, %p, %d, %p): %d\n", bottle, 0, NULL, 0, NULL, rv);
	assert(rv == -ENOSYS);
#endif

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

	int params[2] = {BOTTLE_HEADER, sizeof(bottle_header_t)};
	fwrite(params, sizeof(int), 2, file);
	fwrite(bottle->header, sizeof(bottle_header_t), 1, file);
	params[0] = BOTTLE_TABLE;
	params[1] = sizeof(cap_t) * bottle->header->size;
	fwrite(params, sizeof(int), 2, file);
	fwrite(bottle->table, sizeof(cap_t), bottle->header->size, file);

	printf("Done. Goodbye from main(), test edition.\n");

	return 0;
}

#endif //BOTTLE_CAP_TEST
