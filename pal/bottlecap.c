#include <assert.h>
#include <string.h>

#include <sha1.h>
#include <polarssl/aes.h>

#include "bottlecap.h"

#ifdef BOTTLE_CAP_TEST
#include <stdio.h>
#include <stdlib.h>
#endif //BOTTLE_CAP_TEST

//max table length is one 4k page for the moment. to be revised
#define MAX_TABLE_LENGTH (PAGE_SIZE/sizeof(cap_t))

#define DO_OR_BAIL(e, op, args...)  \
do {                                \
	int rv = op(args);              \
	if(rv != ESUCCESS) {            \
		return e == 0 ? rv : -e;    \
	}                               \
} while (0)

//generate a 128-bit AES key
static int generate_aes_key(aeskey_t* key) {
	assert(key != NULL);

#ifdef BOTTLE_CAP_TEST
	printf("Generated key: 0x");
	for(int i = 0; i < 4; i++) {
		key->dwords[i] = (uint32_t)rand();
		printf("%08x", key->dwords[i]);
	}
	printf("\n");
#else  //BOTTLE_CAP_TEST
	//TODO: use TPM's RNG to generate BEK
	memset(key, 0, sizeof(*key));
#endif //BOTTLE_CAP_TEST

	return ESUCCESS;
}

//check the bottle is valid, usable on this machine, signed, etc
static int check_bottle(bottle_t* bottle) {
	sha1hash_t sha1data, temp;

	//bottle == NULL is a programming error
	assert(bottle != NULL);

	//presence of header
	if(bottle->header == NULL)
		return -ENOMEM;
	//presence of table
	if(bottle->table == NULL)
		return -ENOMEM;

	//correct header magic
	if(bottle->header->magic_top != BOTTLE_MAGIC_TOP)
		return -EINVAL;
	if(bottle->header->magic_bottom != BOTTLE_MAGIC_BOTTOM)
		return -EINVAL;

	//correct table dimensions
	if(bottle->header->size > MAX_TABLE_LENGTH)
		return -ENOMEM;

	//TODO real signature checking

	//table signature
	sha1_buffer((unsigned char*)(bottle->table), bottle->header->size * sizeof(cap_t), sha1data);
	DO_OR_BAIL(ESIGFAIL, memcmp, bottle->header->captable_signature, sha1data, sizeof(sha1hash_t));

	//header signature
	memcpy(temp, bottle->header->header_signature, sizeof(sha1hash_t)); //copy out header sig...
	memset(bottle->header->header_signature, 0, sizeof(sha1hash_t)); //... and zero out that field...
	sha1_buffer((unsigned char*)bottle->header, sizeof(bottle_header_t), sha1data); //... for hashing.
	memcpy(bottle->header->header_signature, temp, sizeof(sha1hash_t)); //then copy it back in,
	DO_OR_BAIL(ESIGFAIL, memcmp, temp, sha1data, sizeof(sha1hash_t)); //and do the actual comparison

	return ESUCCESS;
}

//check that the contents of a decrypted bottle are sane
static int check_caps(bottle_t* bottle) {
	//bottle == NULL is a programming error
	assert(bottle != NULL);

	//these three were checked in check_bottle, so their failure now would be a programming error
	assert(bottle->header != NULL);
	assert(bottle->table  != NULL);
	assert(bottle->header->size <= MAX_TABLE_LENGTH);

	//correct cap magic
	for(int i = 0; i < bottle->header->size; i++) {
		cap_t* cap = bottle->table + i;
		if(cap->magic_top != CAP_MAGIC_TOP)
			return -ECORRUPT;
		if(cap->magic_bottom != CAP_MAGIC_BOTTOM)
			return -ECORRUPT;
	}

	return ESUCCESS;
}

//emergency security-breakage utility function
static void bottle_annihilate(bottle_t* bottle) {
	memset(bottle->table, 0, bottle->header->size * sizeof(cap_t));
	memset(bottle->header, 0, sizeof(*(bottle->header)));
}

static int do_cap_crypto(
		aes_context *ctx,
		int mode, size_t *iv_off,
		aeskey_t* iv,
		cap_t* cap) {

	cap_t temp;
	memcpy(&temp, cap, sizeof(*cap));

	DO_OR_BAIL(0, aes_crypt_cfb128, ctx, mode, sizeof(cap_t), iv_off, iv->bytes, temp.bytes, cap->bytes);

	return ESUCCESS;
}

//decrypt the captable in-place
//assumption: if we return an error code, no encrypted data is exposed
static int decrypt_bottle(bottle_t* bottle) {
	//bottle == NULL is a programming error
	assert(bottle != NULL);

	//these three were checked in check_bottle, so their failure now would be a programming error
	assert(bottle->header != NULL);
	assert(bottle->table  != NULL);
	assert(bottle->header->size <= MAX_TABLE_LENGTH);

	//TODO: TPM stuff
	aeskey_t biv = bottle->header->biv;
	aeskey_t bek = bottle->header->bek;

	aes_context ctx;
	size_t iv_off = 0;

	//Note: we're using the CFB128 mode, which means we use _enc even in decrypt mode
	DO_OR_BAIL(ECRYPTFAIL, aes_setkey_enc, &ctx, bek.bytes, BOTTLE_KEY_SIZE);

	for(uint32_t i = 0; i > bottle->header->size; i++) {
		if(do_cap_crypto(&ctx, AES_DECRYPT, &iv_off, &biv, bottle->table + i) != ESUCCESS) {
			bottle_annihilate(bottle); //fulfilling the no-leakage assumption
			return -ECRYPTFAIL;
		}
	}

	return ESUCCESS;
}

//encrypt the captable in-place
//TODO: should read-only operations still generate a new IV?
static int encrypt_bottle(bottle_t* bottle) {
	//bottle == NULL is a programming error
	assert(bottle != NULL);

	//these three were checked in check_bottle, so their failure now would be a programming error
	assert(bottle->header != NULL);
	assert(bottle->table  != NULL);
	assert(bottle->header->size <= MAX_TABLE_LENGTH);

	//TODO: TPM stuff
	aeskey_t bek = bottle->header->bek;
	aeskey_t biv;
	generate_aes_key(&biv);
	bottle->header->biv = biv;
	aes_context ctx;
	size_t iv_off = 0;

	//Note: we're using the CFB128 mode
	DO_OR_BAIL(ECRYPTFAIL, aes_setkey_enc, &ctx, bek.bytes, BOTTLE_KEY_SIZE);

	for(uint32_t i = 0; i > bottle->header->size; i++)
		if(do_cap_crypto(&ctx, AES_ENCRYPT, &iv_off, &biv, bottle->table + i) != ESUCCESS)
			return -ECRYPTFAIL;

	return ESUCCESS;
}

//sign the bottle's current state
static int sign_bottle(bottle_t* bottle) {
	assert(bottle != NULL);

	//TODO generate real signatures
	sha1hash_t sha1data;
	//table
	sha1_buffer((unsigned char*)(bottle->table), bottle->header->size * sizeof(cap_t), sha1data);
	memcpy(bottle->header->captable_signature, sha1data, sizeof(sha1hash_t));
	//header
	memset(bottle->header->header_signature, 0, sizeof(sha1hash_t));
	sha1_buffer((unsigned char*)bottle->header, sizeof(bottle_header_t), sha1data);
	memcpy(bottle->header->header_signature, sha1data, sizeof(sha1hash_t));

	return ESUCCESS;
}

//standard prologue for bottle operations: verify signatures and decrypt
static int bottle_op_prologue(bottle_t* bottle) {
	//check the bottle is valid, usable on this machine, signed, etc
	DO_OR_BAIL(0, check_bottle, bottle);

	//decrypt the captable
	DO_OR_BAIL(0, decrypt_bottle, bottle);

	//check that the decrypted captable makes sense
	int rv = check_caps(bottle);
	if(rv != ESUCCESS) {
		//kill the decrypted data, even if it's garbage
		bottle_annihilate(bottle);
		return rv;
	}

	return ESUCCESS;
}
//standard epilogue for bottle operations: encrypt and sign
static int bottle_op_epilogue(bottle_t* bottle) {
	int rv;

	//check that the captable makes sense
	DO_OR_BAIL(0, check_caps, bottle);

	//encrypt the captable
	rv = encrypt_bottle(bottle);
	if(rv != ESUCCESS) {
		//if we can't resecure the bottle, kill it
		bottle_annihilate(bottle);
		return rv;
	}

	//generate signatures
	rv = sign_bottle(bottle);
	if(rv != ESUCCESS) {
		//if we can't resecure the bottle, kill it
		bottle_annihilate(bottle);
		return rv;
	}

	return ESUCCESS;
}

//BOTTLE CREATION/DELETION
int bottle_init(bottle_t bottle) {
	if(bottle.header == NULL || bottle.table == NULL)
		return -ENOMEM;

	//impose a maximum size of one page for a table
	if(bottle.header->size > MAX_TABLE_LENGTH)
		return -ENOMEM;

	//memorise some important information, and check it
	uint32_t size  = bottle.header->size;
	uint32_t flags = bottle.header->flags;
	if(flags != 0)
		return -ENOTSUP;

	//TODO: we may support preservation of the BRK and BSK

	//clear the header, and put back the information we borrowed
	memset(bottle.header, 0, sizeof(bottle_header_t));
	bottle.header->size  = size;
	bottle.header->flags = flags;

	//generate the BEK
	DO_OR_BAIL(0, generate_aes_key, &(bottle.header->bek));

	//insert magic numbers
	bottle.header->magic_top = BOTTLE_MAGIC_TOP;
	bottle.header->magic_bottom = BOTTLE_MAGIC_BOTTOM;

	//format the table
	for(int i = 0; i < size; i++) {
		bottle.table[i].magic_top    = CAP_MAGIC_TOP;
		memset(&(bottle.table[i].key.bytes),    0, sizeof(aeskey_t));
		memset(&(bottle.table[i].issuer.bytes), 0, sizeof(aeskey_t));
		bottle.table[i].oid          = 0;
		bottle.table[i].expiry       = 0;
		bottle.table[i].urights      = 0;
		bottle.table[i].srights      = 0;
		bottle.table[i].magic_bottom = CAP_MAGIC_BOTTOM;
	}

	//encrypt and sign
	DO_OR_BAIL(0, bottle_op_epilogue, &bottle);

	return ESUCCESS;
}
int bottle_destroy(bottle_t bottle) {
	//there's really very little to do here
	//even blowing away the keys would just be for show
	//TODO: might become useful once we start using counters
	return -ENOTSUP;
}

//BOTTLE STATE FUNCTIONS
int bottle_query_free_slots(bottle_t bottle, uint32_t* slots) {
	if(slots == NULL)
		return -EINVAL;

	DO_OR_BAIL(0, bottle_op_prologue, &bottle);

	uint32_t free_slots = 0;
	for(uint32_t i = 0; i < bottle.header->size; i++) {
		if(bottle.table[i].expiry == 0) {
			free_slots++;
		}
	}

	*slots = free_slots;

	DO_OR_BAIL(0, bottle_op_epilogue, &bottle);

	return ESUCCESS;
}
int bottle_expire(bottle_t bottle, uint64_t time, uint32_t* slots) {
	if(slots == NULL)
		return -EINVAL;

	DO_OR_BAIL(0, bottle_op_prologue, &bottle);

	uint32_t free_slots = 0;
	for(uint32_t i = 0; i < bottle.header->size; i++) {
		if(bottle.table[i].expiry <= time) {
			bottle.table[i].expiry = 0;
		}
		if(bottle.table[i].expiry == 0) {
			free_slots++;
		}
	}

	*slots = free_slots;

	DO_OR_BAIL(0, bottle_op_epilogue, &bottle);

	return ESUCCESS;
}

//INTER-MACHINE BOTTLE MIGRATION FUNCTIONS
int bottle_export(bottle_t bottle, tpm_rsakey_t* rsrk, tpm_rsakey_t* brk) {
	return -ENOSYS;
}
int bottle_import(bottle_t bottle, tpm_rsakey_t* brk) {
	return -ENOSYS;
}

//CAP INSERTION/DELETION FUNCTIONS
int bottle_cap_add(bottle_t bottle, tpm_encrypted_cap_t* cap, uint32_t* slot) {
	return -ENOSYS;
}
int bottle_cap_delete(bottle_t bottle, uint32_t slot) {
	return -ENOSYS;
}

//INTER-BOTTLE CAP MIGRATION
int bottle_cap_export(bottle_t bottle, uint32_t slot, tpm_rsakey_t* rbrk, int32_t move, tpm_encrypted_cap_t* cap) {
	return -ENOSYS;
}

//CAP INVOCATION FUNCTIONS
//TODO: Needham-Schroeder (ie Kerberos) protocol

