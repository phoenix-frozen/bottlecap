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

//check the bottle is valid, usable on this machine, signed, etc
static int check_bottle(bottle_t* bottle) {
	sha1hash_t sha1data, temp;

	assert(bottle != NULL);

	if(bottle->header == NULL)
		return -ENOMEM;
	if(bottle->table == NULL)
		return -ENOMEM;

	if(bottle->header->magic_top != BOTTLE_MAGIC_TOP)
		return -EINVAL;
	if(bottle->header->magic_bottom != BOTTLE_MAGIC_BOTTOM)
		return -EINVAL;

	//TODO real signature checking

	//table
	sha1_buffer((unsigned char*)(bottle->table), bottle->header->size * sizeof(cap_t), sha1data);
	DO_OR_BAIL(ESIGFAIL, memcmp, bottle->header->captable_signature, sha1data, sizeof(sha1hash_t));

	//header
	memcpy(temp, bottle->header->header_signature, sizeof(sha1hash_t)); //copy out header sig...
	memset(bottle->header->header_signature, 0, sizeof(sha1hash_t)); //... and zero out that field...
	sha1_buffer((unsigned char*)bottle->header, sizeof(bottle_header_t), sha1data); //... for hashing.
	memcpy(bottle->header->header_signature, temp, sizeof(sha1hash_t)); //then copy it back in,
	DO_OR_BAIL(ESIGFAIL, memcmp, temp, sha1data, sizeof(sha1hash_t)); //and do the actual comparison

	return ESUCCESS;
}

//decrypt the captable in-place
//assumption: if we return an error code, no encrypted data is exposed
static int decrypt_bottle(bottle_t* bottle) {
	assert(bottle != NULL);

	//aes_context ctx;

	//TODO: noop for the moment
	return ESUCCESS;
}

//encrypt the captable in-place
static int encrypt_bottle(bottle_t* bottle) {
	assert(bottle != NULL);

	//aes_context ctx;

	//TODO: noop for the moment
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
	sha1_buffer((unsigned char*)bottle->header, sizeof(bottle_header_t), sha1data);
	memcpy(bottle->header->header_signature, sha1data, sizeof(sha1hash_t));

	return ESUCCESS;
}

//emergency security-breakage utility function
static void bottle_annihilate(bottle_t* bottle) {
	memset(bottle->table, 0, bottle->header->size * sizeof(cap_t));
	memset(bottle->header, 0, sizeof(*(bottle->header)));
}

//standard prologue for bottle operations: verify signatures and decrypt
static int bottle_op_prologue(bottle_t* bottle) {
	//check the bottle is valid, usable on this machine, signed, etc
	DO_OR_BAIL(0, check_bottle, bottle);

	//decrypt the captable
	DO_OR_BAIL(0, decrypt_bottle, bottle);

	return ESUCCESS;
}
//standard epilogue for bottle operations: encrypt and sign
static int bottle_op_epilogue(bottle_t* bottle) {
	int rv;
	
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

	//first, clear the header and the table first
	//TODO: is the header clear necessary?
	uint32_t size  = bottle.header->size;
	uint32_t flags = bottle.header->flags;
	memset(bottle.header, 0, sizeof(bottle_header_t));

	for(int i = 0; i < size; i++) {
		bottle.table[i].magic_start  = CAP_MAGIC_TOP;
		memset(&(bottle.table[i].key.bytes),    0, sizeof(aeskey_t));
		memset(&(bottle.table[i].issuer.bytes), 0, sizeof(aeskey_t));
		bottle.table[i].oid          = 0;
		bottle.table[i].expiry       = 0;
		bottle.table[i].urights      = 0;
		bottle.table[i].srights      = 0;
		bottle.table[i].magic_bottom = CAP_MAGIC_BOTTOM;
	}

	bottle.header->size  = size;
	bottle.header->flags = flags;
	if(flags != 0)
		return -ENOTSUP;

#ifdef BOTTLE_CAP_TEST
	printf("BEK is: 0x");
	for(int i = 0; i < 4; i++) {
		bottle.header->bek.dwords[i] = (uint32_t)rand();
		printf("%08x", bottle.header->bek.dwords[i]);
	}
	printf(".\n");
#else  //BOTTLE_CAP_TEST
	//TODO: use TPM's RNG to generate BEK
	memset(&(bottle.header->bek), 0, sizeof(bottle.header->bek));
#endif //BOTTLE_CAP_TEST

	//insert magic numbers
	bottle.header->magic_top = BOTTLE_MAGIC_TOP;
	bottle.header->magic_bottom = BOTTLE_MAGIC_BOTTOM;

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

