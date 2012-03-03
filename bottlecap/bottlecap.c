#include "bottlecap.h"
#include "sha1.h"

#include "assert.h"

//max table length is one 4k page for the moment. to be revised
#define PAGE_SIZE 4096
#define MAX_TABLE_LENGTH (PAGE_SIZE/sizeof(cap_t))

#define DO_OR_BAIL(op, args...)          \
do {                                     \
	int32_t rv = op(args);               \
	if(rv != ESUCCESS) {                 \
		return rv;                       \
	}                                    \
} while (0)

//check the bottle is valid, usable on this machine, signed, etc
static int32_t check_bottle(bottle_t* bottle) {
	assert(bottle != NULL);
	return -ENOSYS;
}

//decrypt the captable in-place
static int32_t decrypt_bottle(bottle_t* bottle) {
	//TODO: noop for the moment
	return ESUCCESS;
}

//encrypt the captable in-place
static int32_t encrypt_bottle(bottle_t* bottle) {
	//TODO: noop for the moment
	return ESUCCESS;
}

static int32_t sign_bottle(bottle_t* bottle) {
	//TODO generate real signatures
	//table
	sha1hash_t sha1data;
	sha1_buffer(bottle->table, size * sizeof(cap_t), sha1data);
	memcpy(bottle->header->captable_signature, sha1data, sizeof(sha1hash_t));
	//header
	sha1_buffer(bottle->header, sizeof(bottle_header_t), sha1data);
	memcpy(bottle->header->header_signature, sha1data, sizeof(sha1hash_t));

	return ESUCCESS;
}

static int32_t bottle_op_prologue(bottle_t* bottle) {
	//check the bottle is valid, usable on this machine, signed, etc
	DO_OR_BAIL(check_bottle, &bottle);

	//decrypt the captable
	DO_OR_BAIL(decrypt_bottle, &bottle);
}
static int32_t bottle_op_epilogue(bottle_t* bottle) {
	//encrypt the captable
	DO_OR_BAIL(encrypt_bottle, &bottle);

	//generate signatures
	DO_OR_BAIL(sign_bottle, &bottle);

	//TODO: what happens if these fail?
}

//BOTTLE CREATION/DELETION
int32_t bottle_init(bottle_t bottle) {
	if(bottle.header == NULL || bottle.table == NULL)
		return -ENOMEM;

	//impose a maximum size of one page for a table
	if(bottle.header->size > MAX_TABLE_LENGHTH)
		return -ENOMEM;

	//first, clear the header and the table first
	//TODO: is the header clear necessary?
	uint32_t size  = bottle.header->size;
	uint32_t flags = bottle.header->flags;
	memset(bottle.header, 0, sizeof(bottle_header_t));
	memset(bottle.table , 0, size * sizeof(cap_t));

	bottle.header->size  = size;
	bottle.header->flags = flags;
	if(flags != 0)
		return -ENOTSUP;
	//TODO: use TPM's RNG to generate BEK
	bottle.header->bek   = 0;

	//insert magic numbers
	bottle.header->magic_top = BOTTLE_MAGIC_TOP;
	bottle.header->magic_bottom = BOTTLE_MAGIC_BOTTOM;

	DO_OR_BAIL(bottle_op_epilogue, &bottle);

	return ESUCCESS;
}
int32_t bottle_destroy(bottle_t bottle) {
	//there's really very little to do here
	//even blowing away the keys would just be for show
	//TODO: might become useful once we start using counters
	return -ENOTSUP;
}

//BOTTLE STATE FUNCTIONS
int32_t bottle_query_free_slots(bottle_t bottle, uint32_t* slots) {
	if(slots == NULL)
		return -EINVAL;

	DO_OR_BAIL(bottle_op_prologue, &bottle);

	uint32_t free_slots = 0;
	for(int i = 0; i < bottle.header->size; i++) {
		if(bottle->table[i].expiry == 0) {
			free_slots++;
		}
	}

	*slots = free_slots;

	DO_OR_BAIL(bottle_op_epilogue, &bottle);
}
int32_t bottle_expire(bottle_t bottle, uint64_t time, uint32_t* slots) {
	if(slots == NULL)
		return -EINVAL;

	DO_OR_BAIL(bottle_op_prologue, &bottle);

	uint32_t free_slots = 0;
	for(int i = 0; i < bottle.header->size; i++) {
		if(bottle->table[i].expiry <= time) {
			bottle->table[i].expiry = 0;
		}
		if(bottle->table[i].expiry == 0) {
			free_slots++;
		}
	}

	*slots = free_slots;

	DO_OR_BAIL(bottle_op_epilogue, &bottle);
}

//INTER-MACHINE BOTTLE MIGRATION FUNCTIONS
int32_t bottle_export(bottle_t bottle, tpm_rsakey_t* rsrk, tpm_rsakey_t* brk) {
	return -ENOSYS;
}
int32_t bottle_import(bottle_t bottle, tpm_rsakey_t* brk) {
	return -ENOSYS;
}

//CAP INSERTION/DELETION FUNCTIONS
int32_t bottle_cap_add(bottle_t bottle, tpm_encrypted_cap_t* cap, uint32_t* slot) {
	return -ENOSYS;
}
int32_t bottle_cap_delete(bottle_t bottle, uint32_t slot) {
	return -ENOSYS;
}

//INTER-BOTTLE CAP MIGRATION
int32_t bottle_cap_export(bottle_t bottle, uint32_t slot, tpm_rsakey_t* rbrk, bool move, tpm_encrypted_cap_t* cap) {
	return -ENOSYS;
}

//CAP INVOCATION FUNCTIONS
//TODO: Needham-Schroeder (ie Kerberos) protocol

