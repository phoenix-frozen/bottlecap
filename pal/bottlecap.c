#include <assert.h>
#include <string.h>

#include <sha1.h>
#include <polarssl/aes.h>

#include <bottlecap/errors.h>
#include <bottlecap/bottlecap.h>

#include <tpm.h>

#include <util.h>

#include "misc.h"
#include "tpm_crypto.h"

#include <stdio.h>
#ifdef BOTTLE_CAP_TEST
#include <stdio.h>
#include <stdlib.h>
#endif //BOTTLE_CAP_TEST

#define TPM_LOCALITY 2

//generate a 128-bit AES key
static int generate_aes_key(aeskey_t* key) {
	assert(key != NULL);

#ifdef BOTTLE_CAP_TEST
	//ask libc for a random number
	for(int i = 0; i < 4; i++) {
		key->dwords[i] = (uint32_t)rand();
	}
#else  //BOTTLE_CAP_TEST
	//ask the TPM for a random number
	uint32_t size = sizeof(aeskey_t);
	DO_OR_BAIL(ECRYPTFAIL, NOTHING, tpm_get_random, TPM_LOCALITY, key->bytes, &size);
	if(size != sizeof(aeskey_t))
		return -ECRYPTFAIL;
#endif //BOTTLE_CAP_TEST

#if 0
	printf("Generated key: 0x");
	for(int i = 0; i < 4; i++) {
		printf("%08x", key->dwords[i]);
	}
	printf("\n");
#endif

	return ESUCCESS;
}

//check the bottle is valid, usable on this machine, signed, etc
static int check_bottle(bottle_t* bottle) {
	DPRINTF("enter(%p)\n", bottle);
	//bottle == NULL is a programming error
	assert(bottle != NULL);

	//initial sanity checks
	DPRINTF("data structure checks...\n");
	if(bottle->header == NULL)
		return -ENOMEM;
	if(bottle->table == NULL)
		return -ENOMEM;

	//correct header magic
	DPRINTF("top magic check...\n");
	if(bottle->header->magic_top != BOTTLE_MAGIC_TOP)
		return -EINVAL;
	DPRINTF("bottom magic check...\n");
	if(bottle->header->magic_bottom != BOTTLE_MAGIC_BOTTOM)
		return -EINVAL;

#ifndef BOTTLE_CAP_TEST
	//sealed blob size
	DPRINTF("sealed-size check...\n");
	if(bottle->header->bek.sealed_data_size > sizeof(bottle->header->bek.sealed_data))
		return -EINVAL;
#endif //BOTTLE_CAP_TEST

	//correct table dimensions
	DPRINTF("bottle size check...\n");
	if(bottle->header->size > MAX_TABLE_LENGTH)
		return -ENOMEM;

	DPRINTF("exit\n");
	return ESUCCESS;
}

//check the bottle is valid, usable on this machine, signed, etc
//assumes BEK is available
static int verify_bottle(bottle_t* bottle) {
	sha1hash_t sha1data, temp;

	//bottle == NULL is a programming error
	assert(bottle != NULL);

	//we can now simply assert that everything that's checked in check_bottle is true
	assert(bottle->header->magic_top == BOTTLE_MAGIC_TOP);
	assert(bottle->header->magic_bottom == BOTTLE_MAGIC_BOTTOM);
	assert(bottle->header->size <= MAX_TABLE_LENGTH);

	//table HMAC
	hmac_sha1_buffer((unsigned char*)(bottle->table), bottle->header->size * sizeof(cap_t),
	                 bottle->bek.bytes, sizeof(bottle->bek),
	                 sha1data);
	DO_OR_BAIL(ESIGFAIL, NOTHING, memcmp, bottle->header->table_hmac, sha1data, sizeof(sha1hash_t));

	//header signature
	memcpy(temp, bottle->header->header_hmac, sizeof(temp));                        //copy the header HMAC out...
	memset(&(bottle->header->header_hmac), 0, sizeof(bottle->header->header_hmac)); //... so we can zero the header field...
	hmac_sha1_buffer((unsigned char*)bottle->header, sizeof(bottle_header_t),       //... and generate the HMAC
	                 bottle->bek.bytes, sizeof(bottle->bek),
	                 sha1data);
	memcpy(bottle->header->header_hmac, temp, sizeof(temp));                        //then copy it back in...
	DO_OR_BAIL(ESIGFAIL, NOTHING, memcmp, temp, sha1data, sizeof(temp));            //... and do the actual comparison

	return ESUCCESS;
}

//check that a cap is sane
static int check_cap(cap_t* cap) {
	assert(cap != NULL);

	if(cap->magic_top != CAP_MAGIC_TOP)
		return -ECORRUPT;
	if(cap->magic_bottom != CAP_MAGIC_BOTTOM)
		return -ECORRUPT;

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
	for(int i = 0; i < bottle->header->size; i++)
		DO_OR_BAIL(0, NOTHING, check_cap, bottle->table + i);

	return ESUCCESS;
}

//emergency security-breakage utility function
static void bottle_annihilate(bottle_t* bottle) {
	ANNIHILATE(bottle->table,  bottle->header->size * sizeof(cap_t));
	ANNIHILATE(bottle->header, sizeof(*(bottle->header)));
	ANNIHILATE(bottle->bek.bytes, sizeof(bottle->bek));
}

//key-sealing utility functions
/* TODO: BUG: TPM_UNSEAL drops state proof block!
 * 
 * There's currently a security vulnerability in the way we use the TPM. We
 * need to get the state proof from the TPM_UNSEAL operation to verify that the
 * key was indeed created by a previous invocation of BottleCap; otherwise, a
 * bottle is trivial to forge in such a way as to expose all its secrets.
 */
#ifdef BOTTLE_CAP_TEST
static int seal_key(tpm_aeskey_t* keyblob, aeskey_t* key) {
	assert(keyblob != NULL);
	assert(key != NULL);

	memcpy(keyblob->sealed_data, key->bytes, sizeof(*key));
	return 0;
}
static int unseal_key(tpm_aeskey_t* keyblob, aeskey_t* key) {
	assert(keyblob != NULL);
	assert(key != NULL);

	memcpy(key->bytes, keyblob->sealed_data, sizeof(*key));
	return 0;
}
#else //BOTTLE_CAP_TEST
static int seal_key(tpm_aeskey_t* keyblob, aeskey_t* key) {
	assert(keyblob != NULL);
	assert(key != NULL);

	//construct PCR value array
	tpm_pcr_value_t pcr_values[3];

	//this is what the tpm_* functions ask for. gofigure
	tpm_pcr_value_t* pcrs[3] = {
		&(pcr_values[0]),
		&(pcr_values[1]),
		&(pcr_values[2]),
	};

	//read the current PCR values
	for(int i = 0; i < 3; i++)
		DO_OR_BAIL(ECRYPTFAIL, NOTHING, tpm_pcr_read, TPM_LOCALITY, 17 + i, pcrs[i]);

	//allocate remaining metadata
	uint8_t pcr_indcs[3] = {17, 18, 19};
	uint32_t sealed_data_size = sizeof(keyblob->sealed_data);

	//seal the key blob
	DO_OR_BAIL(ECRYPTFAIL, NOTHING, tpm_seal, TPM_LOCALITY,
	//int testval = tpm_seal(TPM_LOCALITY,
			TPM_LOC_ZERO | TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE | TPM_LOC_FOUR,
			3, pcr_indcs,
			3, pcr_indcs,
			(const tpm_pcr_value_t**)pcrs, //fuck you Intel
			sizeof(*key),
			key->bytes,
			&sealed_data_size,
			keyblob->sealed_data
	);
	//printf("tpm_seal(%d, 0x%x, %d, %p, %d, %p, %p, %d, %p, %d->%d, %p): %d\n",
	//		TPM_LOCALITY,
	//		TPM_LOC_ZERO | TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE | TPM_LOC_FOUR,
	//		3, pcr_indcs,
	//		3, pcr_indcs,
	//		pcrs,
	//		sizeof(*key),
	//		key->bytes,
	//		sizeof(keyblob->sealed_data),
	//		sealed_data_size,
	//		keyblob->sealed_data,
	//		testval
	//);

	keyblob->sealed_data_size = sealed_data_size;
	return 0;
}
static int unseal_key(tpm_aeskey_t* keyblob, aeskey_t* key) {
	assert(keyblob != NULL);
	assert(key != NULL);

	uint32_t secret_size = sizeof(*key);

	DO_OR_BAIL(ECRYPTFAIL, ANNIHILATE(key, sizeof(*key)), tpm_unseal, TPM_LOCALITY, keyblob->sealed_data_size, keyblob->sealed_data, &secret_size, key->bytes);

	if(secret_size != sizeof(*key)) {
		ANNIHILATE(key, sizeof(*key));
		return -ECRYPTFAIL;
	}

	return ESUCCESS;
}
#endif //BOTTLE_CAP_TEST

//decrypt the captable in-place
//assumes that the BEK is already decrypted
static int decrypt_bottle(bottle_t* bottle) {
	//bottle == NULL is a programming error
	assert(bottle != NULL);

	//these three were checked in check_bottle, so their failure now would be a programming error
	assert(bottle->header != NULL);
	assert(bottle->table  != NULL);
	assert(bottle->header->size <= MAX_TABLE_LENGTH);

	//acquire AES stuff -- IV is in plaintext in the header, BEK is sealed to the TPM
	uint128_t biv = bottle->header->biv;

	aes_context ctx;
	size_t iv_off = 0;

	//Note: we're using the CFB128 mode, which means we use _enc even in decrypt mode
	DO_OR_BAIL(ECRYPTFAIL, NOTHING, aes_setkey_enc, &ctx, bottle->bek.bytes, BOTTLE_KEY_SIZE);

	for(uint32_t i = 0; i < bottle->header->size; i++)
		DO_OR_BAIL(ECRYPTFAIL, NOTHING, do_cap_crypto, &ctx, AES_DECRYPT, &iv_off, &biv, bottle->table + i);

	return ESUCCESS;
}

//encrypt the captable in-place
//assumes the BEK was extracted during decrypt_bottle
static int encrypt_bottle(bottle_t* bottle, int regen) {
	//bottle == NULL is a programming error
	assert(bottle != NULL);

	//these three were checked in check_bottle, so their failure now would be a programming error
	assert(bottle->header != NULL);
	assert(bottle->table  != NULL);
	assert(bottle->header->size <= MAX_TABLE_LENGTH);

	//acquire AES stuff -- IV is either in plaintext in the header or from an RNG, BEK should be decrypted in the holding area
	uint128_t biv;
	if(regen) {
		generate_aes_key(&biv);
		bottle->header->biv = biv;
	} else {
		biv = bottle->header->biv;
	}
	aes_context ctx;
	size_t iv_off = 0;

	//Note: we're using the CFB128 mode
	DO_OR_BAIL(ECRYPTFAIL, NOTHING, aes_setkey_enc, &ctx, bottle->bek.bytes, BOTTLE_KEY_SIZE);

	for(uint32_t i = 0; i < bottle->header->size; i++)
		DO_OR_BAIL(ECRYPTFAIL, NOTHING, do_cap_crypto, &ctx, AES_ENCRYPT, &iv_off, &biv, bottle->table + i);

	return ESUCCESS;
}

//sign the bottle's current state
//assumes the BEK is available
static int sign_bottle(bottle_t* bottle) {
	assert(bottle != NULL);

	//HMAC table
	hmac_sha1_buffer((unsigned char*)(bottle->table), bottle->header->size * sizeof(cap_t),
	                 bottle->bek.bytes, sizeof(bottle->bek),
	                 bottle->header->table_hmac);

	//HMAC header
	memset(&(bottle->header->header_hmac), 0, sizeof(bottle->header->header_hmac));
	hmac_sha1_buffer((unsigned char*)bottle->header, sizeof(bottle_header_t),
	                 bottle->bek.bytes, sizeof(bottle->bek),
	                 bottle->header->header_hmac); //XXX: this is cheating -- I avoid doing it onto the stack and copying because
	                                               //                         I know that's how it's implemented

	return ESUCCESS;
}

//standard prologue for bottle operations: verify signatures and decrypt
static int bottle_op_prologue(bottle_t* bottle) {
	assert(bottle != NULL);

	//check the bottle header fields are sane
	DO_OR_BAIL(0, NOTHING, check_bottle, bottle);

	//unseal BEK
	DO_OR_BAIL(ECRYPTFAIL, NOTHING, unseal_key, &(bottle->header->bek), &(bottle->bek));

	//check the bottle hashes and signatures
	DO_OR_BAIL(0, ANNIHILATE(bottle->bek.bytes, sizeof(aeskey_t)), verify_bottle, bottle);

	//decrypt the captable
	DO_OR_BAIL(0, ANNIHILATE(bottle->bek.bytes, sizeof(aeskey_t)), decrypt_bottle, bottle);

	//check that the decrypted captable makes sense
	DO_OR_BAIL(0, ANNIHILATE(bottle->bek.bytes, sizeof(aeskey_t)), check_caps, bottle);

	return ESUCCESS;
}
/* standard epilogue for bottle operations: encrypt and sign.
 * second argument controls whether to regenerate the IV and
 * signatures; should only be false on a read-only operation
 */
static int bottle_op_epilogue(bottle_t* bottle, int regen) {
	assert(bottle != NULL);

	//check that the captable makes sense
	DO_OR_BAIL(0, NOTHING, check_caps, bottle);

	//encrypt the captable, obliterating sensitive data on error
	DO_OR_BAIL(0, bottle_annihilate(bottle), encrypt_bottle, bottle, regen);

	//generate signatures
	if(regen)
		DO_OR_BAIL(0, ANNIHILATE(bottle->bek.bytes, sizeof(bottle->bek)), sign_bottle, bottle);

	//clear unencrypted BEK
	ANNIHILATE(bottle->bek.bytes, sizeof(bottle->bek));

	return ESUCCESS;
}

//BOTTLE CREATION/DELETION
int bottle_init(bottle_t* bottle) {
	if(bottle->header == NULL || bottle->table == NULL)
		return -ENOMEM;

	//impose a maximum size of one page for a table
	if(bottle->header->size > MAX_TABLE_LENGTH)
		return -ENOMEM;

	//memorise some important information, and check it
	uint32_t size  = bottle->header->size;
	uint32_t flags = bottle->header->flags;
	if(flags != 0)
		return -ENOTSUP;

	//clear the header, and put back the information we borrowed
	memset(bottle->header, 0, sizeof(*(bottle->header)));
	bottle->header->size  = size;
	bottle->header->flags = flags;

	//generate the BEK
	DO_OR_BAIL(0, NOTHING, generate_aes_key, &(bottle->bek));
	DO_OR_BAIL(ECRYPTFAIL, ANNIHILATE(&(bottle->bek), sizeof(bottle->bek)), seal_key, &(bottle->header->bek), &(bottle->bek));

	//insert magic numbers
	bottle->header->magic_top = BOTTLE_MAGIC_TOP;
	bottle->header->magic_bottom = BOTTLE_MAGIC_BOTTOM;

	//format the table
	memset(bottle->table, 0, size * sizeof(cap_t));
	for(int i = 0; i < size; i++) {
		bottle->table[i].magic_top    = CAP_MAGIC_TOP;
		bottle->table[i].magic_bottom = CAP_MAGIC_BOTTOM;
	}

	//encrypt and sign
	DO_OR_BAIL(0, NOTHING, bottle_op_epilogue, bottle, 1);

	return ESUCCESS;
}
int bottle_destroy(bottle_t* bottle) {
	//there's really very little to do here
	//even blowing away the keys would just be for show
	//TODO: might become useful once we start using counters
	return -ENOTSUP;
}

//BOTTLE STATE FUNCTIONS
int bottle_query_free_slots(bottle_t* bottle, uint32_t* slots) {
	if(slots == NULL)
		return -EINVAL;

	DO_OR_BAIL(0, NOTHING, bottle_op_prologue, bottle);

	uint32_t free_slots = 0;
	for(uint32_t i = 0; i < bottle->header->size; i++) {
		assert(bottle->table[i].magic_top == CAP_MAGIC_TOP);
		assert(bottle->table[i].magic_bottom == CAP_MAGIC_BOTTOM);

		if(bottle->table[i].expiry == 0) {
			free_slots++;
		}
	}

	*slots = free_slots;

	DO_OR_BAIL(0, NOTHING, bottle_op_epilogue, bottle, 0);

	return ESUCCESS;
}
int bottle_expire(bottle_t* bottle, uint64_t time, uint32_t* slots) {
	if(slots == NULL)
		return -EINVAL;

	DO_OR_BAIL(0, NOTHING, bottle_op_prologue, bottle);

	uint32_t free_slots = 0;
	for(uint32_t i = 0; i < bottle->header->size; i++) {
		assert(bottle->table[i].magic_top == CAP_MAGIC_TOP);
		assert(bottle->table[i].magic_bottom == CAP_MAGIC_BOTTOM);

		if(bottle->table[i].expiry <= time) {
			//this cap is to be expired -- annihilate it
			ANNIHILATE(bottle->table + i, sizeof(cap_t));
			bottle->table[i].magic_top = CAP_MAGIC_TOP;
			bottle->table[i].magic_bottom = CAP_MAGIC_BOTTOM;
		}
		if(bottle->table[i].expiry == 0) {
			free_slots++;
		}
	}

	*slots = free_slots;

	DO_OR_BAIL(0, NOTHING, bottle_op_epilogue, bottle, 1);

	return ESUCCESS;
}

//INTER-MACHINE BOTTLE MIGRATION FUNCTIONS
#if 0
int bottle_export(bottle_t* bottle, tpm_rsakey_t* rsrk, tpm_rsakey_t* brk) {
	return -ENOSYS;
}
int bottle_import(bottle_t* bottle, tpm_rsakey_t* brk) {
	return -ENOSYS;
}
#endif

//CAP INSERTION/DELETION FUNCTIONS
int bottle_cap_add(bottle_t* bottle, tpm_encrypted_cap_t* cryptcap, uint32_t* slot) {
	//pull relevant data onto our stack
	//TODO: tpm_encrypted_cap_t contains key in plaintext
	//      for the moment, we just assume a tpm_encrypted_cap_t contains
	//      its key in plaintext. and copy everything out to our stack
	aeskey_t aeskey;
	DO_OR_BAIL(ECRYPTFAIL, NOTHING, unseal_key, &(cryptcap->key), &aeskey);
	uint128_t iv = cryptcap->iv;
	cap_t cap = cryptcap->cap;

	//initialise AES
	aes_context ctx;
	size_t iv_off = 0;
	//Note: we're using the CFB128 mode, so we use _enc even to decrypt
	DO_OR_BAIL(ECRYPTFAIL, NOTHING, aes_setkey_enc, &ctx, aeskey.bytes, BOTTLE_KEY_SIZE);

	//decrypt the cap
	DO_OR_BAIL(ECRYPTFAIL, NOTHING, do_cap_crypto, &ctx, AES_DECRYPT, &iv_off, &iv, &cap);

	//check the cap is valid
	DO_OR_BAIL(0, ANNIHILATE(&cap, sizeof(cap_t)), check_cap, &cap);

	//0 expiry date not allowed
	if(cap.expiry == 0)
		return -EINVAL;

	//now that we've successfully decrypted the cap, decrypt the bottle
	DO_OR_BAIL(0, ANNIHILATE(&cap, sizeof(cap_t)), bottle_op_prologue, bottle);

	//find a free slot
	uint32_t i;
	for(i = 0; i < bottle->header->size; i++) {
		if(bottle->table[i].expiry == 0)
			break;
	}

	//we found a free slot...
	if(i < bottle->header->size) {
		//... fill it with the cap...
		*(bottle->table + i) = cap;
		//... and tell the caller where it is
		*slot = i;
	}

	//we're done; destroy the unencrypted cap
	ANNIHILATE(&cap, sizeof(cap));

	DO_OR_BAIL(0, NOTHING, bottle_op_epilogue, bottle, 1);

	return (i < bottle->header->size) ? ESUCCESS : -ENOMEM;
}
int bottle_cap_delete(bottle_t* bottle, uint32_t slot) {
	if(slot > bottle->header->size)
		return -EINVAL;

	int resign = 0;

	DO_OR_BAIL(0, NOTHING, bottle_op_prologue, bottle);

	if(bottle->table[slot].expiry != 0) {
		ANNIHILATE(bottle->table + slot, sizeof(cap_t));
		bottle->table[slot].magic_top = CAP_MAGIC_TOP;
		bottle->table[slot].magic_bottom = CAP_MAGIC_BOTTOM;
		resign = 1;
	}

	DO_OR_BAIL(0, NOTHING, bottle_op_epilogue, bottle, resign);

	return ESUCCESS;
}

//INTER-BOTTLE CAP MIGRATION
#if 0
int bottle_cap_export(bottle_t* bottle, uint32_t slot, tpm_rsakey_t* rbrk, int32_t move, tpm_encrypted_cap_t* cap) {
	return -ENOSYS;
}
#endif

//CAP INVOCATION FUNCTIONS
int bottle_cap_attest(bottle_t* bottle, uint32_t slot, uint128_t nonce, uint64_t expiry, uint32_t urightsmask, cap_attestation_block_t* output) {
	if(output == NULL)
		return -ENOMEM;

	/* TODO: Performance bug: decrypt entire table for single-cap ops.
	 * 
	 * For performance reasons, we probably want to rejig the crypto so that we
	 * can decrypt just one cap and attest it.  Ditto for the other single-slot
	 * operations.
	 */
	DO_OR_BAIL(0, NOTHING, bottle_op_prologue, bottle);

	int rv = ESUCCESS;

	//can't attest an empty slot
	if(bottle->table[slot].expiry == 0) {
		rv = -EINVAL;
		goto attest_exit;
	}

	//trying to include rights you don't have is an error
	if((urightsmask & (~(bottle->table[slot].urights))) != 0) {
		rv = -EINVAL;
		goto attest_exit;
	}

	if(bottle->table[slot].expiry < expiry)
		expiry = bottle->table[slot].expiry;

	//storage area for unencrypted authdata
	cap_attestation_block_t result;

	//fill in everything except the proof, which we don't yet have
	result.authdata.oid = bottle->table[slot].oid;
	result.authdata.expiry = expiry;
	result.authdata.padding_1 = 0;
	result.authdata.urights = bottle->table[slot].urights & urightsmask; //this is probably redundant, given the check above
	result.authdata.padding_2 = 0;

	//getting this far means we can start writing to the output buffer. write the unencrypted data first
	output->nonce = nonce;
	output->expiry  = expiry;
	output->urights = urightsmask;

	//initialise AES state
	aes_context ctx;
	size_t iv_off = 0;
	uint128_t iv = nonce;;
	//Note: we're using the CFB128 mode, so we use _enc even to decrypt
	if(aes_setkey_enc(&ctx, bottle->table[slot].issuer.bytes, BOTTLE_KEY_SIZE) != 0) {
		rv = -ECRYPTFAIL;
		goto attest_exit;
	}

	//now encrypt authdata into the output buffer
	if(aes_crypt_cfb128(&ctx, AES_ENCRYPT, sizeof(result.authdata), &iv_off, iv.bytes, result.authdata.bytes, output->authdata.bytes) != 0) {
		rv = -ECRYPTFAIL;
		goto attest_exit;
	}

	//generate signature
	//TODO: generate real signature
	//XXX: warning, this pointer arithmetic assumes little-endian
	sha1_buffer((unsigned char*)&(output->nonce), sizeof(output->nonce) + sizeof(output->authdata), output->signature.hash);
	assert(output->expiry  == expiry);
	assert(output->urights == urightsmask);

attest_exit:
	ANNIHILATE(&result, sizeof(result));
	DO_OR_BAIL(0, NOTHING, bottle_op_epilogue, bottle, 0);

	return rv;
}

//make some compile-time guarantees about data structure sizes
#define COMPILE_TIME_ASSERT(pred) switch(0){case 0:case pred:;}

static void compile_time_asserts(void) __attribute__((unused));
static void compile_time_asserts(void) {
	cap_attestation_block_t attest_block;
	COMPILE_TIME_ASSERT(sizeof(attest_block.authdata) == sizeof(attest_block.authdata.bytes));

	cap_t cap;
	COMPILE_TIME_ASSERT(sizeof(cap.bytes) == sizeof(cap));
}
