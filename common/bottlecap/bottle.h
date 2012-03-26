#ifndef __BOTTLE_H__
#define __BOTTLE_H__

#include <stdint.h>

#include "cap.h"
#include "crypto.h"

#define BOTTLE_MAGIC_TOP    0x80771ECA
#define BOTTLE_MAGIC_BOTTOM 0x909ACE17

#define BOTTLE_MAGIC_SIGNATURE 0x9222824932fc088cULL

#define BOTTLE_FLAG_SINGLETON  0x1 //this bottle uses monotonic counters to ensure non-copying
#define BOTTLE_FLAG_MIGRATABLE 0x2 //this bottle may be migrated to another TPM

typedef union {
	struct {
		uint128_t  iv;
		sha1hash_t captable_hash; //SHA1({main table}_BEK)
		sha1hash_t header_hash;   //SHA1(header [assuming this field is zero])
		uint64_t   magic;         //0x9222824932fc088cULL
	};
	struct {
		uint128_t iv;
		union {
			uint128_t blocks[3]; /* Encrypted form of the above two hashes.
			                      * Looks like:
			                      * | captable_signature |  header_signature  | magic  |
			                      * |    data[0]    |    data[1]     |    data[2]      |
			                      * (1 char = 1 byte, except '|' is an item boundary,
			                      * and represents no space)
			                      */
			unsigned char bytes[48];
		};
	} encrypted_signature;
} bottle_signature_t;

typedef struct {
	uint32_t magic_top; //0x80771ECA

	//aes cryptographic stuff; always 128-bit AES
	uint128_t    biv; //{Bottle Initialization Vector}_SRK (sealed)
	tpm_aeskey_t bek; //{Bottle Encryption Key}_SRK (sealed)

	//bottle configuration stuff
	uint32_t flags; //timed (that is, uses monotonic counters), migratable (off this TPM)
	uint32_t size;  //number of slots in the bottle

	//matching/integrity check
	bottle_signature_t signature;

	uint32_t magic_bottom; //0x909ACE17
} bottle_header_t;

typedef struct {
	bottle_header_t* header;   //bottle header structure
	//TODO: aeskey_t         password; //password which will be XOR'd into BEK
	aeskey_t         bek;      //placeholder for decrypted BEK
	cap_t*           table;    //{Caps}_BEK
} bottle_t;

#endif /* __BOTTLE_H__ */

