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

typedef struct {
	uint32_t magic_top; //0x80771ECA

	//aes cryptographic stuff; always 128-bit AES
	uint128_t    biv; //{Bottle Initialization Vector}_SRK (sealed)
	tpm_aeskey_t bek; //{Bottle Encryption Key}_SRK (sealed)

	//bottle configuration stuff
	uint32_t flags; //timed (that is, uses monotonic counters), migratable (off this TPM)
	uint32_t size;  //number of slots in the bottle

	//matching/integrity check
	sha1hash_t header_hmac; //SHA1(header with this field as zero, BEK)
	sha1hash_t table_hmac;  //SHA1({main table}_BEK, BEK)

	uint32_t magic_bottom; //0x909ACE17
} bottle_header_t;

typedef struct {
	bottle_header_t* header;   //bottle header structure
	//TODO: aeskey_t         password; //password which will be XOR'd into BEK
	aeskey_t         bek;      //placeholder for decrypted BEK
	cap_t*           table;    //{Caps}_BEK
} bottle_t;

#endif /* __BOTTLE_H__ */

