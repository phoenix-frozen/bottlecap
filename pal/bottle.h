#ifndef __BOTTLE_H__
#define __BOTTLE_H__

#include <stdint.h>

#include "cap.h"
#include "tpm_crypto.h"
#include "util.h"

#define BOTTLE_MAGIC_TOP    0x80771ECA
#define BOTTLE_MAGIC_BOTTOM 0x909ACE17

#define BOTTLE_FLAG_SINGLETON  BIT(0) //this bottle uses monotonic counters to ensure non-copying
#define BOTTLE_FLAG_MIGRATABLE BIT(1) //this bottle may be migrated to another TPM

typedef struct {
	uint32_t magic_top; //0x80771ECA

	//rsa cryptographic stuff; always 2048-bit RSA keys for TPM compatibility
	//TODO: tpm_rsakey_t brk; //{Bottle Root Key}_SEK (sealed)
	//TODO: tpm_rsakey_t bsk; //{Bottle Signing Key}_BRK (bound)
	//TODO: tpm_rsakey_t brk_public; //to be given to cap issuers to send caps
	//TODO: tpm_rsakey_t bsk_public; //to be given to cap issuers to check quotes

	//aes cryptographic stuff; always 128-bit AES
	aeskey_t bek; //{Bottle Encryption Key}_SRK (bound)
	aeskey_t biv; //{Bottle Initialization Vector}_SRK (bound)

	//bottle configuration stuff
	uint32_t     flags; //timed (that is, uses monotonic counters), migratable (off this TPM)
	uint32_t     size;  //number of slots in the bottle

	//matching check
	//TODO: uint256_t    captable_signature; //{SHA1(encrypted main table)}_BSK
	//TODO: uint256_t    header_signature; //{SHA1(header, assuming this field is zero)}_BSK
	sha1hash_t    captable_signature; //{SHA1(main table)}_BSK
	sha1hash_t    header_signature; //{SHA1(header, assuming this field is zero)}_BSK


	uint32_t magic_bottom; //0x909ACE17
} bottle_header_t;

typedef struct {
	bottle_header_t* header;   //bottle header structure
	//TODO: aeskey_t         password; //password which will be XOR'd into BEK; is this a good idea?
	cap_t*           table;    //{Caps}_BEK
} bottle_t;

#endif /* __BOTTLE_H__ */

