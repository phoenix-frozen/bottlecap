#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>

#include <aes.h>

typedef union {
	uint64_t qwords[2];
	uint32_t dwords[4];
	uint8_t  bytes [16];
} uint128_t;

typedef uint128_t aeskey_t;

typedef uint8_t sha1hash_t[20];

//an AES key that is bound/sealed to a TPM state, encrypted with a key
// from a tpm_rsakey_t
typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs

	aeskey_t aeskey;
} tpm_aeskey_t;

//a 'symmetric signature' -- that is, a SHA1 hash that's been AES-encrypted
typedef struct {
	uint128_t iv;
	union {
		uint128_t  encdata[2]; //padding out to a block size
		sha1hash_t hash;       //hash of data
	};
} sym_signature_t;

#endif /* __CRYPTO_H__ */

