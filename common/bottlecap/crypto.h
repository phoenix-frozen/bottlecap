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

//represents an RSA keypair data blob that can be loaded into the TPM
typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs

	uint32_t placeholder;
} tpm_rsakey_t;

//an AES key that is bound/sealed to a TPM state, encrypted with a key
// from a tpm_rsakey_t
typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs

	aeskey_t aeskey;
} tpm_aeskey_t;

//represents a digital signature of a block of data, using a key from a
// tpm_rsakey_t
typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs

	sha1hash_t hash; //SHA1 hash of signed data
} tpm_signature_t;

#endif /* __CRYPTO_H__ */

