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
	uint32_t sealed_data_size;
	uint8_t  sealed_data[384];
} tpm_aeskey_t;

#endif /* __CRYPTO_H__ */

