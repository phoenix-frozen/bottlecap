#ifndef __TPM_CRYPTO_H__
#define __TPM_CRYPTO_H__

#include <stdint.h>

#include <aes.h>

#include "cap.h"

typedef unsigned char sha1hash_t[20];

//represents an RSA keypair data blob that can be loaded into the TPM
typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs
} tpm_rsakey_t;

//an AES key that is bound/sealed to a TPM state, encrypted with a key
// from a tpm_rsakey_t
typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs

	aeskey_t aeskey;
} tpm_aeskey_t;

//represents a cap that is bound/sealed to a TPM state, encrypted with a
// key from a tpm_rsakey_t
typedef struct {
	tpm_aeskey_t key; //{key}_[some TPM-bound RSA key]
	cap_t cap;        //{cap}_key, using the key itself as IV (yes, this means it should be a session key)
} tpm_encrypted_cap_t;

//represents a digital signature of a block of data, using a key from a
// tpm_rsakey_t
typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs

	sha1hash_t hash; //SHA1 hash of signed data
} tpm_signature_t;

//utility function for {en,de}crypting a capability
int do_cap_crypto(aes_context *ctx, int mode, size_t *iv_off, aeskey_t* iv, cap_t* cap);

#endif /* __TPM_CRYPTO_H__ */

