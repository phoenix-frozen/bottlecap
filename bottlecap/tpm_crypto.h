#ifndef __TPM_CRYPTO_H__
#define __TPM_CRYPTO_H__

#include <stdint.h>

#include "cap.h"

typedef sha1hash_t uint32_t[5]

typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs

	//represents an RSA keypair data blob that can be loaded into the TPM
} tpm_rsakey_t;

typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs

	//represents an AES key that is bound/sealed to a TPM state, encrypted
	// with a key from a tpm_rsakey_t
} tpm_aeskey_t;

typedef struct {
	tpm_encrypted_aeskey_t key; //{key}_[some TPM-bound RSA key]
	cap_t cap; //{cap}_key

	//represents a cap that is bound/sealed to a TPM state, encrypted
	// with a key from a tpm_rsakey_t
} tpm_encrypted_cap_t;

typedef struct {
	//TODO: placeholder data structure until I learn a bit more about TPMs

	//represents a digital signature of a block of data, using a key from
	// a tpm_rsakey_t
} tpm_signature_t;


#endif /* __TPM_CRYPTO_H__ */

