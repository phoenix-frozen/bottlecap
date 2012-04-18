#ifndef __CAP_H__
#define __CAP_H__

#include <stdint.h>

#include "crypto.h"

#define CAP_MAGIC_TOP    0xCA9A8171
#define CAP_MAGIC_BOTTOM 0x1718A9AC

#define CAP_RIGHT_MIGRATABLE 0x1 //this cap may be migrated to another bottle

#define BOTTLE_KEY_SIZE 128 //in bits

/** A capability
 * 
 * This structure is carefully designed to be an integer number of AES-128
 * blocks. The magic numbers are placed to foil an attempted bit-manipulation
 * attack on AES-CFB128: CFB allows arbitrary bit-manipulation of one block at
 * the expense of randomising every subsequent one, so we use magic numbers as
 * canaries in case of such manipulation.
 */
typedef union {
	struct {
		uint32_t magic_top;    //0xCA9A8171
		uint32_t urights;      //rights mask, used by issuer
		uint64_t oid;          //object-ID field, used by issuer
		aeskey_t issuer;       //issuer's AES-128 key
		uint64_t expiry;       //cap expiry time, in unsigned 64-bit Unix time, determined by issuer
		                       //Note: expiry == 0 -> slot is empty
		uint32_t srights;      //BottleCap rights word, determined by issuer
		uint32_t magic_bottom; //0x1718A9AC
	};
	uint8_t bytes[48];
} cap_t;

//represents a cap that is bound/sealed to a TPM state, encrypted with a
// key from a tpm_rsakey_t
typedef struct {
	tpm_aeskey_t key; //{key}_[some TPM-bound RSA key]
	uint128_t iv;     //IV for encryption of cap
	cap_t cap;        //{cap}_key
	sha1hash_t hmac;  //SHA1(cap, key)
} tpm_encrypted_cap_t;

#endif /* __CAP_H__ */

