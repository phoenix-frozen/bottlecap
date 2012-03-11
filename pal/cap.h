#ifndef __CAP_H__
#define __CAP_H__

#include <stdint.h>

#include "util.h"

#define CAP_MAGIC_TOP    0xCA9A8171
#define CAP_MAGIC_BOTTOM 0x1718A9AC

#define CAP_RIGHT_MIGRATABLE BIT(0) //this cap may be migrated to another bottle

typedef union {
	uint32_t dwords[4];
	uint64_t qwords[2];
	uint8_t  bytes[16];
} aeskey_t; //AES keys are 128 bits

typedef struct {
	uint32_t magic_top; //0xCA9A8171
	uint32_t urights; //rights mask, used by issuer
	uint64_t oid; //object-ID field, used by issuer
	aeskey_t key; //password is a AES-128 key, generated by issuer
	aeskey_t issuer; //issuer's AES-128 key
	uint64_t expiry; //cap expiry time, in unsigned 64-bit Unix time, determined by issuer
	uint32_t srights; //BottleCap rights word, determined by issuer
	//Note: expiry == 0 -> slot is empty
	uint32_t magic_bottom; //0x1718A9AC
} cap_t;


#endif /* __CAP_H__ */

