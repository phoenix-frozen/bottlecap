#include <bottlecap/errors.h>

#include "tpm_crypto.h"
#include "misc.h"

int do_cap_crypto(
		aes_context *ctx, int mode,
		size_t *iv_off,
		uint128_t* iv,
		cap_t* cap) {

	cap_t temp;
	memcpy(&temp, cap, sizeof(temp));

	DO_OR_BAIL(0, aes_crypt_cfb128, ctx, mode, sizeof(cap_t), iv_off, iv->bytes, temp.bytes, cap->bytes);

	memset(&temp, 0, sizeof(temp));

	return ESUCCESS;
}

