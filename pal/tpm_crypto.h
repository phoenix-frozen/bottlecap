#ifndef __TPM_CRYPTO_H__
#define __TPM_CRYPTO_H__

#include <stdint.h>

#include <aes.h>

#include <bottlecap/crypto.h>
#include <bottlecap/cap.h>

//utility function for {en,de}crypting a capability
int do_cap_crypto(aes_context *ctx, int mode, size_t *iv_off, uint128_t* iv, cap_t* cap);

#endif /* __TPM_CRYPTO_H__ */

