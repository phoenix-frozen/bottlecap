/*
 * sha1.h: Modified for Flicker.
 */

#ifndef _SHA1_H
#define _SHA1_H

#include <polarssl/sha1.h>

//some constants, for convenience
#define SHA_DIGEST_LENGTH 20
/* The SHA block size and message digest sizes, in bytes */

#define SHA_DATASIZE    64
#define SHA_DATALEN     16
#define SHA_DIGESTSIZE  20
#define SHA_DIGESTLEN    5
/* The structure for storing SHA info */

//adjust linker-related stuff
void sha1_starts( sha1_context *ctx ) __attribute__ ((section (".text.slb")));
void sha1_update( sha1_context *ctx, const unsigned char *input, size_t ilen ) __attribute__ ((section (".text.slb")));
void sha1_finish( sha1_context *ctx, unsigned char output[20] ) __attribute__ ((section (".text.slb")));
void sha1( const unsigned char *input, size_t ilen, unsigned char output[20] ) __attribute__ ((section (".text.slb")));

//TODO: ensure static functions in sha1.c are also in .text.slb

#if 0
void sha1_hmac_starts( sha1_context *ctx, const unsigned char *key, size_t keylen );
void sha1_hmac_update( sha1_context *ctx, const unsigned char *input, size_t ilen );
void sha1_hmac_finish( sha1_context *ctx, unsigned char output[20] );
void sha1_hmac_reset( sha1_context *ctx );
void sha1_hmac( const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char output[20] );
#endif


//dodgy API adaptation
#define hmac(key, msg, len, md)   sha1_hmac(key, HMAC_OUTPUT_SIZE, msg, len, md)
#define sha1_buffer(msg, len, md) sha1(msg, len, md)

#endif
