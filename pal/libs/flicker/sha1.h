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

//dodgy API adaptation
#define hmac(key, msg, len, md)   sha1_hmac(key, HMAC_OUTPUT_SIZE, msg, len, md)
#define sha1_buffer(msg, len, md) sha1(msg, len, md)

#endif
