// Minimal shim so libmikey's p()/prf() compile standalone. Everything here is
// a faithful stand-in for the real libmikey/libmcrypto definitions:
//   byte_t              -> libmutil/Typedefs.h
//   SHA_DIGEST_SIZE 20  -> libmikey/keyagreement/KeyAgreement.cxx:45
//   PRF_KEY_CHUNK_LENGTH 32 -> libmikey/keyagreement/KeyAgreement.cxx:43
//   hmac_sha1           -> libmcrypto/source/openssl/hmac.cxx:30 (a bare HMAC call)
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

typedef unsigned char byte_t;
#define SHA_DIGEST_SIZE       20
#define PRF_KEY_CHUNK_LENGTH  32

static void hmac_sha1( const unsigned char * key, unsigned int key_length,
                       const unsigned char * data, unsigned int data_length,
                       unsigned char * mac, unsigned int * mac_length ){
        HMAC( EVP_sha1(), key, key_length, data, data_length, mac, mac_length );
}
