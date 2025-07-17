/*
    Copyright (c) 2025, VeriSign, Inc.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted (subject to the limitations in the disclaimer
    below) provided that the following conditions are met:

        * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.

        * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

        * Neither the name of the copyright holder nor the names of its
        contributors may be used to endorse or promote products derived from this
        software without specific prior written permission.

    NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
    THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
    CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
    IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/
/**
 *  \file mtllib.h
 *  \brief Primary MTL implemenation functions and APIs.
 *  The general implementation of the MTL Mode functions and APIs.
 */
#ifndef __MTL_LIB_H__
#define __MTL_LIB_H__

#include <stddef.h>
#include <stdint.h>
#include <oqs/sig.h>
#include "mtl.h"

typedef enum MTL_HASH_ALGORITHM
{
    HASH_NONE = 0,
    HASH_SHAKE = 1,
    HASH_SHA2 = 2,
} MTL_HASH_ALGORITHM;

typedef enum MTL_RANDOMIZER
{
    RANDOMIZER_PRF = 0,
    RANDOMIZER_SAMPLED  = 1,
} MTL_RANDOMIZER;

typedef enum MTL_CRYPTO_LIBRARY
{
    NONE = 0,
    LIBOQS = 1,
    OPENSSL = 2,
} MTL_CRYPTO_LIBRARY;

typedef struct MTL_ALGORITHM_PROPS
{
    char *name;
    uint16_t sec_param;
    char options;
    MTL_HASH_ALGORITHM hash_algo;
    MTL_RANDOMIZER randomize;
    MTL_CRYPTO_LIBRARY library;
    uint8_t sid_len;
    char *scheme_str;
    uint8_t oid_len;
    uint8_t oid[16];
} MTL_ALGORITHM_PROPS;

typedef enum MTLLIB_STATUS
{
    // Success status
    MTLLIB_OK = 0,
    // Failure where null parameters were passed to a function
    MTLLIB_NULL_PARAMS = 1,
    // Faiure where the algorithm ID, hash algorithm, or 
    //     underlying signature scheme is not recognized
    MTLLIB_BAD_ALGORITHM = 2,
    // Failure where memory is unable to be allocated or managed
    MTLLIB_MEMORY_ERROR = 3,
    // Failure where a feature is not yet supported but has a
    //     place holder for possible future use
    MTLLIB_UNSUPPORTED_FEATURE = 4,
    // Failure where a record field is invalid. Can be due to
    //     unable to read random bytes or a buffer is missing the
    //     data (e.g. authpath should have 4 - 16 byte hashes but
    //     only has 8 bytes)
    MTLLIB_BAD_VALUE = 5,
    // Failures related to the mtllib_sign operations (e.g.
    //     operations that need secret material to do the operations)
    MTLLIB_SIGN_FAIL = 6, 
    // Failures related to crypto operations that indicate the
    //     signature is not valid    
    MTLLIB_BOGUS_CRYPTO = 7,
    // Failures where no ladder can be used to verify an auth path.
    //     May need to get a new ladder or auth path
    MTLLIB_NO_LADDER = 8,
    // Failures related to crypto operations where validity cannot
    //     be determined (e.g. missing something needed to verify)
    MTLLIB_INDETERMINATE = 9,
} MTLLIB_STATUS;

typedef struct MTLLIB_CTX
{
    MTL_ALGORITHM_PROPS *algo_params;
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t *secret_key;
    size_t secret_key_len;
    OQS_SIG *signature;
    MTL_CTX *mtl;
} MTLLIB_CTX;

typedef struct MTL_HANDLE
{
    uint8_t sid[EVP_MAX_MD_SIZE];
    size_t sid_len;
    uint32_t leaf_index;
} MTL_HANDLE;

#define RANDOMIZER_FLAG 0x01

// Function Macros
#define PKSEED_INIT(ptr, value, len)  \
    {                                 \
        ptr.length = len;             \
        memcpy(ptr.seed, value, len); \
    }
#define PKROOT_INIT(ptr, value, len) \
    {                                \
        ptr.length = len;            \
        memcpy(ptr.key, value, len); \
    }
#define SKPRF_INIT(ptr, value, len)   \
    {                                 \
        ptr.length = len;             \
        memcpy(ptr.data, value, len); \
    }
#define SKPRF_CLEAR(ptr, len)     \
    {                             \
        ptr.length = len;         \
        memset(ptr.data, 0, len); \
    }

#define BUFFER_VERIFY_LENGTH(curr, size, ctx) \
    {                                         \
        if (curr < size)                      \
        {                                     \
            printf("ERROR: Buffer error\n");  \
            if (ctx != NULL)                  \
            {                                 \
                free(ctx);                    \
            };                                \
            return MTLLIB_BAD_VALUE;          \
        }                                     \
    }

// MTL Library Function Prototypes
/**
 * MTL Library New Key
 * @param keystr the string identifier for the desired algorithm
 * @param ctx pointer to what will be allocated as the MTL library key context
 * @param ctx_str the optional MTL context string
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_key_new(char *keystr, MTLLIB_CTX **ctx, char *ctx_str);

/**
 * MTL Library Get Public Key
 * @param ctx pointer to the MTL library key context
 * @param pubkey pointer to the existing public key byte array (user does not free)
 * @return size_t Byte length of the public key
 */
size_t mtllib_key_get_pubkey_bytes(MTLLIB_CTX *ctx, uint8_t **pubkey);

/**
 * MTL Library Key Free
 * @param ctx pointer to the MTL library key context
 * @return None
 */
void mtllib_key_free(MTLLIB_CTX *ctx);


/**
 * MTL Library Get Public Key from key parameters
 * @param keystr the string identifier for the desired algorithm
 * @param ctx pointer to what will be allocated as the MTL library key context
 * @param ctx_str the optional MTL context string
 * @param pubkey byte array of public key data
 * @param pubkey_len length in bytes of the public key data
 * @param sid byte array of series id data
 * @param sig_len length in bytes of the series id data
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 * @return None
 */
MTLLIB_STATUS mtllib_key_pubkey_from_params(char *keystr, MTLLIB_CTX **ctx, char *ctx_str,
                                   uint8_t *pubkey, size_t pubkey_len, uint8_t *sid_ptr, size_t sid_len);


/**
 * MTL Library Key from Buffer
 * @param buffer input buffer holding the key
 * @param buffer_len the length of the input buffer
 * @param ctx MTL context created from the buffer
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_key_from_buffer(uint8_t *buffer, size_t buffer_len, MTLLIB_CTX **ctx);

/**
 * MTL Library Key to Buffer
 * @param ctx    MTL context to write to the buffer
 * @param buffer output buffer holding the key bytes
 * @return size_t size of the key buffer
 */
size_t mtllib_key_to_buffer(MTLLIB_CTX *ctx, uint8_t **buffer);

/**
 * MTL Library append a message to the node set
 * @param ctx      MTL context to use
 * @param msg      input message buffer
 * @param msg_len  length of the input message buffer
 * @param mtl_node handle for the appended message
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_append(MTLLIB_CTX *ctx, uint8_t *msg, size_t msg_len, MTL_HANDLE **mtl_node);

/**
 * MTL Library free a MTL handle
 * @param handle     handle to free
 * @return none
 */
void mtllib_sign_free_handle(MTL_HANDLE **mtl_node);

/**
 * MTL Library get the condensed signature for a handle
 * @param ctx     input buffer holding the key
 * @param handle  handle to the signed message
 * @param sig     pointer to fill with the signature bytes
 * @param sig_len pointer to set to the signature bytes length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_condensed_sig(MTLLIB_CTX *ctx, MTL_HANDLE *handle, uint8_t **sig, size_t *sig_len);

/**
 * MTL Library get the signed ladder
 * @param ctx        input buffer holding the key
 * @param ladder     pointer to allocate and fill with the signed ladder bytes
 * @param ladder_len pointer to set to the signed ladder bytes length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_signed_ladder(MTLLIB_CTX *ctx, uint8_t **ladder, size_t *ladder_len);

/**
 * MTL Library get the full signature for a handle
 * @param ctx     input buffer holding the key
 * @param handle  handle to the signed message
 * @param sig     pointer to fill with the signature bytes
 * @param sig_len pointer to set to the signature bytes length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_full_sig(MTLLIB_CTX *ctx, MTL_HANDLE *handle, uint8_t **sig, size_t *sig_len);

/**
 * MTL Library verify a signature (full or condensed)
 * @param ctx        input buffer holding the key
 * @param sig        pointer to the signature bytes
 * @param sig_len    length of the signature in bytes
 * @param ladder     optional pointer to pre-verified ladder (for condensed signatures)
 * @param ladder_len length of the optional pre-verified ladder in bytes
 * @param condensed_len optional pointer that will be filled in to the condensed length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_verify(MTLLIB_CTX *ctx, uint8_t *msg, size_t msg_len, uint8_t *sig, size_t sig_len, uint8_t *ladder_buf, size_t ladder_buf_len, size_t* condensed_len);

/**
 * MTL Library verify a signed ladder
 * @param ctx        input buffer holding the key
 * @param buffer     pointer to the signed ladder bytes
 * @param buffer_len length of the signed ladder in bytes
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_verify_signed_ladder(MTLLIB_CTX *ctx, uint8_t *buffer, size_t buffer_len);

#endif