/*
    Copyright (c) 2026, VeriSign, Inc.
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
#include "mtllib_buffer.h"
#include "mtllib_status.h"

/** Context used for signing ladders 
* \todo update to real fixed customization string once MTL_OID is assigned
 */
#define MTL_SIGNING_CTX_STR_LEN 7
#define MTL_SIGNING_CTX_STR ((const uint8_t *)"OID_MTL")

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
    char *scheme_str;
} MTL_ALGORITHM_PROPS;

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
    MTL_INDEX leaf_index;
} MTL_HANDLE;

#define RANDOMIZER_FLAG 0x01

// Function Macros
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
            LOG_ERROR("Buffer error");  \
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
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_key_new(char *keystr, MTLLIB_CTX **ctx);

/**
 * MTL Library Get Public Key Length
 * @param ctx pointer to the MTL library key context
 * @return size_t Byte length of the public key
 */
size_t mtllib_pubkey_to_buffer_length(MTLLIB_CTX *ctx);

/**
 * MTL Library Get Public Key
 * @param ctx pointer to the MTL library key context
 * @param pubkey MTLLIB_BUFFER containing the existing public key byte array
 *              which has been initalized by mtllib_buffer_initialize.
 * @return size_t Byte length of the public key
 */
MTLLIB_STATUS mtllib_pubkey_to_buffer(MTLLIB_CTX *ctx, MTLLIB_BUFFER *pubkey);

/**
 * MTL Library Key Free
 * @param ctx pointer to the MTL library key context
 * @return None
 */
void mtllib_key_free(MTLLIB_CTX *ctx);


/**
 * MTL Library Get Public Key from key parameters
 * @param keystr the string identifier for the desired algorithm
 * @param pubkey MTLLIB Buffer of public key data
 * @param ctx pointer to what will be allocated as the MTL library key context
 * @param sid_ptr byte array of series id data
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 * @return None
 */
MTLLIB_STATUS mtllib_pubkey_from_buffer(char *keystr, MTLLIB_CTX **ctx, MTLLIB_BUFFER *pubkey, uint8_t *sid_ptr);


/**
 * MTL Library Key from Buffer
 * @param buffer MTLLIB input buffer holding the key
 * @param ctx MTL context created from the buffer
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_key_from_buffer(MTLLIB_BUFFER *buffer, MTLLIB_CTX **ctx);


/**
 * MTL Library Key to Buffer
 * @param ctx    MTL context to write to the buffer
 * @return size_t size of the key buffer
 */
size_t mtllib_key_to_buffer_length(MTLLIB_CTX *ctx);

/**
 * MTL Library Key to Buffer
 * @param ctx    MTL context to write to the buffer
 * @param buffer MTLLIB output buffer holding the key bytes
 * @return size_t size of the key buffer
 */
MTLLIB_STATUS mtllib_key_to_buffer(MTLLIB_CTX *ctx, MTLLIB_BUFFER *buffer);

/**
 * MTL Library append a message to the node set with default empty ctx_str
 * @param ctx      MTL context to use
 * @param msg      input message buffer
 * @param mtl_node handle for the appended message
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_append(MTLLIB_CTX *ctx, 
                                    MTLLIB_BUFFER *msg,
                                    MTL_HANDLE **mtl_node);

/**
 * MTL Library append a message to the node set
 * @param ctx      MTL context to use
 * @param msg      input message buffer
 * @param ctx_str  input context string buffer
 * @param mtl_node handle for the appended message
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_append_with_ctx_str(MTLLIB_CTX *ctx, 
                                    MTLLIB_BUFFER *msg, MTLLIB_BUFFER *ctx_str, 
                                    MTL_HANDLE **mtl_node);

/**
 * MTL Library free a MTL handle
 * @param handle     handle to free
 * @return none
 */
void mtllib_sign_free_handle(MTL_HANDLE **mtl_node);

/**
 * MTL Library Get Public Key Length
 * @param ctx pointer to the MTL library key context
 * @return size_t Byte length of the public key
 */
size_t mtllib_sign_get_condensed_sig_length(MTLLIB_CTX *ctx, MTL_HANDLE *handle);

/**
 * MTL Library get the condensed signature for a handle
 * @param ctx     pointer to the MTL library key context
 * @param handle  handle to the signed message
 * @param sig     pointer to fill with the signature bytes
 * @param sig_len pointer to set to the signature bytes length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_condensed_sig(MTLLIB_CTX *ctx, MTL_HANDLE *handle, MTLLIB_BUFFER *sig);

/**
 * MTL Library get the signed ladder length
 * @param ctx pointer to the MTL library key context
 * @return Length of a signed ladder for ctx, or 0 if unsuccessful
 */
size_t mtllib_sign_get_signed_ladder_length(MTLLIB_CTX *ctx);

/**
 * MTL Library get the signed ladder
 * @param ctx        pointer to the MTL library key context
 * @param ladder     pointer to allocate and fill with the signed ladder bytes
 * @param ladder_len pointer to set to the signed ladder bytes length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_signed_ladder(MTLLIB_CTX *ctx, MTLLIB_BUFFER *ladder);

/**
 * MTL Library get the length of a full signature for a handle
 * @param ctx     pointer to the MTL library key context
 * @param handle  handle to the signed message
 * @return length of the full signature, or 0 on error
 */
size_t mtllib_sign_get_full_sig_length(MTLLIB_CTX *ctx, MTL_HANDLE *handle);

/**
 * MTL Library get the full signature for a handle
 * @param ctx     pointer to the MTL library key context
 * @param handle  handle to the signed message
 * @param sig     pointer to fill with the signature bytes
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_full_sig(MTLLIB_CTX *ctx, MTL_HANDLE *handle, MTLLIB_BUFFER *sig);

/**
 * MTL Library verify a signature (full or condensed) with default empty context
 * @param ctx           pointer to the MTL library key context
 * @param msg           msg to authenticate
 * @param sig           pointer to the signature bytes
 * @param ladder        optional pointer to pre-verified ladder (for condensed signatures)
 * @param condensed_len optional pointer that will be filled in to the condensed length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_verify(MTLLIB_CTX *ctx, 
                            MTLLIB_BUFFER *msg,
                            MTLLIB_BUFFER *sig,
                            MTLLIB_BUFFER *ladder_buf,
                            size_t* condensed_len);

/**
 * MTL Library verify a signature (full or condensed)
 * @param ctx           pointer to the MTL library key context
 * @param msg           msg to authenticate
 * @param ctx_str       context string with which to authenticate msg
 * @param sig           pointer to the signature bytes
 * @param ladder        optional pointer to pre-verified ladder (for condensed signatures)
 * @param condensed_len optional pointer that will be filled in to the condensed length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_verify_with_ctx_str(MTLLIB_CTX *ctx, 
                            MTLLIB_BUFFER *msg,
                            MTLLIB_BUFFER *ctx_str,
                            MTLLIB_BUFFER *sig,
                            MTLLIB_BUFFER *ladder_buf,
                            size_t* condensed_len);

/**
 * MTL Library verify a signed ladder
 * @param ctx        pointer to the MTL library key context
 * @param buffer     MTLLIB buffer with the signed ladder bytes
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_verify_signed_ladder(MTLLIB_CTX *ctx, MTLLIB_BUFFER *buffer);

/**
 * MTL Library get the current size needed for a signed ladder
 * @param ctx     The initalized MTLLIB context 
 * @return 0 for error or max size of the buffer on success
 */
size_t mtllib_sig_get_signed_ladder_size(MTLLIB_CTX *ctx);

/**
 * MTL Library get the size of the hash based on the signature scheme string
 * @param keystr     key string represnting the signature algorithm
 * @return hash size in bytes, or 0 if not a valid key string
 */
uint16_t mtllib_sig_buffer_get_hash_size(char* keystr);

/**
 * MTL Library extract the sid from a signature buffer
 * @param buffer     pointer to the signed ladder bytes
 * @param buffer_len length of the signed ladder in bytes
 * @param hash_size  size of the hash for the specific algorithm
 * @param sid        pre-allocated SERIESID structure for the SID values
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sig_buffer_get_sid(MTLLIB_BUFFER *buffer, uint16_t hash_size, SERIESID* sid);

/**
 * MTL Library extract the leaf index from a signature buffer
 * @param buffer     pointer to the signed ladder bytes
 * @param buffer_len length of the signed ladder in bytes
 * @param hash_size  size of the hash for the specific algorithm
 * @param leaf_index pre-allocated leaf index for the value
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sig_buffer_get_leaf_index(MTLLIB_BUFFER *buffer, uint16_t hash_size, MTL_INDEX* leaf_index);

/**
 * MTL Library get the length of the condensed signature from a signature buffer
 * @param buffer     pointer to the signed ladder bytes
 * @param buffer_len length of the signed ladder in bytes
 * @param hash_size  size of the hash for the specific algorithm
 * @return length in bytes of the condensed signature
 */
size_t mtllib_sig_buffer_condensed_sig_len(MTLLIB_BUFFER *buffer, uint16_t hash_size);
#endif