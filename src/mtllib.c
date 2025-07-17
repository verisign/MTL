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
#include <string.h>

#include "mtl.h"
#include "mtllib.h"
#include "mtl_util.h"
#include "mtllib_util.h"

/**
 * MTL Library New Key
 * @param keystr the string identifier for the desired algorithm
 * @param ctx pointer to what will be allocated as the MTL library key context
 * @param ctx_str the optional MTL context string
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_key_new(char *keystr, MTLLIB_CTX **ctx, char *mtl_ctx_str)
{
    MTLLIB_CTX *mtllib_ctx;

    if ((keystr == NULL) || (ctx == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    // Create the library context
    mtllib_ctx = calloc(1, sizeof(MTLLIB_CTX));
    if(mtllib_ctx == NULL) {
        return MTLLIB_MEMORY_ERROR;
    }

    // Find the algorithm parameters
    mtllib_ctx->algo_params = mtllib_util_get_algorithm_props(keystr);
    if (mtllib_ctx->algo_params == NULL)
    {
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }

    if (mtllib_util_setup_sig_scheme(mtllib_ctx->algo_params->library, mtllib_ctx, NULL, 0, NULL, 0, mtl_ctx_str, NULL, NULL) != MTLLIB_OK)
    {
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }

    *ctx = mtllib_ctx;
    return MTLLIB_OK;
}

/**
 * MTL Library Get Public Key
 * @param ctx pointer to the MTL library key context
 * @param pubkey pointer to the existing public key byte array (user does not free)
 * @return size_t Byte length of the public key
 */
size_t mtllib_key_get_pubkey_bytes(MTLLIB_CTX *ctx, uint8_t **pubkey)
{
    if ((ctx == NULL) || (ctx->signature == NULL) || (pubkey == NULL))
    {
        if (pubkey != NULL)
        {
            *pubkey = NULL;
        }
        return 0;
    }

    size_t public_key_length = ctx->signature->length_public_key;
    *pubkey = ctx->public_key;
    return public_key_length;
}

/**
 * MTL Library Free
 * @param ctx pointer to the MTL library key context
 * @return None
 */
void mtllib_key_free(MTLLIB_CTX *ctx)
{
    if (ctx)
    {
        free(ctx->public_key);
        ctx->public_key = NULL;
        free(ctx->secret_key);
        ctx->secret_key = NULL;
        if (ctx->signature)
        {
            OQS_SIG_free(ctx->signature);
            ctx->signature = NULL;
        }   
        if (ctx->mtl)
        {
            free(ctx->mtl->sig_params);
            ctx->mtl->sig_params = NULL;
            mtl_free(ctx->mtl);
            ctx->mtl = NULL;
        }
        free(ctx);
    }
}


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
                                            uint8_t *pubkey, size_t pubkey_len,
                                            uint8_t *sid_ptr, size_t sid_len)
{
    MTLLIB_CTX *mtllib_ctx = NULL;
    SERIESID sid;
    SEED seed;

    if ((keystr == NULL) || (ctx == NULL) || (pubkey == NULL) || (sid_ptr == NULL) ||
        (pubkey_len == 0) || (sid_len == 0) || (pubkey_len > 65535) || (sid_len > 1024))
    {
        fprintf(stderr, "ERROR: Bad public key parameters\n");
        return MTLLIB_NULL_PARAMS;
    }

    *ctx = NULL;
    mtllib_ctx = calloc(1, sizeof(MTLLIB_CTX));
    if (mtllib_ctx == NULL)
    {
        fprintf(stderr, "ERROR: Alloc Error\n");
        return MTLLIB_MEMORY_ERROR;
    }

    // Find the algorithm parameters
    mtllib_ctx->algo_params = mtllib_util_get_algorithm_props((char *)keystr);
    if (mtllib_ctx->algo_params == NULL)
    {
        fprintf(stderr, "ERROR: Unknown Algorithm\n");
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }
    // SID
    sid.length = sid_len;
    memcpy(&sid.id, sid_ptr, sid.length);

    seed.length = mtllib_ctx->algo_params->sec_param;
    // Note SLH-DSA PK = (PK.seed, PK.root)
    memcpy(&seed.seed, pubkey, seed.length);

    if (mtllib_util_setup_sig_scheme(mtllib_ctx->algo_params->library,
                                     mtllib_ctx, NULL, 0,
                                     pubkey, pubkey_len,
                                     ctx_str, &seed, &sid) != MTLLIB_OK)
    {
        fprintf(stderr, "ERROR: Key Setup Failed\n");
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }

    *ctx = mtllib_ctx;
    return MTLLIB_OK;
}

/**
 * MTL Library Key from Buffer
 * @param buffer     input buffer holding the key
 * @param buffer_len the length of the input buffer
 * @param ctx        MTL context created from the buffer
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_key_from_buffer(uint8_t *buffer, size_t buffer_len, MTLLIB_CTX **ctx)
{
    MTLLIB_CTX *mtllib_ctx = NULL;
    uint16_t flags = 0;
    uint8_t *buffer_ptr = NULL;
    uint8_t *record = NULL;
    char *mtl_ctx_str = NULL;
    size_t sk_len = 0;
    size_t pk_len = 0;
    size_t curr_len = buffer_len;
    size_t bytes_len = 0;
    SERIESID sid;
    SEED seed;
    uint32_t leaf_count;
    uint16_t hash_size;
    size_t index;
    uint8_t *pk;
    uint8_t *sk;

    if ((buffer == NULL) || (ctx == NULL) || (buffer_len == 0))
    {
        return MTLLIB_NULL_PARAMS;
    }

    *ctx = NULL;
    buffer_ptr = buffer;

    mtllib_ctx = calloc(1, sizeof(MTLLIB_CTX));
    if (mtllib_ctx == NULL)
    {
        return MTLLIB_MEMORY_ERROR;
    }

    // Read Algorithm String
    if (mtllib_util_buffer_read_bytes(&buffer_ptr, &curr_len, &record, &bytes_len, 1024, 1) != MTLLIB_OK)
    {
        free(mtllib_ctx);
        return MTLLIB_BAD_VALUE;
    }

    // Find the algorithm parameters
    mtllib_ctx->algo_params = mtllib_util_get_algorithm_props((char *)record);
    free(record);
    if (mtllib_ctx->algo_params == NULL)
    {
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }

    // Read Secret Key
    if (mtllib_util_buffer_read_bytes(&buffer_ptr, &curr_len, &record, &bytes_len, 256, 0) != MTLLIB_OK)
    {
        free(mtllib_ctx);
        return MTLLIB_BAD_VALUE;
    }
    sk_len = bytes_len - 4;
    sk = record;

    // Read Public Key
    if (mtllib_util_buffer_read_bytes(&buffer_ptr, &curr_len, &record, &bytes_len, 128, 1) != MTLLIB_OK)
    {
        free(mtllib_ctx);
        return MTLLIB_BAD_VALUE;
    }
    pk_len = bytes_len - 4;
    pk = record;

    // Get/Check Randomizer Setting
    BUFFER_VERIFY_LENGTH(curr_len, 2, mtllib_ctx);
    bytes_to_uint16(buffer_ptr, &flags);
    buffer_ptr += 2;
    curr_len -= 2;

    if (((flags & RANDOMIZER_FLAG) != mtllib_ctx->algo_params->randomize))
    {
        free(mtllib_ctx);
        return MTLLIB_BAD_VALUE;
    }

    // Get Context String
    if (mtllib_util_buffer_read_bytes(&buffer_ptr, &curr_len, (uint8_t **)&mtl_ctx_str, &bytes_len, 256, 0) != MTLLIB_OK)
    {
        free(mtllib_ctx);
        return MTLLIB_BAD_VALUE;
    }
    if (bytes_len <= 4)
    {
        mtl_ctx_str = NULL;
    }

    // Get MTL information
    // SID
    if (mtllib_util_buffer_read_bytes(&buffer_ptr, &curr_len, &record, &bytes_len, 64, 0) != MTLLIB_OK)
    {
        free(mtllib_ctx);
        return MTLLIB_BAD_VALUE;
    }
    sid.length = bytes_len - 4;
    memcpy(&sid.id, record, sid.length);
    free(record);

    seed.length = mtllib_ctx->algo_params->sec_param;
    // Note SLH-DSA PK = (PK.seed, PK.root)
    memcpy(&seed.seed, pk, seed.length);
    if (mtllib_util_setup_sig_scheme(mtllib_ctx->algo_params->library,
                                     mtllib_ctx, sk, sk_len,
                                     pk, pk_len,
                                     mtl_ctx_str, &seed, &sid) != MTLLIB_OK)
    {
        free(sk);
        free(pk);
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }
    free(sk);
    free(pk);

    // Leaf Count
    BUFFER_VERIFY_LENGTH(curr_len, 4, mtllib_ctx);
    bytes_to_uint32(buffer_ptr, &leaf_count);
    buffer_ptr += 4;
    curr_len -= 4;

    // Hash size
    BUFFER_VERIFY_LENGTH(curr_len, 2, mtllib_ctx);
    bytes_to_uint16(buffer_ptr, &hash_size);
    buffer_ptr += 2;
    curr_len -= 2;
    if ((hash_size > 64) || (hash_size < 1))
    {
        free(mtllib_ctx);
        return MTLLIB_BAD_VALUE;
    }

    // Leaf Nodes
    for (index = 0; index < leaf_count; index++)
    {
        BUFFER_VERIFY_LENGTH(curr_len, hash_size, mtllib_ctx);
        mtl_node_set_insert(&mtllib_ctx->mtl->nodes, index, index, buffer_ptr);
        buffer_ptr += hash_size;
        curr_len -= hash_size;

        // Compute the internal nodes
        if (mtl_node_set_update_parents(mtllib_ctx->mtl, index) != MTL_OK)
        {
            free(mtllib_ctx);
            return MTLLIB_BAD_VALUE;
        }
    }

    // Randomizer Nodes
    for (index = 0; index < leaf_count; index++)
    {
        BUFFER_VERIFY_LENGTH(curr_len, hash_size, mtllib_ctx);
        mtl_node_set_insert_randomizer(&mtllib_ctx->mtl->nodes, index, buffer_ptr);
        buffer_ptr += hash_size;
        curr_len -= hash_size;
    }

    *ctx = mtllib_ctx;
    return MTLLIB_OK;
}

/**
 * MTL Library Key to Buffer
 * @param ctx    MTL context to write to the buffer
 * @param buffer output buffer holding the key bytes
 * @return size_t size of the key buffer
 */
size_t mtllib_key_to_buffer(MTLLIB_CTX *ctx, uint8_t **buffer)
{
    uint8_t *buffer_ptr = NULL;
    uint8_t *key_buffer = NULL;
    size_t param_len = 0;
    size_t mtl_hashes = 0;
    size_t hash_size = 0;
    size_t index = 0;
    uint8_t *hash_ptr = NULL;
    size_t buffer_len = 0;
    uint16_t flags = 0;

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL) || (buffer == NULL))
    {
        // Also check ctx->mtl sid and nodes for null
        return 0;
    }
    *buffer = NULL;
    param_len = 2400;
    mtl_hashes = ctx->mtl->nodes.leaf_count;
    hash_size = ctx->mtl->nodes.hash_size;
    param_len += mtl_hashes * hash_size; // Allocate bytes for each leaf node
    if (ctx->algo_params->randomize)
    {
        param_len += mtl_hashes * hash_size; // Allocate bytes for each leaf node randomizer
    }

    key_buffer = calloc(1, param_len);
    if (key_buffer == NULL)
    {
        return MTLLIB_BAD_VALUE;
    }
    buffer_len = param_len;
    buffer_ptr = key_buffer;

    // Add Algorithm String
    if (mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, (uint8_t *)ctx->algo_params->name, strlen(ctx->algo_params->name), 1024, 1) != MTLLIB_OK)
    {
        free(key_buffer);
        return MTLLIB_BAD_VALUE;
    }

    // Add Secret Key Bytes
    if (mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, ctx->secret_key, ctx->secret_key_len, 256, 0) != MTLLIB_OK)
    {
        free(key_buffer);
        return MTLLIB_BAD_VALUE;
    }

    // Add Public Key Bytes
    if (mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, ctx->public_key, ctx->public_key_len, 128, 1) != MTLLIB_OK)
    {
        free(key_buffer);
        return MTLLIB_BAD_VALUE;
    }

    // Add the randomizer setting
    if (ctx->algo_params->randomize)
    {
        flags = flags | RANDOMIZER_FLAG;
    }
    BUFFER_VERIFY_LENGTH(buffer_len, 2, NULL);
    uint16_to_bytes(buffer_ptr, flags);
    buffer_ptr += 2;
    buffer_len -= 2;

    // Add Context String
    if (ctx->mtl->ctx_str != NULL)
    {
        if (mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, ctx->mtl->ctx_str, strlen(ctx->mtl->ctx_str), 256, 0) != MTLLIB_OK)
        {
            free(key_buffer);
            return MTLLIB_BAD_VALUE;
        }
    }
    else
    {
        uint32_to_bytes(buffer_ptr, 0);
        buffer_ptr += 4;
        buffer_len -= 4;
    }

    // Write the MTL mode data (SID, Leaf Count, Hashes, Randomizers)
    // Add SID Bytes
    if (mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, ctx->mtl->sid.id, ctx->mtl->sid.length, 256, 0) != MTLLIB_OK)
    {
        free(key_buffer);
        return MTLLIB_BAD_VALUE;
    }

    // Add leaf Count
    BUFFER_VERIFY_LENGTH(buffer_len, 4, NULL);
    uint32_to_bytes(buffer_ptr, mtl_hashes);
    buffer_ptr += 4;
    buffer_len -= 4;

    // Add hash size
    BUFFER_VERIFY_LENGTH(buffer_len, 2, NULL);
    uint16_to_bytes(buffer_ptr, hash_size);
    buffer_ptr += 2;
    buffer_len -= 2;

    // Add each leaf in the tree
    for (index = 0; index < mtl_hashes; index++)
    {
        if (mtl_node_set_fetch(&ctx->mtl->nodes, index, index, &hash_ptr) == MTL_OK)
        {
            BUFFER_VERIFY_LENGTH(buffer_len, hash_size, NULL);
            memcpy(buffer_ptr, hash_ptr, hash_size);
            buffer_ptr += hash_size;
            buffer_len -= hash_size;
            free(hash_ptr);
        }
        else
        {
            free(key_buffer);
            return 0;
        }
    }

    // Add each randomizer in the tree
    if (ctx->algo_params->randomize)
    {
        for (index = 0; index < mtl_hashes; index++)
        {
            if (mtl_node_set_get_randomizer(&ctx->mtl->nodes, index, &hash_ptr) == MTL_OK)
            {
                BUFFER_VERIFY_LENGTH(buffer_len, hash_size, NULL);
                memcpy(buffer_ptr, hash_ptr, hash_size);
                buffer_ptr += hash_size;
                buffer_len -= hash_size;
                free(hash_ptr);
            }
            else
            {
                free(key_buffer);
                return 0;
            }
        }
    }

    *buffer = key_buffer;
    return buffer_ptr - key_buffer;
}

/**
 * MTL Library append a message to the node set
 * @param ctx      MTL context to use
 * @param msg      input message buffer
 * @param msg_len  length of the input message buffer
 * @param mtl_node handle for the appended message
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_append(MTLLIB_CTX *ctx, uint8_t *msg, size_t msg_len, MTL_HANDLE **mtl_node)
{
    uint32_t leaf_index = 0;
    MTL_HANDLE *handle = NULL;

    if ((ctx == NULL) || (msg == NULL) || (mtl_node == NULL))
    {
        LOG_ERROR("NULL input parameters");
        if (mtl_node != NULL)
        {
            *mtl_node = NULL;
        }
        return MTLLIB_NULL_PARAMS;
    }
    *mtl_node = NULL;

    if (mtl_hash_and_append(ctx->mtl, msg, msg_len, &leaf_index) != MTL_OK)
    {
        LOG_ERROR("Unable to add message to node set");
        return MTLLIB_SIGN_FAIL;
    }

    handle = calloc(1, sizeof(MTL_HANDLE));
    handle->leaf_index = leaf_index;
    handle->sid_len = ctx->mtl->sid.length;
    memcpy(handle->sid, ctx->mtl->sid.id, handle->sid_len);

    *mtl_node = handle;
    return MTLLIB_OK;
}

/**
 * MTL Library free a MTL handle
 * @param handle     handle to free
 * @return none
 */
void mtllib_sign_free_handle(MTL_HANDLE **mtl_node)
{
    if ((mtl_node != NULL) && (*mtl_node != NULL))
    {
        free(*mtl_node);
        *mtl_node = NULL;
    }
}

/**
 * MTL Library get the condensed signature for a handle
 * @param ctx     input buffer holding the key
 * @param handle  handle to the signed message
 * @param sig     pointer to allocate and fill with the signature bytes
 * @param sig_len pointer to set to the signature bytes length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_condensed_sig(MTLLIB_CTX *ctx, MTL_HANDLE *handle, uint8_t **sig, size_t *sig_len)
{
    RANDOMIZER *mtl_rand = NULL;
    AUTHPATH *auth = NULL;

    if (sig_len != NULL)
    {
        *sig_len = 0;
    }

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL) ||
        (handle == NULL) || (sig == NULL) || (sig_len == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    if (mtl_randomizer_and_authpath(ctx->mtl, handle->leaf_index, &mtl_rand, &auth) != MTL_OK)
    {
        return MTLLIB_SIGN_FAIL;
    }

    *sig_len = mtl_auth_path_to_buffer(mtl_rand, auth, ctx->algo_params->sec_param, sig);
    mtl_authpath_free(auth);
    mtl_randomizer_free(mtl_rand);

    return MTLLIB_OK;
}

/**
 * MTL Library get the signed ladder
 * @param ctx        input buffer holding the key
 * @param handle     handle to the signed message
 * @param ladder     pointer to allocate and fill with the signed ladder bytes
 * @param ladder_len pointer to set to the signed ladder bytes length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_signed_ladder(MTLLIB_CTX *ctx, uint8_t **ladder, size_t *ladder_len)
{
    LADDER *ladder_ptr = NULL;
    uint8_t *ladder_sig = NULL;
    size_t ladder_sig_len;
    uint8_t *ladder_buffer = NULL;
    uint32_t ladder_buffer_len = 0;
    uint8_t *underlying_buffer = NULL;
    uint32_t underlying_buffer_len = 0;

    if (ladder_len != NULL)
    {
        *ladder_len = 0;
    }

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL) ||
        (ladder == NULL) || (ladder_len == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    // Get the latest ladder
    ladder_ptr = mtl_ladder(ctx->mtl);
    ladder_buffer_len = mtl_ladder_to_buffer(ladder_ptr, ctx->mtl->nodes.hash_size, &ladder_buffer);

    // Get the scheme separated ladder buffer
    underlying_buffer_len = mtl_get_scheme_separated_buffer(ctx->mtl, ladder_ptr,
                                                            ctx->mtl->nodes.hash_size,
                                                            &underlying_buffer, ctx->algo_params->oid, ctx->algo_params->oid_len);

    // Ladder signatures is signature length + 4 bytes for length value
    ladder_sig = malloc(ctx->signature->length_signature + 4 + ladder_buffer_len);
    memcpy(ladder_sig, ladder_buffer, ladder_buffer_len);
    free(ladder_buffer);
    mtl_ladder_free(ladder_ptr);
    uint32_to_bytes(&ladder_sig[ladder_buffer_len], ctx->signature->length_signature);
    if (OQS_SIG_sign(ctx->signature, ladder_sig + 4 + ladder_buffer_len, &ladder_sig_len, underlying_buffer,
                     underlying_buffer_len, ctx->secret_key) == OQS_ERROR)
    {
        *ladder = NULL;
        *ladder_len = 0;
        free(ladder_sig);
        free(underlying_buffer);
        return MTLLIB_SIGN_FAIL;
    }
    free(underlying_buffer);

    *ladder = ladder_sig;
    *ladder_len = ctx->signature->length_signature + 4 + ladder_buffer_len;

    return MTLLIB_OK;
}

/**
 * MTL Library get the full signature for a handle
 * @param ctx     input buffer holding the key
 * @param handle  handle to the signed message
 * @param sig     pointer to fill with the signature bytes
 * @param sig_len pointer to set to the signature bytes length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_full_sig(MTLLIB_CTX *ctx, MTL_HANDLE *handle, uint8_t **sig, size_t *sig_len)
{
    uint8_t *condensed = NULL;
    size_t condensed_len = 0;
    uint8_t *ladder = NULL;
    size_t ladder_len = 0;
    uint8_t *full = NULL;

    if (sig_len != NULL)
    {
        *sig_len = 0;
    }

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL) ||
        (handle == NULL) || (sig == NULL) || (sig_len == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    if (mtllib_sign_get_condensed_sig(ctx, handle, &condensed, &condensed_len) != MTLLIB_OK)
    {
        return MTLLIB_SIGN_FAIL;
    }

    if (mtllib_sign_get_signed_ladder(ctx, &ladder, &ladder_len) != MTLLIB_OK)
    {
        free(condensed);
        return MTLLIB_SIGN_FAIL;
    }

    full = calloc(1, condensed_len + ladder_len);
    if (full == NULL)
    {
        free(condensed);
        free(ladder);
        free(full);
        return MTLLIB_SIGN_FAIL;
    }
    memcpy(full, condensed, condensed_len);
    memcpy(full + condensed_len, ladder, ladder_len);
    *sig_len = condensed_len + ladder_len;

    free(condensed);
    free(ladder);
    *sig = full;

    return MTLLIB_OK;
}

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
MTLLIB_STATUS mtllib_verify(MTLLIB_CTX *ctx, uint8_t *msg, size_t msg_len, uint8_t *sig, size_t sig_len, uint8_t *ladder_buf, size_t ladder_buf_len, size_t* condensed_len)
{
    AUTHPATH *auth_path = NULL;
    RANDOMIZER *mtl_rand = NULL;
    uint32_t condensed_size = 0;
    size_t full_sig_len = 0;
    RUNG *rung = NULL;
    LADDER *ladder = NULL;
    size_t ladder_len = 0;

    if ((ctx == NULL) || (msg == NULL) || (sig == NULL) || (msg_len == 0) || (sig_len == 0)) {
        return MTLLIB_NULL_PARAMS;
    }

    if(condensed_len != NULL) {
        *condensed_len = 0;
    }

    // Fetch the signature parameters
    condensed_size = mtl_auth_path_from_buffer((char *)sig, sig_len, ctx->algo_params->sec_param, ctx->algo_params->sid_len, &mtl_rand, &auth_path);
    if (condensed_size == 0)
    {
        mtl_randomizer_free(mtl_rand);
        mtl_authpath_free(auth_path);
        LOG_ERROR("ERROR: Authentication Path is Invalid\n");
        exit(3);
    }
    if(condensed_len != NULL) {
        *condensed_len = condensed_size;
    }

    // Try to verify with the provided ladder (for performance less crypto to verify)
    if ((ladder_buf != NULL) && (ladder_buf_len > 0))
    {
        // Get the ladder from the buffer
        ladder_len = mtl_ladder_from_buffer((char *)ladder_buf, ladder_buf_len, ctx->algo_params->sec_param, ctx->algo_params->sid_len, &ladder);
        if (ladder_len == 0)
        {
            LOG_ERROR("Unable to read ladder from buffer");
            mtl_ladder_free(ladder);
            mtl_randomizer_free(mtl_rand);
            mtl_authpath_free(auth_path);
            return MTLLIB_BOGUS_CRYPTO;
        }

        // Verify the signature
        rung = mtl_rung(auth_path, ladder);
        if (rung == NULL)
        {
            LOG_ERROR("NULL mtl_rung");
            mtl_ladder_free(ladder);
            mtl_randomizer_free(mtl_rand);
            mtl_authpath_free(auth_path);
            return MTLLIB_NULL_PARAMS;
        }
        if (mtl_hash_and_verify(ctx->mtl, msg, msg_len, mtl_rand, auth_path, rung) == MTL_OK)
        {
            mtl_ladder_free(ladder);
            mtl_randomizer_free(mtl_rand);
            mtl_authpath_free(auth_path);
            return MTLLIB_OK;
        }
        else
        {
            LOG_ERROR("MTL authentication failed validation\n");
        }
        mtl_ladder_free(ladder);
    }

    // If provided ladder didn't work see if we have a full signature we can use
    if (condensed_size < sig_len)
    {
        // Check if we have a full signature (e.g. signed ladder)
        full_sig_len = sig_len - condensed_size;
        if (full_sig_len > 100)
        {
            if (mtllib_verify_signed_ladder(ctx, sig + condensed_size, full_sig_len) == MTLLIB_OK)
            {
                // Get the ladder from the buffer
                ladder_len = mtl_ladder_from_buffer((char *)sig + condensed_size, full_sig_len, ctx->algo_params->sec_param, ctx->algo_params->sid_len, &ladder);
                if (ladder_len == 0)
                {
                    LOG_ERROR("Unable to read ladder from buffer");
                    mtl_ladder_free(ladder);
                    mtl_randomizer_free(mtl_rand);
                    mtl_authpath_free(auth_path);
                    return MTLLIB_BOGUS_CRYPTO;
                }

                // Verify the signature
                rung = mtl_rung(auth_path, ladder);
                if (rung == NULL)
                {
                    LOG_ERROR("NULL mtl_rung");
                    mtl_ladder_free(ladder);
                    mtl_randomizer_free(mtl_rand);
                    mtl_authpath_free(auth_path);
                    return MTLLIB_NULL_PARAMS;
                }
                if (mtl_hash_and_verify(ctx->mtl, msg, msg_len, mtl_rand, auth_path, rung) == MTL_OK)
                {
                    mtl_ladder_free(ladder);
                    mtl_randomizer_free(mtl_rand);
                    mtl_authpath_free(auth_path);
                    return MTLLIB_OK;
                }
                else
                {
                    LOG_ERROR("MTL authentication failed validation\n");
                }
                mtl_ladder_free(ladder);
            }
            else
            {
                LOG_ERROR("Unable to validate the provided ladder\n");
            }
        }
        else
        {
            LOG_ERROR("There is no ladder to use for validating this signature.  Please fetch a valid ladder.\n");
        }
    } else {
        return MTLLIB_NO_LADDER;
    }

    // Free the data that was created above
    mtl_randomizer_free(mtl_rand);
    mtl_authpath_free(auth_path);

    return MTLLIB_OK;
}

/**
 * MTL Library verify a signed ladder
 * @param ctx        input buffer holding the key
 * @param buffer     pointer to the signed ladder bytes
 * @param buffer_len length of the signed ladder in bytes
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_verify_signed_ladder(MTLLIB_CTX *ctx, uint8_t *buffer, size_t buffer_len)
{
    LADDER *ladder = NULL;
    size_t ladder_len = 0;

    if ((ctx == NULL) || (buffer == NULL))
    {
        LOG_ERROR("Unable to read ladder from buffer");
        return MTLLIB_NULL_PARAMS;
    }

    // Get the ladder from the buffer
    ladder_len = mtl_ladder_from_buffer((char *)buffer, buffer_len, ctx->algo_params->sec_param, ctx->algo_params->sid_len, &ladder);
    if (ladder_len == 0)
    {
        LOG_ERROR("Unable to read ladder from buffer");
        return MTLLIB_BOGUS_CRYPTO;
    }
    mtl_ladder_free(ladder);

    if (ladder_len + ctx->signature->length_signature + 4 > buffer_len)
    {
        LOG_ERROR("Unable to read ladder from buffer");
        return MTLLIB_INDETERMINATE;
    }

    // Verify the signature on the ladder...
    if (OQS_SIG_verify(ctx->signature, buffer, ladder_len,
                       buffer + 4 + ladder_len, ctx->signature->length_signature, ctx->public_key) == OQS_SUCCESS)
    {
        return MTLLIB_BOGUS_CRYPTO;
    }

    return MTLLIB_OK;
}