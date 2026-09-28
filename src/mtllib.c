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
#include <string.h>

#include "mtl.h"
#include "mtllib.h"
#include "mtl_util.h"
#include "mtllib_util.h"
#include "mtllib_buffer.h"
#include "mtl_error.h"

/**
 * MTL Library New Key
 * @param keystr the string identifier for the desired algorithm
 * @param ctx pointer to what will be allocated as the MTL library key context
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_key_new(char *keystr, MTLLIB_CTX **ctx)
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

    if (mtllib_util_setup_sig_scheme(mtllib_ctx->algo_params->library, mtllib_ctx, NULL, 0, NULL, 0, NULL, MTL_PRIVATE_KEY) != MTLLIB_OK)
    {
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }

    *ctx = mtllib_ctx;
    return MTLLIB_OK;
}

/**
 * MTL Library Get Public Key Length
 * @param ctx pointer to the MTL library key context
 * @return size_t Byte length of the public key
 */
size_t mtllib_pubkey_to_buffer_length(MTLLIB_CTX *ctx)
{
    if ((ctx == NULL) || (ctx->signature == NULL))
    {
        return 0;
    }

    return ctx->signature->length_public_key;
}

/**
 * MTL Library Get Public Key
 * @param ctx pointer to the MTL library key context
 * @param pubkey MTLLIB_BUFFER containing the existing public key byte array
 *              which has been initalized by mtllib_buffer_initialize.
 * @return size_t Byte length of the public key
 */
MTLLIB_STATUS mtllib_pubkey_to_buffer(MTLLIB_CTX *ctx, MTLLIB_BUFFER *pubkey)
{
    if ((ctx == NULL) || (ctx->signature == NULL) || (pubkey == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    size_t public_key_length = ctx->signature->length_public_key;
    if((mtllib_buffer_size(pubkey) < public_key_length) || (mtllib_buffer_in_use(pubkey) != 0)) {
        return MTLLIB_BUFFER_ISSUE;
    }

    mtllib_buffer_append(pubkey, ctx->public_key, public_key_length);
    return MTLLIB_OK;
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
            mtl_free(ctx->mtl);
            ctx->mtl = NULL;
        }
        free(ctx);
    }
}


/**
 * MTL Library Get Public Key from key parameters
 * @param keystr the string identifier for the desired algorithm
 * @param pubkey MTLLIB Buffer of public key data
 * @param ctx pointer to what will be allocated as the MTL library key context
 * @param sid_ptr byte array of series id data
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 * @return None
 */
MTLLIB_STATUS mtllib_pubkey_from_buffer(char *keystr, MTLLIB_CTX **ctx, MTLLIB_BUFFER *pubkey, uint8_t *sid_ptr)
{
    MTLLIB_CTX *mtllib_ctx = NULL;
    SERIESID sid;

    if ((keystr == NULL) || (ctx == NULL) || (pubkey == NULL) || (sid_ptr == NULL) ||
        (mtllib_buffer_data_ptr(pubkey) == NULL) ||
        (mtllib_buffer_in_use(pubkey) == 0) ||
        (mtllib_buffer_in_use(pubkey) > 0xffffffff))
    {
        LOG_ERROR("Bad public key parameters");
        return MTLLIB_NULL_PARAMS;
    }

    *ctx = NULL;
    mtllib_ctx = calloc(1, sizeof(MTLLIB_CTX));
    if (mtllib_ctx == NULL)
    {
        LOG_ERROR("Alloc Error");
        return MTLLIB_MEMORY_ERROR;
    }

    // Find the algorithm parameters
    mtllib_ctx->algo_params = mtllib_util_get_algorithm_props((char *)keystr);
    if (mtllib_ctx->algo_params == NULL)
    {
        LOG_ERROR("Unknown Algorithm");
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }
    // SID
    sid.length = 2*mtllib_ctx->algo_params->sec_param;
    memcpy(&sid.id, sid_ptr, sid.length);

    if (mtllib_util_setup_sig_scheme(mtllib_ctx->algo_params->library,
                                     mtllib_ctx, NULL, 0,
                                     mtllib_buffer_data_ptr(pubkey),
                                     mtllib_buffer_in_use(pubkey),
                                     &sid,
                                     MTL_PUBLIC_KEY) != MTLLIB_OK)
    {
        LOG_ERROR("Key Setup Failed");
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }

    *ctx = mtllib_ctx;
    return MTLLIB_OK;
}

/**
 * MTL Library Key from Buffer
 * @param buffer MTLLIB Buffer input buffer holding the key
 * @param ctx MTL context created from the buffer
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_key_from_buffer(MTLLIB_BUFFER *buffer, MTLLIB_CTX **ctx)
{
    MTLLIB_CTX *mtllib_ctx = NULL;
    uint16_t flags = 0;
    uint8_t *buffer_ptr = NULL;
    uint8_t *record = NULL;
    size_t sk_len = 0;
    size_t pk_len = 0;
    size_t curr_len = 0;
    size_t bytes_len = 0;
    SERIESID sid;
    MTL_INDEX leaf_count;
    uint16_t hash_size;
    MTL_INDEX index;
    uint8_t *pk;
    uint8_t *sk;

    if ((buffer == NULL) || (ctx == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    *ctx = NULL;
    buffer_ptr = buffer->buffer_data;
    curr_len = mtllib_buffer_in_use(buffer);

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
    if (mtllib_util_buffer_read_bytes(&buffer_ptr, &curr_len, &record, &bytes_len, MTLLIB_BUFFER_MAX_FIELD_LENGTH, 0) != MTLLIB_OK)
    {
        free(mtllib_ctx);
        return MTLLIB_BAD_VALUE;
    }
    sk_len = bytes_len - 4;
    sk = record;

    // Read Public Key
    if (mtllib_util_buffer_read_bytes(&buffer_ptr, &curr_len, &record, &bytes_len, MTLLIB_BUFFER_MAX_FIELD_LENGTH, 1) != MTLLIB_OK)
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

    // Get MTL information
    // SID
    if (mtllib_util_buffer_read_bytes(&buffer_ptr, &curr_len, &record, &bytes_len, 256, 0) != MTLLIB_OK)
    {
        free(mtllib_ctx);
        return MTLLIB_BAD_VALUE;
    }
    sid.length = bytes_len - 4;
    memcpy(&sid.id, record, sid.length);
    free(record);


    if (mtllib_util_setup_sig_scheme(mtllib_ctx->algo_params->library,
                                     mtllib_ctx, sk, sk_len,
                                     pk, pk_len,
                                     &sid,
                                     MTL_PRIVATE_KEY) != MTLLIB_OK)
    {
        free(sk);
        free(pk);
        mtllib_key_free(mtllib_ctx);
        return MTLLIB_BAD_ALGORITHM;
    }
    free(sk);
    free(pk);

    // Leaf Count
    BUFFER_VERIFY_LENGTH(curr_len, sizeof(MTL_INDEX), mtllib_ctx);
    bytes_to_mtl_index(buffer_ptr, &leaf_count);
    buffer_ptr += sizeof(MTL_INDEX);
    curr_len -= sizeof(MTL_INDEX);

    // Hash size
    BUFFER_VERIFY_LENGTH(curr_len, 2, mtllib_ctx);
    bytes_to_uint16(buffer_ptr, &hash_size);
    buffer_ptr += 2;
    curr_len -= 2;
    if ((hash_size > 32) || (hash_size < 1))
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
 * @return size_t size of the key buffer
 */
size_t mtllib_key_to_buffer_length(MTLLIB_CTX *ctx)
{
    size_t param_len = 0;
    size_t mtl_hashes = 0;
    size_t hash_size = 0;

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL))
    {
        // Also check ctx->mtl sid and nodes for null
        LOG_ERROR("Unable to compute length (invalid context)");
        return 0;
    }
    mtl_hashes = ctx->mtl->nodes.leaf_count;
    hash_size = ctx->mtl->nodes.hash_size;

    param_len = (
        4 + strlen(ctx->algo_params->name) + // Alg String
        4 + ctx->signature->length_secret_key + // Secret Key
        4 + ctx->signature->length_public_key + // Public Key
        2 + // Randomization
        4 + 2 * hash_size // SID
        + sizeof(MTL_INDEX) + 2 // Number of Hashes + Hash Length
    );
    param_len += mtl_hashes * hash_size; // Allocate bytes for each leaf node
    if (ctx->algo_params->randomize)
    {
        param_len += mtl_hashes * hash_size; // Allocate bytes for each leaf node randomizer
    }

    return param_len;
}

/**
 * MTL Library Key to Buffer
 * @param ctx    MTL context to write to the buffer
 * @param buffer MTLLIB Buffer output buffer holding the key bytes
 * @return size_t size of the key buffer
 */
MTLLIB_STATUS mtllib_key_to_buffer(MTLLIB_CTX *ctx, MTLLIB_BUFFER *buffer)
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
    MTLLIB_STATUS status = MTLLIB_OK;

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL) || (buffer == NULL))
    {
        // Also check ctx->mtl sid and nodes for null
        return MTLLIB_NULL_PARAMS;
    }
    param_len = mtllib_key_to_buffer_length(ctx);
    mtl_hashes = ctx->mtl->nodes.leaf_count;
    hash_size = ctx->mtl->nodes.hash_size;
    if (mtllib_buffer_available(buffer) < param_len) {
        return MTLLIB_BUFFER_ISSUE;
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
    if (mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, ctx->secret_key, ctx->secret_key_len, MTLLIB_BUFFER_MAX_FIELD_LENGTH, 0) != MTLLIB_OK)
    {
        free(key_buffer);
        return MTLLIB_BAD_VALUE;
    }

    // Add Public Key Bytes
    if (mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, ctx->public_key, ctx->public_key_len, MTLLIB_BUFFER_MAX_FIELD_LENGTH, 1) != MTLLIB_OK)
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

    // Write the MTL mode data (SID, Leaf Count, Hashes, Randomizers)
    // Add SID Bytes
    if (mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, ctx->mtl->sid.id, ctx->mtl->sid.length, 256, 0) != MTLLIB_OK)
    {
        free(key_buffer);
        return MTLLIB_BAD_VALUE;
    }

    // Add leaf Count
    BUFFER_VERIFY_LENGTH(buffer_len, 4, NULL);
    mtl_index_to_bytes(buffer_ptr, mtl_hashes);
    buffer_ptr += sizeof(MTL_INDEX);
    buffer_len -= sizeof(MTL_INDEX);

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

    status = mtllib_buffer_append(buffer, key_buffer, buffer_ptr - key_buffer);
    free(key_buffer);
    return status;
}

/**
 * MTL Library append a message to the node set with default null ctx_str
 * @param ctx      MTL context to use
 * @param msg      input message buffer
 * @param mtl_node handle for the appended message
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_append(MTLLIB_CTX *ctx, 
                                    MTLLIB_BUFFER *msg,
                                    MTL_HANDLE **mtl_node)
{
    return mtllib_sign_append_with_ctx_str(ctx, msg, NULL, mtl_node);
}

/**
 * MTL Library append a message to the node set
 * @param ctx      MTL context to use
 * @param msg      input message buffer
 * @param ctx_str  input context string buffer
 * @param mtl_node handle for the appended message
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_append_with_ctx_str(MTLLIB_CTX *ctx, 
                                    MTLLIB_BUFFER *msg,
                                    MTLLIB_BUFFER *ctx_str,
                                    MTL_HANDLE **mtl_node)
{
    MTL_INDEX leaf_index = 0;
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

    if (mtl_hash_and_append(ctx->mtl,
                            mtllib_buffer_data_ptr(msg), 
                            mtllib_buffer_in_use(msg),
                            mtllib_buffer_data_ptr(ctx_str), 
                            mtllib_buffer_in_use(ctx_str),
                            &leaf_index) != MTL_OK)
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
 * MTL Library Get Condensed Signature Length
 * @param ctx pointer to the MTL library key context
 * @param handle  handle to the signed message
 * @return size_t Byte length of the condensed signature. 0 on error.
 */
size_t mtllib_sign_get_condensed_sig_length(MTLLIB_CTX *ctx, MTL_HANDLE *handle) {
    AUTHPATH *authpath;
    RANDOMIZER *randomizer;
    uint8_t *sig_buffer;
    size_t sig_len;

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL) ||
        (handle == NULL))
    {
        LOG_ERROR("Unable to compute condensed signature length (invalid context/handle)");
        return 0;
    }

    if (mtl_randomizer_and_authpath(ctx->mtl, handle->leaf_index, &randomizer, &authpath) != MTL_OK)
    {
        LOG_ERROR("Unable to compute condensed signature length (unable to compute authpath)");
        return 0;
    }
    sig_len = mtl_auth_path_to_buffer(randomizer, authpath, ctx->algo_params->sec_param, &sig_buffer);

    mtl_authpath_free(authpath);
    mtl_randomizer_free(randomizer);
    free(sig_buffer);
    
    return sig_len;
}

/**
 * MTL Library get the condensed signature for a handle
 * @param ctx     pointer to the MTL library key context
 * @param handle  handle to the signed message
 * @param sig     pointer to allocate and fill with the signature bytes
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_condensed_sig(MTLLIB_CTX *ctx, MTL_HANDLE *handle, MTLLIB_BUFFER *sig)
{
    RANDOMIZER *mtl_rand = NULL;
    AUTHPATH *auth = NULL;
    size_t sig_len = 0;
    uint8_t *sig_buffer;
    MTLLIB_STATUS status = MTLLIB_OK;

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL) ||
        (handle == NULL) || (sig == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    if (mtl_randomizer_and_authpath(ctx->mtl, handle->leaf_index, &mtl_rand, &auth) != MTL_OK)
    {
        return MTLLIB_SIGN_FAIL;
    }

    sig_len = mtl_auth_path_to_buffer(mtl_rand, auth, ctx->algo_params->sec_param, &sig_buffer);
    mtl_authpath_free(auth);
    mtl_randomizer_free(mtl_rand);

    if (mtllib_buffer_append(sig, sig_buffer, sig_len) != MTLLIB_OK) {
        status = MTLLIB_BUFFER_ISSUE;
    }
    free(sig_buffer);
    return status;
}

/**
 * MTL Library get the signed ladder length
 * @param ctx pointer to the MTL library key context
 * @return Length of a signed ladder for ctx, or 0 if unsuccessful
 */
size_t mtllib_sign_get_signed_ladder_length(MTLLIB_CTX *ctx)
{
    LADDER *ladder_ptr = NULL;
    size_t length;
    uint8_t *ladder_buffer = NULL;
    uint32_t ladder_buffer_len = 0;

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL))
    {
        LOG_ERROR("Unable to compute ladder length (invalid context)");
        return 0;
    }

    // Get the latest ladder
    ladder_ptr = mtl_ladder(ctx->mtl);
    ladder_buffer_len = mtl_ladder_to_buffer(ladder_ptr, ctx->mtl->nodes.hash_size, &ladder_buffer);
    mtl_ladder_free(ladder_ptr);

    // Ladder signatures is signature length + 4 bytes for length value
    length = ctx->signature->length_signature + 4 + ladder_buffer_len;
    free(ladder_buffer);
    return length;
}

/**
 * MTL Library get the length of a full signature for a handle
 * @param ctx     pointer to the MTL library key context
 * @param handle  handle to the signed message
 * @return length of the full signature, or 0 on error
 */
size_t mtllib_sign_get_full_sig_length(MTLLIB_CTX *ctx, MTL_HANDLE *handle) {
    return mtllib_sign_get_condensed_sig_length(ctx, handle) 
            + mtllib_sign_get_signed_ladder_length(ctx);
}

/**
 * MTL Library get the signed ladder
 * @param ctx        input buffer holding the key
 * @param handle     handle to the signed message
 * @param ladder     pointer to allocate and fill with the signed ladder bytes
 * @param ladder_len pointer to set to the signed ladder bytes length
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_signed_ladder(MTLLIB_CTX *ctx, MTLLIB_BUFFER *ladder)
{
    LADDER *ladder_ptr = NULL;
    uint8_t *ladder_sig = NULL;
    size_t ladder_sig_len;
    uint8_t *ladder_buffer = NULL;
    uint32_t ladder_buffer_len = 0;
    uint32_t oqs_return_code = OQS_ERROR;

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL) ||
        (ladder == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    // Get the latest ladder
    ladder_ptr = mtl_ladder(ctx->mtl);
    ladder_buffer_len = mtl_ladder_to_buffer(ladder_ptr, ctx->mtl->nodes.hash_size, &ladder_buffer);

    // Ladder signatures is signature length + 4 bytes for length value
    ladder_sig = malloc(ctx->signature->length_signature + 4 + ladder_buffer_len);
    memcpy(ladder_sig, ladder_buffer, ladder_buffer_len);
    mtl_ladder_free(ladder_ptr);
    uint32_to_bytes(&ladder_sig[ladder_buffer_len], ctx->signature->length_signature);
    if (ctx->signature->sig_with_ctx_support) {
        oqs_return_code = OQS_SIG_sign_with_ctx_str(ctx->signature, 
                     ladder_sig + 4 + ladder_buffer_len, &ladder_sig_len, 
                     ladder_buffer, ladder_buffer_len, 
                     MTL_SIGNING_CTX_STR, MTL_SIGNING_CTX_STR_LEN,
                     ctx->secret_key);
    }
    else {
        // OQS_SIG_sign_with_ctx_str() supports the use of context strings
        // Since the context string MUST be null as per draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00, OQS_SIG_sign() is used instead
        oqs_return_code = OQS_SIG_sign(ctx->signature, 
                     ladder_sig + 4 + ladder_buffer_len, &ladder_sig_len, 
                     ladder_buffer, ladder_buffer_len, 
                     ctx->secret_key);
    }
    if (oqs_return_code != OQS_SUCCESS)
    {
        free(ladder_sig);
        free(ladder_buffer);
        return MTLLIB_SIGN_FAIL;
    }

    free(ladder_buffer);


    if (mtllib_buffer_append(ladder, ladder_sig, ctx->signature->length_signature + 4 + ladder_buffer_len) != MTLLIB_OK) {
        free(ladder_sig);
        return MTLLIB_BUFFER_ISSUE;
    }
    free(ladder_sig);
    return MTLLIB_OK;
}

/**
 * MTL Library get the full signature for a handle
 * @param ctx     input buffer holding the key
 * @param handle  handle to the signed message
 * @param sig     pointer to fill with the signature bytes
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sign_get_full_sig(MTLLIB_CTX *ctx, MTL_HANDLE *handle, MTLLIB_BUFFER *sig)
{
    MTLLIB_BUFFER *condensed;
    MTLLIB_BUFFER *ladder;
    uint8_t *full = NULL;
    size_t sig_len = 0;

    if ((ctx == NULL) || (ctx->mtl == NULL) || (ctx->algo_params == NULL) ||
        (handle == NULL) || (sig == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    if (mtllib_buffer_initialize(&condensed, mtllib_sign_get_condensed_sig_length(ctx, handle), NULL) != MTLLIB_OK) {
        return MTLLIB_BUFFER_ISSUE;
    }
    if (mtllib_buffer_initialize(&ladder, mtllib_sign_get_signed_ladder_length(ctx), NULL)) {
        return MTLLIB_BUFFER_ISSUE;
    }

    if (mtllib_sign_get_condensed_sig(ctx, handle, condensed) != MTLLIB_OK)
    {
        mtllib_buffer_free(condensed);
        mtllib_buffer_free(ladder);
        return MTLLIB_SIGN_FAIL;
    }

    if (mtllib_sign_get_signed_ladder(ctx, ladder) != MTLLIB_OK)
    {
        mtllib_buffer_free(condensed);
        mtllib_buffer_free(ladder);
        return MTLLIB_SIGN_FAIL;
    }

    full = calloc(1, mtllib_buffer_in_use(condensed) + mtllib_buffer_in_use(ladder));
    if (full == NULL)
    {
        mtllib_buffer_free(condensed);
        mtllib_buffer_free(ladder);
        return MTLLIB_SIGN_FAIL;
    }

    memcpy(full, mtllib_buffer_data_ptr(condensed), mtllib_buffer_in_use(condensed));
    memcpy(full + mtllib_buffer_in_use(condensed), mtllib_buffer_data_ptr(ladder), mtllib_buffer_in_use(ladder));
    sig_len = mtllib_buffer_in_use(condensed) + mtllib_buffer_in_use(ladder);

    mtllib_buffer_free(condensed);
    mtllib_buffer_free(ladder);
    if (mtllib_buffer_append(sig, full, sig_len) != MTLLIB_OK) {
        free(full);
        return MTLLIB_BUFFER_ISSUE;
    }
    free(full);
    return MTLLIB_OK;
}

/**
 * MTL Library verify a signature (full or condensed) with default null context
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
                            size_t* condensed_len)
{
    return mtllib_verify_with_ctx_str(ctx, msg, NULL, sig, ladder_buf, condensed_len);
}

/**
 * MTL Library verify a signature (full or condensed)
 * @param ctx        input buffer holding the key
 * @param msg           msg to authenticate
 * @param ctx_str       context string with which to authenticate msg; MUST be null as per draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00
 * @param sig           pointer to the signature bytes
 * @param ladder        optional pointer to pre-verified ladder (for condensed signatures)
 * @param condensed_len optional pointer that will be filled in to the condensed length
 * @return MTLLIB_STATUS MTLLIB_OK if successful with cached ladder, MTLLIB_OK_VALIDATED_LADDER if successful with new ladder from full sig
 */
MTLLIB_STATUS mtllib_verify_with_ctx_str(MTLLIB_CTX *ctx, 
                            MTLLIB_BUFFER *msg, MTLLIB_BUFFER *ctx_str,
                            MTLLIB_BUFFER *sig, MTLLIB_BUFFER *ladder_buf,
                            size_t* output_condensed_len)
{
    AUTHPATH *auth_path = NULL;
    RANDOMIZER *mtl_rand = NULL;
    uint32_t condensed_len = 0;
    size_t ladder_sig_len = 0;
    RUNG *rung = NULL;
    LADDER *ladder = NULL;
    size_t ladder_len = 0;
    MTLLIB_BUFFER* mtl_ladder_buffer = NULL;
    uint8_t *msg_raw = NULL;
    size_t msg_len = 0;
    uint8_t *ctx_str_raw = NULL;
    size_t ctx_str_len = 0;
    uint8_t *sig_raw = NULL;
    size_t sig_len = 0;
    uint8_t *ladder_buf_raw = NULL;
    size_t ladder_buf_len = 0;
    MTLLIB_STATUS verify_status = MTLLIB_OK;

    if ((ctx == NULL) || (msg == NULL) || (sig == NULL)) {
        return MTLLIB_NULL_PARAMS;
    }

    if(output_condensed_len != NULL) {
        *output_condensed_len = 0;
    }

    // Parse input buffers
    msg_raw = mtllib_buffer_data_ptr(msg);
    msg_len = mtllib_buffer_in_use(msg);
    ctx_str_raw = mtllib_buffer_data_ptr(ctx_str);
    ctx_str_len = mtllib_buffer_in_use(ctx_str);
    sig_raw = mtllib_buffer_data_ptr(sig);
    sig_len = mtllib_buffer_in_use(sig);
    if (ladder_buf != NULL) {
        ladder_buf_raw = mtllib_buffer_data_ptr(ladder_buf);
        ladder_buf_len = mtllib_buffer_in_use(ladder_buf);
    }

    // Fetch the signature parameters
    condensed_len = mtl_auth_path_from_buffer(sig_raw, sig_len, ctx->algo_params->sec_param, &mtl_rand, &auth_path);
    if (condensed_len == 0)
    {
        mtl_randomizer_free(mtl_rand);
        mtl_authpath_free(auth_path);
        LOG_ERROR("Authentication Path is Invalid");
        return MTLLIB_BAD_VALUE;
    }
    if(output_condensed_len != NULL) {
        *output_condensed_len = condensed_len;
    }

   // Try to verify with the provided ladder (for performance less crypto to verify)
    if ((ladder_buf != NULL) && (ladder_buf_len > 0))
    {
        // Get the ladder from the buffer
        // If the ladder length is 0 then fall through to the next case as the provided ladder is not useful
        if (mtl_ladder_from_buffer(ladder_buf_raw, ladder_buf_len, ctx->algo_params->sec_param, &ladder) > 0)
        {
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
            if (mtl_verify(ctx->mtl, msg_raw, msg_len, ctx_str_raw, ctx_str_len, mtl_rand, auth_path, rung) == MTL_OK)
            {
                mtl_ladder_free(ladder);
                mtl_randomizer_free(mtl_rand);
                mtl_authpath_free(auth_path);
                return MTLLIB_OK;
            }
            else
            {
                LOG_ERROR("Provided ladder failed validation");
            }
            mtl_ladder_free(ladder);
        }
    }

    // If provided ladder didn't work see if we have a full signature we can use
    if (condensed_len < sig_len)
    {
        ladder_sig_len = sig_len - condensed_len;
        // Strip condensed signature from the front of the signature, leaving just the signed ladder
        if(mtllib_buffer_initialize(&mtl_ladder_buffer, ladder_sig_len, sig_raw + condensed_len) != MTLLIB_OK) 
        {
            LOG_ERROR("Buffer error while processing signed ladder");
            mtl_randomizer_free(mtl_rand);
            mtl_authpath_free(auth_path);
            return MTLLIB_BUFFER_ISSUE;
        }

        verify_status = mtllib_verify_signed_ladder(ctx, mtl_ladder_buffer);
        if (verify_status == MTLLIB_OK)
        {
            // Get the ladder from the buffer
            ladder_len = mtl_ladder_from_buffer(mtllib_buffer_data_ptr(mtl_ladder_buffer),
                                                mtllib_buffer_in_use(mtl_ladder_buffer),
                                                ctx->algo_params->sec_param, &ladder);
            mtllib_buffer_free(mtl_ladder_buffer);
            if (ladder_len == 0)
            {
                LOG_ERROR("Unable to read ladder from buffer");
                mtl_randomizer_free(mtl_rand);
                mtl_authpath_free(auth_path);
                mtllib_buffer_free(mtl_ladder_buffer);
                return MTLLIB_BUFFER_ISSUE;
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
            if (mtl_hash_and_verify(ctx->mtl, msg_raw, msg_len, ctx_str_raw, ctx_str_len, mtl_rand, auth_path, rung) == MTL_OK)
            {
                mtl_ladder_free(ladder);
                mtl_randomizer_free(mtl_rand);
                mtl_authpath_free(auth_path);
                return MTLLIB_OK_VALIDATED_LADDER;
            }
            else
            {
                LOG_ERROR("Ladder was valid, but authpath could not authenticate with the ladder");
                mtl_ladder_free(ladder);
                mtl_randomizer_free(mtl_rand);
                mtl_authpath_free(auth_path);
                return MTLLIB_BOGUS_CRYPTO;
            }
        }
        else if(verify_status == MTLLIB_NO_LADDER)
        {
            LOG_ERROR("There is no valid ladder to use for validating this signature.  Please fetch a valid ladder.");
            mtllib_buffer_free(mtl_ladder_buffer);
            mtl_randomizer_free(mtl_rand);
            mtl_authpath_free(auth_path);
            return MTLLIB_NO_LADDER;
        }
        else if(verify_status == MTLLIB_BAD_VALUE)
        {
            LOG_ERROR("Unable to parse the provided ladder");
            mtllib_buffer_free(mtl_ladder_buffer);
            mtl_randomizer_free(mtl_rand);
            mtl_authpath_free(auth_path);
            return MTLLIB_BAD_VALUE;
        }
        else
        {
            LOG_ERROR("Unable to validate the provided ladder");
            mtllib_buffer_free(mtl_ladder_buffer);
            mtl_randomizer_free(mtl_rand);
            mtl_authpath_free(auth_path);
            return MTLLIB_BOGUS_CRYPTO;
        }
    } else {
        LOG_ERROR("There is no valid ladder to use for validating this signature.  Please fetch a valid ladder.");
        mtl_randomizer_free(mtl_rand);
        mtl_authpath_free(auth_path);
        return MTLLIB_NO_LADDER;
    }

    // Should be unreachable, but return error just in case
    return MTLLIB_BOGUS_CRYPTO;
}

/**
 * MTL Library verify a signed ladder
 * @param ctx        pointer to the MTL library key context
 * @param buffer     MTLLIB buffer with the signed ladder bytes
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_verify_signed_ladder(MTLLIB_CTX *ctx, MTLLIB_BUFFER *buffer)
{
    LADDER *ladder = NULL;
    size_t ladder_len = 0;
    uint32_t oqs_return_code = OQS_ERROR;

    if ((ctx == NULL) || (buffer == NULL) ||
        (mtllib_buffer_data_ptr(buffer) == NULL) ||
        (mtllib_buffer_in_use(buffer) == 0))
    {
        LOG_ERROR("Unable to read ladder from buffer");
        return MTLLIB_NULL_PARAMS;
    }

    // Get the ladder from the buffer
    ladder_len = mtl_ladder_from_buffer(mtllib_buffer_data_ptr(buffer), mtllib_buffer_in_use(buffer), ctx->algo_params->sec_param, &ladder);
    if (ladder_len == 0)
    {
        LOG_ERROR("Unable to read ladder from buffer");
        return MTLLIB_BAD_VALUE;
    }
    mtl_ladder_free(ladder);

    if (ladder_len + ctx->signature->length_signature + 4 > mtllib_buffer_in_use(buffer))
    {
        LOG_ERROR("Unable to read ladder from buffer");
        return MTLLIB_INDETERMINATE;
    }

    // Verify the signature on the ladder...
    if (ctx->signature->sig_with_ctx_support) {
        oqs_return_code = OQS_SIG_verify_with_ctx_str(ctx->signature, mtllib_buffer_data_ptr(buffer), ladder_len,
                       mtllib_buffer_data_ptr(buffer) + 4 + ladder_len, ctx->signature->length_signature, 
                       MTL_SIGNING_CTX_STR, MTL_SIGNING_CTX_STR_LEN,
                       ctx->public_key);
    }
    else {
        // OQS_SIG_verify_with_ctx_str() supports the use of context strings
        // Since the context string MUST be null as per draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00, OQS_SIG_verify() is used instead
        oqs_return_code = OQS_SIG_verify(ctx->signature, mtllib_buffer_data_ptr(buffer), ladder_len,
                       mtllib_buffer_data_ptr(buffer) + 4 + ladder_len, ctx->signature->length_signature, 
                       ctx->public_key);
    }
    if (oqs_return_code != OQS_SUCCESS)
    {
        LOG_ERROR("OQS_SIG_verify - Failed!");        
        return MTLLIB_BOGUS_CRYPTO;
    }

    return MTLLIB_OK;
}

/**
 * MTL Library get the current size needed for a signed ladder
 * @param ctx     The initalized MTLLIB context 
 * @return 0 for error or max size of the buffer on success
 */
size_t mtllib_sig_get_signed_ladder_size(MTLLIB_CTX *ctx) {
    size_t ladder_size = 0;
    size_t rung_size = 0;
    size_t total_rungs = 0;

    if((ctx == NULL) || (ctx->mtl == NULL)) {
        return 0;
    }
    total_rungs = mtl_bit_width(ctx->mtl->nodes.leaf_count);

    // Rung size is: (from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1)
    //     Left Index  (MTL_INDEX_LEN bytes)
    //     Right Index (MTL_INDEX_LEN bytes)
    //     Rung Hash   (sec_param bytes)
    rung_size = MTL_INDEX_LEN  + MTL_INDEX_LEN + ctx->algo_params->sec_param;

    // Ladder size is: (from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1)
    //     Flags          (2 bytes)
    //     SID            (sec_param *2 bytes)
    //     Rung Count     (2 bytes) 
    //     Size of rungs  (total_rungs * rung_size)
    ladder_size = 2 + (ctx->algo_params->sec_param *2) + 2 + (total_rungs * rung_size);

    // Signed ladder size is: (from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1)
    //      Ladder Size    (see calc above)
    //      Signature Len  (4 bytes)
    //      Signature Data (signature specific)
    return ladder_size + 4 + ctx->signature->length_signature;
}


/**
 * MTL Library get the size of the hash based on the signature scheme string
 * @param keystr     key string represnting the signature algorithm
 * @return hash size in bytes, or 0 if not a valid key string
 */
uint16_t mtllib_sig_buffer_get_hash_size(char* keystr) {
    MTL_ALGORITHM_PROPS* algo_params = mtllib_util_get_algorithm_props(keystr);
    if(algo_params != NULL) {
        return algo_params->sec_param;
    }
    return 0;
}

/**
 * MTL Library extract the sid from a signature buffer
 * @param buffer     pointer to the signed ladder bytes
 * @param buffer_len length of the signed ladder in bytes
 * @param hash_size  size of the hash for the specific algorithm
 * @param sid        pre-allocated SERIESID structure for the SID values
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sig_buffer_get_sid(MTLLIB_BUFFER *buffer,
                                        uint16_t hash_size, SERIESID* sid)
{
    if((buffer == NULL)||(mtllib_buffer_in_use(buffer) < 2 + 32)) {
        return MTLLIB_BUFFER_ISSUE;
    }
    if(sid == NULL) {
        return MTLLIB_NULL_PARAMS;
    }
    sid->length = hash_size * 2;
    /* The SID can be found after the following fields
     * Flags: 2 bytes
     */
    memcpy(sid->id, buffer->buffer_data+2, sid->length);

    return MTLLIB_OK;
}

/**
 * MTL Library extract the leaf index from a signature buffer
 * @param buffer     pointer to the signed ladder bytes
 * @param buffer_len length of the signed ladder in bytes
 * @param hash_size  size of the hash for the specific algorithm
 * @param leaf_index pre-allocated leaf index for the value
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_sig_buffer_get_leaf_index(MTLLIB_BUFFER *buffer,
                                        uint16_t hash_size, MTL_INDEX* leaf_index)
{
    size_t buffer_offset = 0;

    if((buffer == NULL)||(mtllib_buffer_in_use(buffer) < 2 + 32 + 16 + sizeof(MTL_INDEX))) {
        return MTLLIB_BUFFER_ISSUE;
    }
    if(leaf_index == NULL) {
        return MTLLIB_NULL_PARAMS;
    }

    /* The leaf index can be found after the following fields
     * Flags: 2 bytes
     * SID: 2 * hash_size bytes
     * Randomizer: hash_size bytes
     */
    buffer_offset = 2 + (hash_size * 2) + hash_size;
    bytes_to_mtl_index(&buffer->buffer_data[buffer_offset], leaf_index);

    return MTLLIB_OK;
}


/**
 * MTL Library get the length of the condensed signature from a signature buffer
 * @param buffer     pointer to the signed ladder bytes
 * @param buffer_len length of the signed ladder in bytes
 * @param hash_size  size of the hash for the specific algorithm
 * @return length in bytes of the condensed signature
 */
size_t mtllib_sig_buffer_condensed_sig_len(MTLLIB_BUFFER *buffer,
                                        uint16_t hash_size) {
    size_t buffer_offset = 0;
    size_t mtl_id_len = sizeof(MTL_INDEX);
    uint16_t sib_hash_count = 0;

    if((buffer == NULL)||(mtllib_buffer_in_use(buffer) < 2 + (2 * hash_size) + hash_size + (mtl_id_len * 3) + 2)) {
        return 0;
    }

    /* The condensed signature is the following length
     * Flags: 2 bytes
     * SID: 2 * hash_size bytes
     * Randomizer: hash_size bytes
     * Leaf Index: MTL_ID bytes
     * Rung Left Index: MTL_ID bytes
     * Rung Right Index: MTL_ID bytes
     */
    buffer_offset = 2 + (2 * hash_size) + hash_size + (mtl_id_len * 3);
     // Sibiling Hash Count: 2 bytes
    buffer_offset += bytes_to_uint16(&buffer->buffer_data[buffer_offset], &sib_hash_count);
     // Sibiling Hash Values: count * hash_size bytes
    buffer_offset += (sib_hash_count * hash_size);

    return buffer_offset;
}