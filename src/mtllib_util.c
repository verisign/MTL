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
#include "mtl_spx.h"
#include "mtl_util.h"

#include "mtllib.h"
#include "mtllib_util.h"
#include "mtllib_schemes.h"

#include <oqs/sig.h>
#include <openssl/rand.h>

/**
 * MTL Library Get Algorithm Properties Utility
 * @param keystr Key string
 * @return MTL_ALGORITHM_PROPS Algorithm properties struct
 *                             (or NULL if not present)
 */
MTL_ALGORITHM_PROPS *mtllib_util_get_algorithm_props(char *keystr)
{
    size_t algo_idx = 0;

    // Find the appropriate algorithm
    while (sig_algos[algo_idx].name != NULL)
    {
        if (strcmp(sig_algos[algo_idx].name, (char *)keystr) == 0)
        {
            return &sig_algos[algo_idx];
        }
        algo_idx++;
    }
    return NULL;
}

/**
 * MTL Library Write Key Algorithms
 * @param fp pointer to the file stream to write the algorithm identifiers
 * @return MTLLIB_STATUS MTLLIB_OK on success
 */
MTLLIB_STATUS mtllib_key_write_algorithms(FILE *fp)
{
    uint16_t algo_idx = 0;

    if (fp == NULL)
    {
        return MTLLIB_NULL_PARAMS;
    }

    while (sig_algos[algo_idx].name != NULL)
    {
        fprintf(fp, "      %s\n", sig_algos[algo_idx].name);
        algo_idx++;
    }
    return MTLLIB_OK;
}

static MTLLIB_STATUS mtllib_util_setup_sig_scheme_liboqs(MTLLIB_CTX *mtllib_ctx,
                                                         uint8_t *sk,
                                                         size_t sk_len,
                                                         uint8_t *pk,
                                                         size_t pk_len)
{
    if (mtllib_ctx->algo_params->scheme_str == NULL)
    {
        return MTLLIB_NULL_PARAMS;
    }

    // Create the new underlying singnature and allocate space for keys
    mtllib_ctx->signature = OQS_SIG_new(mtllib_ctx->algo_params->scheme_str);
    if (mtllib_ctx->signature == NULL)
    {
        fprintf(stderr, "ERROR: Unable to initalize keys\n");
        return MTLLIB_MEMORY_ERROR;
    }
    mtllib_ctx->secret_key = calloc(1, mtllib_ctx->signature->length_secret_key);
    mtllib_ctx->public_key = calloc(1, mtllib_ctx->signature->length_public_key);

    if ((mtllib_ctx->public_key == NULL) || (mtllib_ctx->secret_key == NULL))
    {
        fprintf(stderr, "ERROR: Unable allocate key memory\n");
        return MTLLIB_MEMORY_ERROR;
    }

    if ((sk == NULL) && (pk == NULL))
    {
        // Poplulate the public and secret keys
        if (OQS_SIG_keypair(mtllib_ctx->signature, mtllib_ctx->public_key, mtllib_ctx->secret_key) != OQS_SUCCESS)
        {
            fprintf(stderr, "ERROR: Unable generate keys\n");
            return MTLLIB_MEMORY_ERROR;
        }
        mtllib_ctx->secret_key_len = mtllib_ctx->signature->length_secret_key;
        mtllib_ctx->public_key_len = mtllib_ctx->signature->length_public_key;
    }
    else
    {
        if (sk != NULL)
        {
            // It is possible to not have the secret key info in operations like validation.
            if (sk_len == mtllib_ctx->signature->length_secret_key)
            {
                mtllib_ctx->secret_key_len = sk_len;
                memcpy(mtllib_ctx->secret_key, sk, sk_len);
            }
            else
            {
                fprintf(stderr, "ERROR: Key length does not match (sk: %ld != %ld)\n", sk_len, mtllib_ctx->signature->length_secret_key);
                return MTLLIB_MEMORY_ERROR;
            }
        }

        if (pk != NULL)
        {
            if (pk_len == mtllib_ctx->signature->length_public_key)
            {
                mtllib_ctx->public_key_len = pk_len;
                memcpy(mtllib_ctx->public_key, pk, pk_len);
            }
            else
            {
                fprintf(stderr, "ERROR: Key length does not match (pk: %ld != %ld)\n", pk_len, mtllib_ctx->signature->length_public_key);
                return MTLLIB_MEMORY_ERROR;
            }
        }
        else
        {
            fprintf(stderr, "ERROR: No Public Key!\n");
            return MTLLIB_BAD_VALUE;
        }
    }
    return MTLLIB_OK;
}

/**
 * MTL Library Setup Signature Scheme Utility
 * @param lib         MTL Library Type to instantiate from
 * @param mtllib_ctx  MTL Library Context to update
 * @param sk          Byte array containing the secret key
 * @param sk_len      Length of the secret key byte array
 * @param pk          Byte array containin the public key
 * @param pk_len      Length of the public key byte array
 * @param mtl_ctx_str Null or context string to use
 * @param seed        Seed value for MTL series (NULL for new keys)
 * @param sid         Series ID value for MTL series (NULL for new keys)
 * @return MTLLIB_STATUS MTLLIB_OK on success
 */
MTLLIB_STATUS mtllib_util_setup_sig_scheme(MTL_CRYPTO_LIBRARY lib,
                                           MTLLIB_CTX *mtllib_ctx,
                                           uint8_t *sk,
                                           size_t sk_len,
                                           uint8_t *pk,
                                           size_t pk_len,
                                           char *mtl_ctx_str,
                                           SEED *seed,
                                           SERIESID *sid)
{
    SPX_PARAMS *param_ptr = NULL;
    SEED *setup_seed = NULL;
    SERIESID *setup_sid = NULL;
    MTLLIB_STATUS setup_status = MTLLIB_OK;

    if ((mtllib_ctx == NULL) || (mtllib_ctx->algo_params == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    // Allocate the underlying signature scheme
    switch (lib)
    {
    case LIBOQS:
        setup_status = mtllib_util_setup_sig_scheme_liboqs(mtllib_ctx, sk, sk_len, pk, pk_len);
        if(setup_status != MTLLIB_OK) {
            return setup_status;
        }
        break;
    case OPENSSL:
        fprintf(stderr, "ERROR: Unsupported cryptography algorithm\n");
        return MTLLIB_UNSUPPORTED_FEATURE;
    case NONE:
    default:
        return MTLLIB_BAD_ALGORITHM;
    }

    if (seed == NULL)
    {
        setup_seed = calloc(1, sizeof(SEED));
        // Create the seed from the public key
        setup_seed->length = mtllib_ctx->algo_params->sec_param;
        memcpy(&setup_seed->seed, mtllib_ctx->public_key, setup_seed->length);
    }
    else
    {
        setup_seed = seed;
    }

    if (sid == NULL)
    {
        setup_sid = calloc(1, sizeof(SERIESID));
        setup_sid->length = mtllib_ctx->algo_params->sid_len;
        if(!RAND_bytes(setup_sid->id, setup_sid->length)) {
            // Unable to get the needed randomization
            printf("ERROR: cannot generate the appropriate random values\n");
            if (seed == NULL)
            {
                free(setup_seed);
            }
            return MTLLIB_BAD_VALUE;            
        }
    }
    else
    {
        setup_sid = sid;
    }
    mtl_initns(&mtllib_ctx->mtl, setup_seed, setup_sid, mtl_ctx_str);

    if (seed == NULL)
    {
        free(setup_seed);
    }

    if (sid == NULL)
    {
        free(setup_sid);
    }

    // Setup the SLH-DSA Parameters
    // Robust is not part of SLH-DSA
    param_ptr = malloc(sizeof(SPX_PARAMS));
    param_ptr->robust = 0;

    PKSEED_INIT(param_ptr->pk_seed, mtllib_ctx->public_key, mtllib_ctx->algo_params->sec_param);
    PKROOT_INIT(param_ptr->pk_root, mtllib_ctx->public_key + mtllib_ctx->algo_params->sec_param,
                mtllib_ctx->algo_params->sec_param);
    SKPRF_INIT(param_ptr->prf, mtllib_ctx->secret_key + mtllib_ctx->algo_params->sec_param,
               mtllib_ctx->algo_params->sec_param);

    // Select the hashing algorithm
    switch (mtllib_ctx->algo_params->hash_algo)
    {
    case HASH_SHAKE:
        if (mtl_set_scheme_functions(mtllib_ctx->mtl, param_ptr, mtllib_ctx->algo_params->randomize,
                                     spx_mtl_node_set_hash_message_shake,
                                     spx_mtl_node_set_hash_leaf_shake,
                                     spx_mtl_node_set_hash_int_shake, mtl_ctx_str) != MTL_OK)
        {
            return MTLLIB_NULL_PARAMS;
        }
        break;
    case HASH_SHA2:
        if (mtl_set_scheme_functions(mtllib_ctx->mtl, param_ptr, mtllib_ctx->algo_params->randomize,
                                     spx_mtl_node_set_hash_message_sha2,
                                     spx_mtl_node_set_hash_leaf_sha2,
                                     spx_mtl_node_set_hash_int_sha2, mtl_ctx_str) != MTL_OK)
        {
            return MTLLIB_NULL_PARAMS;
        }
        break;
    case HASH_NONE:
    default:
        printf("ERROR: Bad algorithm\n");
        return MTLLIB_BAD_ALGORITHM;
    }

    return MTLLIB_OK;
}

/**
 * MTL Library Read Bytes with Length from Buffer
 * @param buffer     Buffer to read from (and advance pointer)
 * @param buffer_len Current length of the buffer (updates after read)
 * @param dest       Destination buffer to write to
 * @param dest_len   Length of the destination buffer
 * @param max_len    Max value allowed for the num of bytes read
 * @param min_len    Min value allowed for the num of bytes read
 * @return MTLLIB_STATUS MTLLIB_OK on success
 */
MTLLIB_STATUS mtllib_util_buffer_read_bytes(uint8_t **buffer,
                                            size_t *buffer_len,
                                            uint8_t **dest,
                                            size_t *dest_len,
                                            size_t max_len,
                                            size_t min_len)
{
    size_t bytes_read = 0;
    uint32_t bytes_len = 0;
    uint8_t *buffer_ptr = NULL;
    uint8_t *dest_value = NULL;

    if ((buffer == NULL) || (buffer_len == NULL) ||
        (*buffer == NULL) || (dest == NULL) || (dest_len == NULL))
    {
        printf("ERROR: NULL parameters!\n");
        return MTLLIB_NULL_PARAMS;
    }

    buffer_ptr = *buffer;
    *dest_len = 0;

    if ((*buffer_len < 4) || (max_len < min_len))
    {
        printf("ERROR: Buffer is invalid!\n");
        return MTLLIB_BAD_VALUE;
    }

    bytes_read += bytes_to_uint32(buffer_ptr, &bytes_len);
    buffer_ptr += 4;
    if ((bytes_len > max_len) || (bytes_len < min_len))
    {
        printf("ERROR: Buffer length value is invalid!\n");
        return MTLLIB_BAD_VALUE;
    }

    if (*buffer_len < bytes_len + 4)
    {
        printf("ERROR: Buffer error\n");
        return MTLLIB_BAD_VALUE;
    }

    // Add one byte so that it is null terminated
    // for later comparisons (if string, etc...)
    if (bytes_len > 0)
    {
        dest_value = calloc(1, bytes_len + 1);
        if (dest_value == NULL)
        {
            printf("ERROR: Cannot allocate buffer!\n");
            return MTLLIB_NULL_PARAMS;
        }
        memcpy(dest_value, buffer_ptr, bytes_len);
        bytes_read += bytes_len;
    }
    else
    {
        dest_value = NULL;
    }

    *buffer_len -= 4 + bytes_len;
    *buffer += 4 + bytes_len;
    *dest_len = bytes_read;
    *dest = dest_value;
    return MTLLIB_OK;
}

/**
 * MTL Library Write Bytes with Length to Buffer
 * @param buffer     Buffer to read from (and advance pointer)
 * @param buffer_len Current length of the buffer (updates after read)
 * @param src        Source buffer to read from
 * @param src_len    Length of the source buffer
 * @param max_len    Max value allowed for the num of bytes read
 * @param min_len    Min value allowed for the num of bytes read
 * @return MTLLIB_STATUS MTLLIB_OK on success
 */
MTLLIB_STATUS mtllib_util_buffer_write_bytes(uint8_t **buffer,
                                             size_t *buffer_len,
                                             uint8_t *src,
                                             size_t src_len,
                                             size_t max_len,
                                             size_t min_len)
{
    if ((buffer == NULL) || (buffer_len == NULL) || (src == NULL))
    {
        return MTLLIB_NULL_PARAMS;
    }

    if ((src_len > max_len) || (src_len < min_len) ||
        (max_len < min_len))
    {
        printf("ERROR: Invalid parameter length\n");
        return MTLLIB_BAD_VALUE;
    }
    BUFFER_VERIFY_LENGTH(*buffer_len, 4, NULL);
    uint32_to_bytes(*buffer, src_len);
    *buffer += 4;
    *buffer_len -= 4;

    memcpy(*buffer, src, src_len);
    *buffer += src_len;
    *buffer_len -= src_len;

    return MTLLIB_OK;
}