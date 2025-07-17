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
 *  \file mtllib_util.h
 *  \brief Helper functions for the mtllib API implementation.
 */
#ifndef __MTL_LIB_UTIL_H__
#define __MTL_LIB_UTIL_H__

#include <stddef.h>
#include <stdint.h>
#include "mtllib.h"

// MTL Library Function Prototypes
/**
 * MTL Library Get Algorithm Properties Utility
 * @param keystr Key string
 * @return MTL_ALGORITHM_PROPS Algorithm properties struct
 *                             (or NULL if not present)
 */
MTL_ALGORITHM_PROPS *mtllib_util_get_algorithm_props(char *keystr);

/**
 * MTL Library Write Key Algorithms
 * @param fp pointer to the file stream to write the algorithm identifiers
 * @return MTLLIB_STATUS MTLLIB_OK on success
 */
MTLLIB_STATUS mtllib_key_write_algorithms(FILE *fp);

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
                                           SERIESID *sid);

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
                                            size_t min_len);

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
                                             size_t min_len);

#endif