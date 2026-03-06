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
#ifndef __MTL_LIB_BUFFER_H__
#define __MTL_LIB_BUFFER_H__

#include <stddef.h>
#include <stdint.h>
#include <oqs/sig.h>
#include "mtllib_status.h"

/** Maximum size supported for a single buffer element */
#define MTLLIB_BUFFER_MAX_FIELD_LENGTH 0x7FFFFFFF

typedef enum MTLLIB_BUFFER_TYPE
{
    MTLLIB_UNINITALIZED_BUFFER = 0,
    MTLLIB_EXTERNAL_BUFFER = 1,
    MTLLIB_INTERNAL_BUFFER = 2,    
} MTLLIB_BUFFER_TYPE;

typedef struct MTLLIB_BUFFER {
    MTLLIB_BUFFER_TYPE  buffer_type;
    size_t   buffer_length;
    size_t   buffer_position;
    uint8_t* buffer_data;
} MTLLIB_BUFFER;

/**
 * MTL Library initalize a buffer
 * @param buffer pointer to the MTLLIB_BUFFER object that will be created
 * @param buffer_length number of bytes that should be allocated for the buffer
 * @param buffer_data the buffer bytes data.  Passing NULL indicates the buffer
 *              should allocate an internal buffer, otherwise it should use the
 *              passed in pointer to the bytes data
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_buffer_initialize(MTLLIB_BUFFER** buffer, size_t buffer_length, uint8_t* buffer_data);

/**
 * MTL Library free buffer
 * @param buffer pointer to the MTLLIB_BUFFER object that will be freed. If the
 *              buffer bytes data was passed in, the caller must free the bytes.
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_buffer_free(MTLLIB_BUFFER* buffer);

/**
 * MTL Library function to get the max bytes allocated in a buffer
 * @param buffer pointer to the active MTLLIB_BUFFER object
 * @return size of the allocated buffer
 */
size_t mtllib_buffer_size(MTLLIB_BUFFER* buffer);

/**
 * MTL Library function to get the count of bytes in use in a buffer
 * @param buffer pointer to the active MTLLIB_BUFFER object
 * @return number of bytes in use in the allocated buffer
 */
size_t mtllib_buffer_in_use(MTLLIB_BUFFER* buffer);

/**
 * MTL Library function to get the count of remaining free bytes in the buffer
 * @param buffer pointer to the active MTLLIB_BUFFER object
 * @return number of bytes in use in the allocated buffer
 */
size_t mtllib_buffer_available(MTLLIB_BUFFER *buffer);

/**
 * MTL Library function to get a pointer to the current buffer data
 * @param buffer pointer to the active MTLLIB_BUFFER object
 * @return number of bytes in use in the allocated buffer
 */
uint8_t* mtllib_buffer_data_ptr(MTLLIB_BUFFER *buffer);

/**
 * MTL Library function to append data to a buffer
 * @param buffer pointer to the active MTLLIB_BUFFER object
 * @param data data to append to the buffer
 * @param length length of the data to append
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_buffer_append(MTLLIB_BUFFER* buffer, uint8_t* data, size_t length);

/**
 * MTL Library function to append data to a buffer at a location
 * @param buffer pointer to the active MTLLIB_BUFFER object
 * @param data data to append to the buffer
 * @param length length of the data to append
 * @param position position in buffer to append at
 * @return MTLLIB_STATUS MTLLIB_OK if successful
 */
MTLLIB_STATUS mtllib_buffer_append_at(MTLLIB_BUFFER* buffer, uint8_t* data, size_t length, size_t position);


#endif //__MTL_LIB_BUFFER_H__