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
 *  \file mtllib_status.h
 *  \brief Definitions of the status return values for MTLLIB
 */
#ifndef __MTL_LIB_STATUS_H__
#define __MTL_LIB_STATUS_H__

typedef enum MTLLIB_STATUS
{
    // Success status
    MTLLIB_OK = 0,
    // Success status plus indicates that the signature on the
    //     ladder was successfuly verified
    MTLLIB_OK_VALIDATED_LADDER = 1,
    // Failure where null parameters were passed to a function
    MTLLIB_NULL_PARAMS = 2,
    // Faiure where the algorithm ID, hash algorithm, or 
    //     underlying signature scheme is not recognized
    MTLLIB_BAD_ALGORITHM = 3,
    // Failure where memory is unable to be allocated or managed
    MTLLIB_MEMORY_ERROR = 4,
    // Failure where a feature is not yet supported but has a
    //     place holder for possible future use
    MTLLIB_UNSUPPORTED_FEATURE = 5,
    // Failure where a record field is invalid. Can be due to
    //     unable to read random bytes or a buffer is missing the
    //     data (e.g. authpath should have 4 - 16 byte hashes but
    //     only has 8 bytes)
    MTLLIB_BAD_VALUE = 6,
    // Failures related to the mtllib_sign operations (e.g.
    //     operations that need secret material to do the operations)
    MTLLIB_SIGN_FAIL = 7, 
    // Failures related to crypto operations that indicate the
    //     signature is not valid    
    MTLLIB_BOGUS_CRYPTO = 8,
    // Failures where no ladder can be used to verify an auth path.
    //     May need to get a new ladder or auth path
    MTLLIB_NO_LADDER = 9,
    // Failures related to crypto operations where validity cannot
    //     be determined (e.g. missing something needed to verify)
    MTLLIB_INDETERMINATE = 10,
    // Failures related but buffer issues (e.g. not long enough or
    //     not initalized)
    MTLLIB_BUFFER_ISSUE = 11
} MTLLIB_STATUS;


#endif   // __MTL_LIB_STATUS_H__