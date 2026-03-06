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
 *  \file mtl_hash.h
 *  \brief Concrete instantiations of the generic hash functions H_leaf and H_int
*/
#ifndef __MTL_HASH_H__
#define __MTL_HASH_H__

#include <arpa/inet.h>
#include <math.h>
#include <openssl/hmac.h>
#include <string.h>

#include "mtl_util.h"
#include "mtl_node_set.h"


// Defined hash families
#define MTL_HASH_SHA2 1
#define MTL_HASH_SHAKE 2

// H_leaf and H_int function  pointer types
typedef MTLSTATUS H_LEAF(SERIESID * sid,
				      	MTL_INDEX node_index,
				      	uint8_t * msg_buffer, uint32_t msg_len,
					  	uint8_t * ctx, uint32_t ctx_len,
				      	uint8_t * rand, uint32_t rand_len,
				      	uint8_t * hash_out, uint32_t hash_len);

typedef MTLSTATUS H_INT(SERIESID * sid,
				  		MTL_INDEX adrs_left,
				  		MTL_INDEX adrs_right,
				  		uint8_t * hash_left,
				  		uint8_t * hash_right, uint8_t * hash_out,
				  		uint32_t hash_len);
						
// H_mtl pointer type, not yet modified						
typedef MTLSTATUS H_MSG(void *params, SERIESID * sid, MTL_INDEX node_id,
			     		uint8_t * randomizer, uint32_t randomizer_len,
			     		uint8_t * msg_buffer, uint32_t msg_length,
			     		uint8_t * hash, uint32_t hash_length, char* ctx,
				 		uint8_t ** rmtl, uint32_t * rmtl_len);

/*****************************************************************
* cSHA2-X Hash Function - Based on OpenSSL EVP API
* From draft-harvey-cfrg-mtl-mode-07
******************************************************************
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @param out_len: Desired output size. Also interpreted as security parameter
 * @return MTL_OK on success
 */
MTLSTATUS mtl_hash_sha2(uint8_t * out, const uint8_t * in, size_t in_len, size_t out_len);


/*****************************************************************
* cSHAKE Hash Function - Based on OpenSSL EVP API.
* Automatically uses cSHAKE128 or cSHAKE256 based on hash_len. 
* Uses fixed customization string from draft-harvey-cfrg-mtl-mode-07. 
* NOTE: cSHAKE not yet supported by OpenSSL. For now, we use SHAKE as a placeholder. 
******************************************************************
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @param hash_len: Desired output size. Also interpreted as security parameter
 * @return MTL_OK on success
 */
MTLSTATUS mtl_hash_shake(uint8_t * out, const uint8_t * in, size_t in_len, size_t out_len);


/*****************************************************************
* Hash the message set with the rand
******************************************************************
 * @param sid:        Series identifier for this MTL node set
 * @param node_index:    Node identifier for this message
 * @param rand:       Randomizer for this message
 * @param rand_len:   Length of the rand byte array
 * @param msg_buffer: Byte array of the message that will be added
 * @param msg_len:    Length of the msg_buffer array
 * @param hash_out:       Pointer to byte array where hash is stored
 * @param hash_len:   Length of hash byte array. Also interpreted as security parameter
 * @param ctx:        Context string for this message
 * @param algorithm:  Type of algorithm used (#defined values) 
 * @return MTL_OK if successful
 */
MTLSTATUS mtl_node_set_hash_leaf(
				      SERIESID * sid,
				      MTL_INDEX node_index,
				      uint8_t * msg_buffer, uint32_t msg_len,
					  uint8_t * ctx, uint32_t ctx_len,
				      uint8_t * rand, uint32_t rand_len,
				      uint8_t * hash_out, uint32_t hash_len, 
					  uint8_t algorithm);

H_LEAF mtl_node_set_hash_leaf_sha2;
H_LEAF mtl_node_set_hash_leaf_shake;

/*****************************************************************
* Algorithm 2: Hashing Two Child Nodes to Produce an Internal Node.
******************************************************************
 * @param sid:        Series ID generated for the MTL node set
 * @param adrs_left:   Left index of this node's address
 * @param adrs_right:  Right index of this node's address
 * @param hash_left:   Pointer to byte array for left child hash
 * @param hash_right:  Pointer to byte array for right child hash
 * @param hash_out:       Pointer where the resulting hash is placed
 * @param hash_len:   Length of hash byte arrays
 * @param algorithm:  Type of algorithm used (#defined values) 
 * @return MTL_OK if successful 
 */
MTLSTATUS mtl_node_set_hash_int(
				  SERIESID * sid,
				  MTL_INDEX adrs_left,
				  MTL_INDEX adrs_right,
				  uint8_t * hash_left,
				  uint8_t * hash_right, uint8_t * hash_out,
				  uint32_t hash_len, uint8_t algorithm);

H_INT mtl_node_set_hash_int_sha2;
H_INT mtl_node_set_hash_int_shake;


/** Simple insecure hash functions for testing purposes only */
H_MSG mtl_hash_h_msg_testing;
H_LEAF mtl_hash_h_leaf_testing;
H_INT mtl_hash_h_int_testing;

#endif      // __MTL_HASH_H__