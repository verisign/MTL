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
#include <stdint.h>
#include "mtl.h"

/**
 * Mock function for message hashing operations:
 * return 0
 */
MTLSTATUS mtl_test_hash_msg(void *parameters,
			  SERIESID * sid,
			  uint32_t node_id,
			  uint8_t * randomizer,
			  uint32_t randomizer_len,
			  uint8_t * msg_buffer,
			  uint32_t msg_length, uint8_t * hash,
			  uint32_t hash_length, char * ctx,
			  uint8_t ** rmtl, uint32_t * rmtl_len)
{
	// for these tests these parameters are not used
	parameters = parameters;
	sid = sid;
	node_id = node_id;
	randomizer = randomizer;
	randomizer_len = randomizer_len;
	msg_buffer = msg_buffer;
	msg_length = msg_length;
	ctx = ctx;
	rmtl = rmtl;
	rmtl_len = rmtl_len;

	memset(hash, 0, hash_length);
	return MTL_OK;
						
}

/**
 * Mock function for leaf hashing operations:
 * first hash_len bytes of message
 */
MTLSTATUS mtl_test_hash_leaf(SERIESID * sid,
				      	MTL_INDEX node_index,
				      	uint8_t * msg_buffer, uint32_t msg_len,
					  	uint8_t * ctx, uint32_t ctx_len,
				      	uint8_t * rand, uint32_t rand_len,
				      	uint8_t * hash_out, uint32_t hash_len)
{
	sid = sid;
	node_index = node_index;
	msg_buffer = msg_buffer;
	msg_len = msg_len;
	ctx = ctx;
	ctx_len = ctx_len;
	rand = rand;
	rand_len = rand_len;
			
	memcpy(hash_out, msg_buffer, hash_len);
	return MTL_OK;
						
}

/**
 * Mock function for internal hashing operations:
 * XOR of both child nodes
 */
MTLSTATUS mtl_test_hash_int(SERIESID * sid,
				  		uint32_t adrs_left,
				  		uint32_t adrs_right,
				  		uint8_t * hash_left,
				  		uint8_t * hash_right, uint8_t * hash_out,
				  		uint32_t hash_len)
{
	// for these tests these parameters are not used
	sid = sid;
	adrs_left = adrs_left;
	adrs_right = adrs_right;
		
	memcpy(hash_out, hash_left, hash_len);
	uint32_t i;
	for( i = 0; i < hash_len; i++ ) { 
		hash_out[i] ^= hash_right[i];
	}
	return MTL_OK;
}
