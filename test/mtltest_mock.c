/*
	Copyright (c) 2024, VeriSign, Inc.
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
 * Mock function for message hashing operations
 */
uint8_t mtl_test_hash_msg(void *parameters,
			  SERIESID * sid,
			  uint32_t node_id,
			  uint8_t * randomizer,
			  uint32_t randomizer_len,
			  uint8_t * msg_buffer,
			  uint32_t msg_length, uint8_t * hash,
			  uint32_t hash_length, char * ctx,
			  uint8_t ** rmtl, uint32_t * rmtl_len)
{
	EVP_MD *hash_func = NULL;
	EVP_MD_CTX *mdctx = NULL;
	unsigned int hash_len;
	uint8_t * rmtl_buffer;
	// for these tests these parameters are not used
	sid = sid;
	node_id = node_id;
	ctx=ctx;

	parameters = parameters;
	hash_length = hash_length;

	hash_func = (EVP_MD *) EVP_sha256();
	mdctx = EVP_MD_CTX_new();

	if (1 != EVP_DigestInit_ex(mdctx, hash_func, NULL)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to allocate hash function");
		// ERROR                
		return 1;
	}
	if (1 != EVP_DigestUpdate(mdctx, randomizer, randomizer_len)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable add message to digest");
		// ERROR                
		return 1;
	}
	if (1 != EVP_DigestUpdate(mdctx, msg_buffer, msg_length)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable add message to digest");
		// ERROR                
		return 1;
	}
	if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to finalize digest");
		// ERROR                
		return 1;
	}

	if(*rmtl_len == 0) {
		rmtl_buffer = malloc(randomizer_len);
		memcpy(rmtl_buffer, randomizer, randomizer_len);
		*rmtl = rmtl_buffer;
		*rmtl_len = randomizer_len;
	}

	EVP_MD_CTX_free(mdctx);
	return 0;
}

/**
 * Mock function for leaf hashing operations
 */
uint8_t mtl_test_hash_leaf(void *params,
			   SERIESID * sid,
			   uint32_t node_id,
			   uint8_t * msg_buffer,
			   uint32_t msg_length,
			   uint8_t * hash, uint32_t hash_length)
{
	EVP_MD *hash_func = NULL;
	EVP_MD_CTX *mdctx = NULL;
	unsigned int hash_len;
	hash_length = hash_length;
	uint8_t tmp[4];

	params = params;
	sid = sid;
	node_id = node_id;

	hash_func = (EVP_MD *) EVP_sha256();
	mdctx = EVP_MD_CTX_new();

	if (1 != EVP_DigestInit_ex(mdctx, hash_func, NULL)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to allocate hash function");
		// ERROR                
		return 1;
	}
	memcpy(&tmp[0], &node_id, 4);
	if (1 != EVP_DigestUpdate(mdctx, tmp, 4)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable add message to digest");
		// ERROR                
		return 1;
	}
	if (1 != EVP_DigestUpdate(mdctx, msg_buffer, msg_length)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable add message to digest");
		// ERROR                
		return 1;
	}
	if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to finalize digest");
		// ERROR                
		return 1;
	}

	EVP_MD_CTX_free(mdctx);
	return 0;
}

/**
 * Mock function for internal hashing operations
 */
uint8_t mtl_test_hash_node(void *params,
			   SERIESID * sid,
			   uint32_t left_index,
			   uint32_t right_index,
			   uint8_t * left_hash,
			   uint8_t * right_hash,
			   uint8_t * hash, uint32_t hash_length)
{
	EVP_MD *hash_func = NULL;
	EVP_MD_CTX *mdctx = NULL;
	unsigned int hash_len;
	uint8_t tmp[4];

	params = params;
	left_index = left_index;
	right_index = right_index;
	sid = sid;

	hash_func = (EVP_MD *) EVP_sha256();
	mdctx = EVP_MD_CTX_new();

	if (1 != EVP_DigestInit_ex(mdctx, hash_func, NULL)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to allocate hash function");
		// ERROR                
		return 1;
	}
	memcpy(&tmp[0], &left_index, 4);
	if (1 != EVP_DigestUpdate(mdctx, tmp, 4)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable add message to digest");
		// ERROR                
		return 1;
	}
	memcpy(&tmp[0], &right_index, 4);
	if (1 != EVP_DigestUpdate(mdctx, tmp, 4)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable add message to digest");
		// ERROR                
		return 1;
	}
	if (1 != EVP_DigestUpdate(mdctx, left_hash, hash_length)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable add message to digest");
		// ERROR                
		return 1;
	}
	if (1 != EVP_DigestUpdate(mdctx, right_hash, hash_length)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable add message to digest");
		// ERROR                
		return 1;
	}
	if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to finalize digest");
		// ERROR  
		return 1;
	}

	EVP_MD_CTX_free(mdctx);
	return 0;
}
