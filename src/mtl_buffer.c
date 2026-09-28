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

#include "mtl_error.h"
#include "mtl_node_set.h"
#include "mtl.h"
#include "mtl_util.h"

#define VERIFY_AUTH_BUFFER_LEN(ptr, size, end, temp, temp_rand, ret)  	if(ptr + size > end) { LOG_ERROR("AUTH Path Buffer is insufficent length"); mtl_authpath_free(temp); mtl_randomizer_free(temp_rand); *ret = NULL; return 0; } 
#define VERIFY_LADDER_BUFFER_LEN(ptr, size, end, temp, ret)  	if(ptr + size > end) { LOG_ERROR("LADDER Buffer is insufficent length"); mtl_ladder_free(temp); *ret = NULL; return 0; } 

/*****************************************************************
* Create MTL Auth Path from a memory buffer
******************************************************************
 * @param buffer:     Memory buffer
 * @param hash_size:  Length of hash algorithm output in bytes
 * @param randomizer: Pointer to where the randomizer is created
 * @param auth_path:   Pointer to where the auth path is created
 * @return size of the authpath buffer in bytes
 */
uint32_t mtl_auth_path_from_buffer(uint8_t *buffer, size_t buffer_size,
					uint32_t hash_size, 
					RANDOMIZER ** randomizer, AUTHPATH ** auth_path)
{
	uint32_t sig_size = 0;
	uint8_t *sig_ptr = NULL;
	AUTHPATH *path = NULL;
	RANDOMIZER *mtl_rand = NULL;
	uint8_t *sig_end_ptr = NULL;
	size_t sibling_hash_length = 0;

	if ((auth_path == NULL) || (buffer == NULL) ||
	    (hash_size == 0) || (randomizer == NULL)) {
		LOG_ERROR("Bad Function Parameters");
		return 0;
	}
	uint16_t sid_len = hash_size * 2;

	sig_ptr = (uint8_t *) buffer;
	sig_end_ptr = sig_ptr + buffer_size;
	path = calloc(1, sizeof(AUTHPATH));
	mtl_rand = calloc(1, sizeof(RANDOMIZER));
	if (path == NULL || mtl_rand == NULL) {
		LOG_ERROR("Unable to allocate path and randomizer");
		return 0;
	}

	// Authentication Path from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.1
	// Flags (2)
	VERIFY_AUTH_BUFFER_LEN	(sig_ptr, sizeof(path->flags), sig_end_ptr, path, mtl_rand, auth_path);
	sig_ptr += bytes_to_uint16(sig_ptr, &path->flags);
	sig_size += sizeof(path->flags);

	// SID (Variable - set by scheme)
	path->sid.length = sid_len;
	VERIFY_AUTH_BUFFER_LEN	(sig_ptr, sid_len, sig_end_ptr, path, mtl_rand, auth_path);
	memcpy(path->sid.id, sig_ptr, sid_len);
	sig_ptr += sid_len;
	sig_size += sid_len;

	// Randomizer from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.1
	mtl_rand->value = malloc(hash_size);
	if (mtl_rand->value == NULL) {
		LOG_ERROR("Unable to allocate space for randomizer auth");
		return 0;
	}
	mtl_rand->length = hash_size;
	VERIFY_AUTH_BUFFER_LEN	(sig_ptr, hash_size, sig_end_ptr, path, mtl_rand, auth_path);
	memcpy(mtl_rand->value, sig_ptr, hash_size);
	sig_ptr += mtl_rand->length;
	sig_size += mtl_rand->length;

	// Leaf Index (8)
	VERIFY_AUTH_BUFFER_LEN	(sig_ptr, sizeof(MTL_INDEX), sig_end_ptr, path, mtl_rand, auth_path);	
	sig_ptr += bytes_to_mtl_index(sig_ptr, &path->leaf_index);
	sig_size += sizeof(MTL_INDEX);

	// Rung Left (8)
	VERIFY_AUTH_BUFFER_LEN	(sig_ptr, sizeof(MTL_INDEX), sig_end_ptr, path, mtl_rand, auth_path);	
	sig_ptr += bytes_to_mtl_index(sig_ptr, &path->rung_left);
	sig_size += sizeof(MTL_INDEX);

	// Rung Right (8)
	VERIFY_AUTH_BUFFER_LEN	(sig_ptr, sizeof(MTL_INDEX), sig_end_ptr, path, mtl_rand, auth_path);	
	sig_ptr += bytes_to_mtl_index(sig_ptr, &path->rung_right);
	sig_size += sizeof(MTL_INDEX);

	// Sibiling Node Count (2)
	VERIFY_AUTH_BUFFER_LEN	(sig_ptr, 2, sig_end_ptr, path, mtl_rand, auth_path);	
	sig_ptr += bytes_to_uint16(sig_ptr, &path->sibling_hash_count);
	sig_size += 2;

	// Sibiling Hash Values (*)
	sibling_hash_length = (size_t)path->sibling_hash_count *
	                      (size_t)hash_size;
	VERIFY_AUTH_BUFFER_LEN	(sig_ptr, sibling_hash_length, sig_end_ptr, path, mtl_rand, auth_path);
	path->sibling_hash = malloc(sibling_hash_length);
	if(path->sibling_hash == NULL) {
		LOG_ERROR("Unable allocate path buffer space");
		return 0;
	}
	memcpy(path->sibling_hash, sig_ptr, sibling_hash_length);
	sig_ptr += sibling_hash_length;
	sig_size += sibling_hash_length;

	*auth_path = path;
	*randomizer = mtl_rand;
	return sig_size;
}

/*****************************************************************
* Create memory buffer from MTL Auth Path
******************************************************************
 * @param randomizer: Pointer to the randomizer value for this node
 * @param auth_path:  Pointer to the auth path to convert
 * @param hash_size:  Length of hash algorithm output in bytes
 * @param buffer:     Pointer to where the buffer is created
 * @return size of the authpath buffer in bytes
 */
uint32_t mtl_auth_path_to_buffer(RANDOMIZER * randomizer, AUTHPATH * auth_path,
				 uint32_t hash_size, uint8_t ** buffer)
{
	uint32_t sig_size;
	uint8_t *sig_ptr;
	uint8_t *sig_buffer;
	size_t sibling_hash_length = 0;

	if ((auth_path == NULL) || (randomizer == NULL) || (buffer == NULL)
	    || (hash_size == 0)) {
		LOG_ERROR("NULL Parameters");
		return 0;
	}

	if (((auth_path->sibling_hash_count * hash_size) > 0) &&
	    (auth_path->sibling_hash == NULL)) {
		LOG_ERROR("Bad Hash Path Parameters");
		return 0;
	}
	if (randomizer->length != hash_size) {
		LOG_ERROR("Bad Hash Path Parameters");
		return 0;
	}

	// Condensed signature from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.1
	// Condensed Sig = flags + SID + randomizer + leaf index + target left index 
	//  + target right index + sibling count + list of siblings 
	sig_size =
	    sizeof(auth_path->flags) + auth_path->sid.length + randomizer->length
		+ 3 * sizeof(MTL_INDEX) + sizeof(auth_path->sibling_hash_count)
	    + (auth_path->sibling_hash_count * hash_size);
	sig_buffer = malloc(sig_size);
	if(sig_buffer == NULL) {
		LOG_ERROR("Unable to allocate buffer memory");
		return 0;
	}	
	sig_ptr = sig_buffer;

	// Authentication Path from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.1
	// Flags (2)
	sig_ptr += uint16_to_bytes(sig_ptr, auth_path->flags);

	// SID (Variable - set by scheme)
	memcpy(sig_ptr, auth_path->sid.id, auth_path->sid.length);
	sig_ptr += auth_path->sid.length;

	// Randomizer from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.1
	memcpy(sig_ptr, randomizer->value, randomizer->length);
	sig_ptr += randomizer->length;

	// Leaf Index (8)
	sig_ptr += mtl_index_to_bytes(sig_ptr, auth_path->leaf_index);

	// Rung Left (8)
	sig_ptr += mtl_index_to_bytes(sig_ptr, auth_path->rung_left);

	// Rung Right (8)
	sig_ptr += mtl_index_to_bytes(sig_ptr, auth_path->rung_right);

	// Sibiling Node Count (2)
	sig_ptr += uint16_to_bytes(sig_ptr, auth_path->sibling_hash_count);

	// Sibiling Hash Values (*)
	sibling_hash_length = (size_t)auth_path->sibling_hash_count * 
	                      (size_t)hash_size;
	memcpy(sig_ptr, auth_path->sibling_hash, sibling_hash_length);

	*buffer = sig_buffer;
	return sig_size;
}

/*****************************************************************
* Create MTL Ladder from memory buffer
******************************************************************
 * @param buffer:     Pointer to the buffer to convert
 * @param buffer_size Memory buffer size 
 * @param hash_size:  Length of hash algorithm output in bytes
 * @param ladder_ptr: Pointer to where the ladder is created
 * @return size of the ladder in bytes
 */
uint32_t mtl_ladder_from_buffer(uint8_t *buffer, size_t buffer_size,
				uint32_t hash_size, LADDER ** ladder_ptr)
{
	if ((buffer == NULL) || (hash_size == 0) 
	    || (ladder_ptr == NULL)) {
		LOG_ERROR("NULL Parameters");
		return 0;
	}
	uint16_t sid_len = 2*hash_size;

	uint32_t ladder_size = 0;
	uint8_t *sig_ptr = (uint8_t *) buffer;
	uint8_t *sig_end_ptr = sig_ptr + buffer_size;	
	LADDER *ladder = calloc(1,sizeof(LADDER));
	if (ladder == NULL) {
		LOG_ERROR("Unable to allocate ladder buffer");
		return 0;
	}
	uint16_t i;
	RUNG *rung;
	size_t rung_hash_length = 0;

	// Ladder from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1
	// Flags (2)
	VERIFY_LADDER_BUFFER_LEN(sig_ptr, sizeof(ladder->flags), sig_end_ptr, ladder, ladder_ptr);	
	sig_ptr += bytes_to_uint16(sig_ptr, &ladder->flags);
	ladder_size += sizeof(ladder->flags);

	// SID (Variable - set by scheme)
	ladder->sid.length = sid_len;
	VERIFY_LADDER_BUFFER_LEN(sig_ptr, sid_len, sig_end_ptr, ladder, ladder_ptr);	
	memcpy(ladder->sid.id, sig_ptr, sid_len);
	sig_ptr += sid_len;
	ladder_size += sid_len;

	// Rung Count (2)
	VERIFY_LADDER_BUFFER_LEN(sig_ptr, sizeof(ladder->rung_count), sig_end_ptr, ladder, ladder_ptr);	
	sig_ptr += bytes_to_uint16(sig_ptr, &ladder->rung_count);
	ladder_size += sizeof(ladder->rung_count);

	// Rung from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1
	rung_hash_length = sizeof(RUNG) * (size_t)ladder->rung_count;
	ladder->rungs = malloc(rung_hash_length);
	if (ladder->rungs == NULL) {
		LOG_ERROR("Failed to allocate rung");
		return 0;
	}
	for (i = 0; i < ladder->rung_count; i++) {
		rung =
		    (RUNG *) ((uint8_t *) ladder->rungs + (sizeof(RUNG) * i));

		// Left Index (8)
		rung->hash_length = hash_size;
		VERIFY_LADDER_BUFFER_LEN(sig_ptr, sizeof(MTL_INDEX), sig_end_ptr, ladder, ladder_ptr);	
		sig_ptr += bytes_to_mtl_index(sig_ptr, &rung->left_index);
		ladder_size += sizeof(MTL_INDEX);

		// Right Index (8)
		VERIFY_LADDER_BUFFER_LEN(sig_ptr, sizeof(MTL_INDEX), sig_end_ptr, ladder, ladder_ptr);	
		sig_ptr += bytes_to_mtl_index(sig_ptr, &rung->right_index);
		ladder_size += sizeof(MTL_INDEX);

		// Rung's Hash
		VERIFY_LADDER_BUFFER_LEN(sig_ptr, hash_size, sig_end_ptr, ladder, ladder_ptr);	
		memcpy(rung->hash, sig_ptr, hash_size);
		sig_ptr += hash_size;
		ladder_size += hash_size;
	}

	*ladder_ptr = ladder;
	return ladder_size;
}

/*****************************************************************
* Create memory buffer from MTL Ladder
******************************************************************
 * @param Ladder:     Pointer to the ladder to convert
 * @param hash_size:  Length of hash algorithm output in bytes
 * @param buffer:     Pointer to where the buffer is created
 * @return size of the ladder buffer in bytes
 */
uint32_t mtl_ladder_to_buffer(LADDER * ladder, uint32_t hash_size,
			      uint8_t ** buffer)
{
	uint32_t expected_sig_size;
	uint32_t sig_size = 0;
	uint8_t *sig_ptr;
	uint8_t *sig_buffer;
	uint16_t index;
	RUNG *rung;

	if ((ladder == NULL) || (hash_size == 0) || (buffer == NULL)) {
		LOG_ERROR("NULL Parameters");
		return 0;
	}

	if ((ladder->sid.length > 64) || (hash_size > 32)
		|| (ladder->sid.length != hash_size * 2) ) {
		// The hash size and SID should not be more than 512 bits
		LOG_ERROR("Invalid hash length and/or SID length");
		return 0;		
	}
	
	// draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1 
	// Ladder = flags + SID + rung count + rungs
	expected_sig_size = sizeof(ladder->flags) + 2*hash_size 
							+ sizeof(ladder->rung_count) 
							// rung = left index + right index + hash
							+ (ladder->rung_count * ( 2*sizeof(MTL_INDEX) + hash_size));
	
	sig_buffer = malloc(expected_sig_size);
	if(sig_buffer == NULL) {
		LOG_ERROR("Unable to allocate buffer memory");
		return 0;
	}
	sig_ptr = sig_buffer;

	// Ladder from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1
	// Flags (2)
	sig_ptr += uint16_to_bytes(sig_ptr, ladder->flags);
	sig_size += sizeof(ladder->flags);

	// SID (Variable - set by scheme)
	memcpy(sig_ptr, ladder->sid.id, ladder->sid.length);
	sig_ptr += ladder->sid.length;
	sig_size += ladder->sid.length;

	// Rung Count (2)
	sig_ptr += uint16_to_bytes(sig_ptr, ladder->rung_count);
	sig_size += sizeof(ladder->rung_count);

	// Rung from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1
	// Rungs        
	for (index = 0; index < ladder->rung_count; index++) {
		rung =
		    (RUNG *) ((uint8_t *) ladder->rungs +
			      (sizeof(RUNG) * index));

		// Rung Left (4)
		sig_ptr += mtl_index_to_bytes(sig_ptr, rung->left_index);
		sig_size += sizeof(MTL_INDEX);

		// Rung Right (4)
		sig_ptr += mtl_index_to_bytes(sig_ptr, rung->right_index);
		sig_size += sizeof(MTL_INDEX);

		memcpy(sig_ptr, rung->hash, hash_size);
		sig_ptr += hash_size;
		sig_size += hash_size;
	}

	*buffer = sig_buffer;
	return sig_size;
}
