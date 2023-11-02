/*
	Copyright (c) 2023, VeriSign, Inc.
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

/*****************************************************************
* Create MTL Auth Path from a memory buffer
******************************************************************
 * @param buffer:     Memory buffer
 * @param hash_size:  Length of hash algorithm output in bytes
 * @param sid_len:    Lenght of the Series ID in bytes
 * @param randomized: 0 if not randomized, 1 if message was
 * @param auth_path:   Pointer to where the auth path is created
 * @return size of the authpath buffer in bytes
 */
uint32_t mtl_auth_path_from_buffer(char *buffer, uint32_t hash_size,
				   uint16_t sid_len, RANDOMIZER ** randomizer,
				   AUTHPATH ** auth_path)
{
	uint32_t sig_size = 0;
	uint8_t *sig_ptr = NULL;
	AUTHPATH *path = NULL;
	RANDOMIZER *mtl_rand = NULL;

	if ((auth_path == NULL) || (buffer == NULL) ||
	    (hash_size == 0) || (sid_len == 0) || (randomizer == NULL)) {
		LOG_ERROR("Bad Function Parameters");
		return 0;
	}

	sig_size = 16 + sid_len;
	sig_ptr = (uint8_t *) buffer;
	path = calloc(1, sizeof(AUTHPATH));
	mtl_rand = calloc(1, sizeof(RANDOMIZER));

	// Randomizer Auth from draft-harvey-cfrg-mtl-mode-00 Section 9.4
	mtl_rand->value = malloc(hash_size);
	mtl_rand->length = hash_size;
	memcpy(mtl_rand->value, sig_ptr, hash_size);
	sig_ptr += hash_size;
	sig_size += hash_size;

	// Authentication Path from draft-harvey-cfrg-mtl-mode-00 Section 7.3
	// Flags (2)
	sig_ptr += bytes_to_uint16(sig_ptr, &path->flags);

	// SID (Variable - 8 set by scheme)
	path->sid.length = sid_len;
	memcpy(path->sid.id, sig_ptr, sid_len);
	sig_ptr += sid_len;

	// Leaf Index (4)
	sig_ptr += bytes_to_uint32(sig_ptr, &path->leaf_index);

	// Rung Left (4)
	sig_ptr += bytes_to_uint32(sig_ptr, &path->rung_left);

	// Rung Right (4)
	sig_ptr += bytes_to_uint32(sig_ptr, &path->rung_right);

	// Sibiling Node Count (2)
	sig_ptr += bytes_to_uint16(sig_ptr, &path->sibling_hash_count);

	// Sibiling Hash Values (*)
	path->sibling_hash = malloc(path->sibling_hash_count * hash_size);
	memcpy(path->sibling_hash, sig_ptr,
	       path->sibling_hash_count * hash_size);
	sig_ptr += path->sibling_hash_count * hash_size;
	sig_size += path->sibling_hash_count * hash_size;

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
	// Buffer size has 16 fixed length bytes and several variable sizes
	sig_size =
	    16 + hash_size + auth_path->sid.length +
	    (auth_path->sibling_hash_count * hash_size);
	sig_buffer = malloc(sig_size);
	sig_ptr = sig_buffer;

	// Randomizer Auth from draft-harvey-cfrg-mtl-mode-00 Section 9.4
	memcpy(sig_ptr, randomizer->value, randomizer->length);
	sig_ptr += hash_size;
	// Authentication Path from draft-harvey-cfrg-mtl-mode-00 Section 7.3
	// Flags (2)
	sig_ptr += uint16_to_bytes(sig_ptr, auth_path->flags);

	// SID (Variable - 8 set by scheme)
	memcpy(sig_ptr, auth_path->sid.id, auth_path->sid.length);
	sig_ptr += auth_path->sid.length;

	// Leaf Index (4)
	sig_ptr += uint32_to_bytes(sig_ptr, auth_path->leaf_index);

	// Rung Left (4)
	sig_ptr += uint32_to_bytes(sig_ptr, auth_path->rung_left);

	// Rung Right (4)
	sig_ptr += uint32_to_bytes(sig_ptr, auth_path->rung_right);

	// Sibiling Node Count (2)
	sig_ptr += uint16_to_bytes(sig_ptr, auth_path->sibling_hash_count);

	// Sibiling Hash Values (*)
	memcpy(sig_ptr, auth_path->sibling_hash,
	       auth_path->sibling_hash_count * hash_size);

	*buffer = sig_buffer;
	return sig_size;
}

/*****************************************************************
* Create MTL Ladder from memory buffer
******************************************************************
 * @param buffer:     Pointer to the buffer to convert
 * @param hash_size:  Length of hash algorithm output in bytes
 * @param sid_len:    Size of the MTL Series Id
 * @param ladder_ptr: Pointer to where the ladder is created
 * @return size of the authpath buffer in bytes
 */
uint32_t mtl_ladder_from_buffer(char *buffer, uint32_t hash_size,
				uint16_t sid_len, LADDER ** ladder_ptr)
{
	if ((buffer == NULL) || (hash_size == 0) || (sid_len == 0)
	    || (ladder_ptr == NULL)) {
		LOG_ERROR("NULL Parameters");
		return 0;
	}

	uint32_t ladder_size = 4;
	uint8_t *sig_ptr = (uint8_t *) buffer;
	LADDER *ladder = malloc(sizeof(AUTHPATH));
	uint16_t i;
	RUNG *rung;

	// Ladder from draft-harvey-cfrg-mtl-mode-00 Section 7.1
	// Flags (2)
	sig_ptr += bytes_to_uint16(sig_ptr, &ladder->flags);

	// SID (Variable - 8 set by scheme)
	ladder->sid.length = sid_len;
	memcpy(ladder->sid.id, sig_ptr, sid_len);
	sig_ptr += sid_len;
	ladder_size += sid_len;

	// Rung Count (2)
	sig_ptr += bytes_to_uint16(sig_ptr, &ladder->rung_count);

	// Rung from draft-harvey-cfrg-mtl-mode-00 Section 7.2
	ladder->rungs = malloc(8 * hash_size * ladder->rung_count);
	for (i = 0; i < ladder->rung_count; i++) {
		rung =
		    (RUNG *) ((uint8_t *) ladder->rungs + (sizeof(RUNG) * i));

		rung->hash_length = hash_size;
		sig_ptr += bytes_to_uint32(sig_ptr, &rung->left_index);
		ladder_size += 4;

		// Right Index (4)
		sig_ptr += bytes_to_uint32(sig_ptr, &rung->right_index);
		ladder_size += 4;

		// Randomizer (Hash Size)
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
	uint32_t sig_size;
	uint8_t *sig_ptr;
	uint8_t *sig_buffer;
	uint16_t index;
	RUNG *rung;

	if ((ladder == NULL) || (hash_size == 0) || (buffer == NULL)) {
		LOG_ERROR("NULL Parameters");
		return 0;
	}

	sig_size =
	    4 + ladder->sid.length + ((8 + hash_size) * ladder->rung_count);
	sig_buffer = malloc(sig_size);
	sig_ptr = sig_buffer;

	// Ladder from draft-harvey-cfrg-mtl-mode-00 Section 7.1
	// Flags (2)
	sig_ptr += uint16_to_bytes(sig_ptr, ladder->flags);

	// SID (Variable - 8 set by scheme)
	memcpy(sig_ptr, ladder->sid.id, ladder->sid.length);
	sig_ptr += ladder->sid.length;

	// Rung Count (2)
	sig_ptr += uint16_to_bytes(sig_ptr, ladder->rung_count);

	// Rung from draft-harvey-cfrg-mtl-mode-00 Section 7.2
	// Rungs        
	for (index = 0; index < ladder->rung_count; index++) {
		rung =
		    (RUNG *) ((uint8_t *) ladder->rungs +
			      (sizeof(RUNG) * index));

		// Rung Left (4)
		sig_ptr += uint32_to_bytes(sig_ptr, rung->left_index);

		// Rung Right (4)
		sig_ptr += uint32_to_bytes(sig_ptr, rung->right_index);

		memcpy(sig_ptr, rung->hash, hash_size);
		sig_ptr += hash_size;
	}

	*buffer = sig_buffer;
	return sig_size;
}
