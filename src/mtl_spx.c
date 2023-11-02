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
#include <arpa/inet.h>
#include <math.h>
#include <openssl/hmac.h>
#include <string.h>

#include "mtl_error.h"
#include "mtl_util.h"
#include "spx_funcs.h"
#include "mtl_spx.h"

#define BUFFER_APPEND(ptr, offset, data, datalen)  {memcpy(ptr + offset, data, datalen); offset += datalen;}

/*****************************************************************
* MTL Node Set generate message PRF SHA2 values
******************************************************************
 * @param skprf:       secret key prf data pointer
 * @param skprf_len:   secret key prf data length
 * @param optrand:     msg rand buffer data pointer
 * @param optrand_len: msg rand buffer data length
 * @param addrs:       address field buffer
 * @param addrs_len:   address field buffer length
 * @param message:     message buffer data pointer
 * @param message_len: message buffer data length
 * @param rmtl:        output of the prf function
 * @param hash_len:    length of the hash for the scheme
 * @return 0 on success, integer on failure
 */
uint8_t spx_mtl_node_set_prf_msg_sha2(uint8_t * skprf, uint32_t skprf_len,
				      uint8_t * optrand, uint32_t optrand_len,
				      uint8_t * message, uint32_t message_len,
				      uint8_t * rmtl, uint32_t hash_len)
{
	uint32_t rmtl_len = 0;
	const EVP_MD *h_func = NULL;
	uint8_t *buffer = NULL;
	uint32_t buffer_offset = 0;

	if ((skprf == NULL) || (skprf_len == 0) ||
	    (optrand == NULL) || (optrand_len == 0) ||
	    (message == NULL) || (message_len == 0) || (hash_len == 0)) {
		LOG_ERROR("Invalid parameters");
		return 1;
	}
	// SHA2 PRF_msg from draft-harvey-cfrg-mtl-mode-00 Section 10.2.2
	// PRF_msg(SK.prf, OptRand, M) = HMAC-SHA-X(SK.prf, OptRand || M)
	buffer = calloc(1, optrand_len + message_len);
	BUFFER_APPEND(buffer, buffer_offset, optrand, optrand_len);
	BUFFER_APPEND(buffer, buffer_offset, message, message_len);

	if (hash_len <= 16) {
		h_func = EVP_sha256();
	} else {
		h_func = EVP_sha512();
	}

	if (HMAC(h_func, skprf, skprf_len, buffer, optrand_len + message_len,
		 rmtl, &rmtl_len) == NULL) {
		LOG_ERROR("HMAC Failure");
		free(buffer);
		return 2;
	}

	free(buffer);
	return 0;
}

/*****************************************************************
* MTL Node Set generate message PRF SHAKE values
******************************************************************
 * @param skprf:       secret key prf data pointer
 * @param skprf_len:   secret key prf data length
 * @param optrand:     msg rand buffer data pointer
 * @param optrand_len: msg rand buffer data length
 * @param addrs:       address field buffer
 * @param addrs_len:   address field buffer length
 * @param message:     message buffer data pointer
 * @param message_len: message buffer data length
 * @param rmtl:        output of the prf function
 * @param hash_len:    length of the hash for the scheme
 * @return 0 on success, integer on failure
 */
uint8_t spx_mtl_node_set_prf_msg_shake(uint8_t * skprf, uint32_t skprf_len,
				       uint8_t * optrand, uint32_t optrand_len,
				       uint8_t * message, uint32_t message_len,
				       uint8_t * rmtl, uint32_t hash_len)
{
	uint8_t *buffer;
	uint32_t buffer_len;
	uint32_t buffer_offset = 0;

	if ((skprf == NULL) || (skprf_len == 0) ||
	    (optrand == NULL) || (optrand_len == 0) ||
	    (message == NULL) || (message_len == 0) || (hash_len == 0)) {
		LOG_ERROR("Invalid parameters");
		return 1;
	}
	// SHA2 PRF_msg from draft-harvey-cfrg-mtl-mode-00 Section 10.1.2
	// PRF_msg(SK.prf, OptRand, M) = SHAKE256(SK.prf || OptRand || M, 8n)
	buffer_len = skprf_len + optrand_len + message_len;
	buffer = calloc(1, buffer_len);
	BUFFER_APPEND(buffer, buffer_offset, skprf, skprf_len);
	BUFFER_APPEND(buffer, buffer_offset, optrand, optrand_len);
	BUFFER_APPEND(buffer, buffer_offset, message, message_len);

	shake256(rmtl, buffer, buffer_len, hash_len);
	free(buffer);

	return 0;

}

/*****************************************************************
* Build the ADRS structure in compressed format
******************************************************************
 * @param mtl_adrs:  Bytes array to hold the ADRS structure
 * @param type:  single byte ADRS type
 * @param addrs: ADRS tree address data (8 bytes when compressed)
 * @param left:  MTL tree address left value
 * @param right: MTL tree address right value 
 * @return None
 */
uint8_t mtlns_adrs_compressed(uint8_t * mtl_adrs, uint8_t type, SERIESID * sid,
			      uint32_t left, uint32_t right)
{
	uint16_t sid_offset = 0;

	memset(mtl_adrs, 0, ADRS_ADDR_SIZE_C);
	// ADRS - Type (Normally 4 bytes but only 1 when compressed)
	mtl_adrs[ADRS_TYPE_ADDR_C] = (uint8_t) type;

	// ADRS - SID (12 bytes in this situation but only 8 when compressed)
	if (sid->length >= ADRS_TREE_ADDR_C_LEN) {
		memcpy(&((uint8_t *) mtl_adrs)[ADRS_TREE_ADDR_C], sid->id,
		       ADRS_TREE_ADDR_C_LEN);
	} else {
		sid_offset = ADRS_TREE_ADDR_C_LEN - sid->length;
		memcpy(&((uint8_t *) mtl_adrs)[ADRS_TREE_ADDR_C + sid_offset],
		       sid->id, sid->length);
	}

	// ADRS - Node ID
	uint32_to_bytes(&((uint8_t *) mtl_adrs)[ADRS_ADDR_2_C], left);
	uint32_to_bytes(&((uint8_t *) mtl_adrs)[ADRS_ADDR_3_C], right);

	return ADRS_ADDR_SIZE_C;
}

/*****************************************************************
* Build the ADRS structure in uncompressed format
******************************************************************
 * @param mtl_adrs:  Bytes array to hold the ADRS structure
 * @param type:  single byte ADRS type
 * @param addrs: ADRS tree address data (8 bytes when compressed)
 * @param left:  MTL tree address left value
 * @param right: MTL tree address right value 
 * @return None
 */
uint8_t mtlns_adrs_full(uint8_t * mtl_adrs, uint32_t type, SERIESID * sid,
			uint32_t left, uint32_t right)
{
	uint16_t sid_offset = 0;

	memset(mtl_adrs, 0, ADRS_ADDR_SIZE);
	// ADRS - Type
	uint32_to_bytes(&((uint8_t *) mtl_adrs)[ADRS_TYPE_ADDR], type);
	// ADRS - SID (12 bytes in this situation but only 8 when compressed)
	if (sid->length >= ADRS_TREE_ADDR_LEN) {
		memcpy(&((uint8_t *) mtl_adrs)[ADRS_TREE_ADDR], sid->id,
		       ADRS_TREE_ADDR_LEN);
	} else {
		sid_offset = ADRS_TREE_ADDR_LEN - sid->length;
		memcpy(&((uint8_t *) mtl_adrs)[ADRS_TREE_ADDR + sid_offset],
		       sid->id, sid->length);
	}

	// ADRS - Node ID
	uint32_to_bytes(&((uint8_t *) mtl_adrs)[ADRS_ADDR_2], left);
	uint32_to_bytes(&((uint8_t *) mtl_adrs)[ADRS_ADDR_3], right);

	return ADRS_ADDR_SIZE;
}

/*****************************************************************
* Perform the SHA2 hashing for tree leaves (internal or leaf)
******************************************************************
 * @param seed:     SPHINCS+ public key seed 
 * @param seed_len: Length of the SPHNICS+ public key
 * @param addrs:    Compressed ADRS tree address structure
 * @param adrs_len: Lenght of the ADRS tree address structure
 * @param data:     Data value to hash 
 * @param data_len: Length of the data value
 * @param hash:     Pointer to byte array where hash is stored
 * @param hash_len: Length of byte array
 * @return 0 if successful
 */
uint8_t spx_sha2(uint8_t * seed, uint32_t seed_len,
		 uint8_t * adrs, uint32_t adrs_len,
		 uint8_t * data, uint32_t data_len,
		 uint8_t * hash, uint32_t hash_len)
{
	uint8_t *padded_seed = NULL;
	uint32_t padded_seed_len = 0;
	uint8_t *buffer = NULL;
	size_t buffer_len = 0;
	uint32_t buffer_offset = 0;

	// BlockPad(PK.seed)
	padded_seed_len = block_pad(seed, seed_len, hash_len, &padded_seed);

	// Create the buffer that gets hashed   
	buffer_len = padded_seed_len + adrs_len + data_len;
	buffer = malloc(buffer_len);

	BUFFER_APPEND(buffer, buffer_offset, padded_seed, padded_seed_len);
	BUFFER_APPEND(buffer, buffer_offset, adrs, adrs_len);
	BUFFER_APPEND(buffer, buffer_offset, data, data_len);
	free(padded_seed);

	// Hash functionfrom draft-harvey-cfrg-mtl-mode-00 Section 10.2
	if (hash_len <= 16) {
		sha256(&hash[0], buffer, buffer_len);

	} else {
		sha512(&hash[0], buffer, buffer_len);
	}

	memset(&hash[0] + hash_len, 0, 64 - hash_len);

	free(buffer);
	return 0;
}

/*****************************************************************
* Perform the SHAKE hashing for tree leaves (internal or leaf)
******************************************************************
 * @param seed:     SPHINCS+ public key seed 
 * @param seed_len: Length of the SPHNICS+ public key
 * @param addrs:    Compressed ADRS tree address structure
 * @param adrs_len: Lenght of the ADRS tree address structure
 * @param data:     Data value to hash 
 * @param data_len: Length of the data value
 * @param hash:     Pointer to byte array where hash is stored
 * @param hash_len: Length of byte array
 * @return 0 if successful
 */
uint8_t spx_shake(uint8_t * seed, uint32_t seed_len,
		  uint8_t * adrs, uint32_t adrs_len,
		  uint8_t * data, uint32_t data_len,
		  uint8_t * hash, uint32_t hash_len)
{
	uint8_t *buffer;
	size_t buffer_len = 0;
	uint32_t buffer_offset = 0;

	// Create the buffer that gets hashed   
	buffer_len = seed_len + adrs_len + data_len;
	buffer = malloc(buffer_len);

	BUFFER_APPEND(buffer, buffer_offset, seed, seed_len);
	BUFFER_APPEND(buffer, buffer_offset, adrs, adrs_len);
	BUFFER_APPEND(buffer, buffer_offset, data, data_len);

	shake256(&hash[0], buffer, buffer_len, hash_len);

	free(buffer);
	return 0;
}

/*****************************************************************
* Hash the message set with the rand
******************************************************************
 * @param params:     SPHINCS+ public key seed & key
 * @param sid:        Series identifier for this MTL node set
 * @param node_id:    Node identifier for this message
 * @param rand:       PRF based rand for this message
 * @param rand_len:   Length of the rand byte array
 * @param msg_buffer: Byte array of the message that will be added
 * @param msg_len:    Length of the msg_buffer array
 * @param hash:       Pointer to byte array where hash is stored
 * @param hash_len:   Length of hash byte array
 * @param algorithm:  Type of algorithm used (#defined values) 
 * @return 0 if successful
 */
uint8_t spx_mtl_node_set_hash_message(void *params,
				      SERIESID * sid,
				      uint32_t node_id,
				      uint8_t * rand,
				      uint32_t rand_len,
				      uint8_t * msg_buffer, uint32_t msg_len,
				      uint8_t * hash, uint32_t hash_len,
				      uint8_t algorithm)
{
	SPX_PARAMS *spx_prop = params;
	unsigned int tmp_hash_len = 0;
	uint8_t *buffer = NULL;
	uint32_t buffer_len = 0;
	uint32_t buffer_offset = 0;
	uint8_t rmtl[EVP_MAX_MD_SIZE];
	uint32_t address_len = ADRS_ADDR_SIZE;
	uint8_t address[32] = { 0 };
	uint8_t *adrs_msg_buffer;

	if ((params == NULL) || (rand == NULL) || (rand_len == 0)
	    || (msg_buffer == NULL) || (msg_len == 0) || (hash == NULL)
	    || (hash_len == 0)) {
		LOG_ERROR("Null parameters");
		return 1;
	}
	// PRF_msg operation from draft-harvey-cfrg-mtl-mode-00 Section 5.1 
	// R_mtl = PRF_msg(SK.prf, OptRand, ADRS || M)
	// Section 5.1 and 5.2 of the draft specify the use of ADRS
	// Later section 10.X does not call this out because it is assumed
	// to be included in the message buffer at that point.
	// Construct that included buffer now.
	address_len =
	    mtlns_adrs_full((uint8_t *) & address, SPX_ADRS_MTL_MSG, sid,
			    0, node_id);
	adrs_msg_buffer = malloc(msg_len + address_len);
	memcpy(adrs_msg_buffer, address, address_len);
	memcpy(adrs_msg_buffer + address_len, msg_buffer, msg_len);

	switch (algorithm) {
	case SPX_MTL_SHA2:
		if (spx_mtl_node_set_prf_msg_sha2(spx_prop->prf.data,
						  spx_prop->prf.length, rand,
						  rand_len, adrs_msg_buffer,
						  msg_len + address_len,
						  rmtl, hash_len) != 0) {
			LOG_ERROR("Unable to generate message prf")
		}
		break;
	case SPX_MTL_SHAKE:
		if (spx_mtl_node_set_prf_msg_shake(spx_prop->prf.data,
						   spx_prop->prf.length, rand,
						   rand_len, adrs_msg_buffer,
						   msg_len + address_len, rmtl,
						   hash_len) != 0) {
			LOG_ERROR("Unable to generate message prf")
		}
		break;
	default:
		LOG_ERROR("Invalid hash algorithm")
	}

	// Signer operations from draft-harvey-cfrg-mtl-mode-00 Section 5.1 
	// data_value = H_msg_mtl(R_mtl, PK.seed, PK.root, ADRS || M)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	buffer_len =
	    rand_len + spx_prop->pk_seed.length + spx_prop->pk_root.length +
	    msg_len;
	buffer = malloc(buffer_len + EVP_MAX_MD_SIZE);
	buffer_offset = 0;

	BUFFER_APPEND(buffer, buffer_offset, rand, rand_len);
	BUFFER_APPEND(buffer, buffer_offset,
		      spx_prop->pk_seed.seed, spx_prop->pk_seed.length);
	BUFFER_APPEND(buffer, buffer_offset,
		      spx_prop->pk_root.key, spx_prop->pk_root.length);
	BUFFER_APPEND(buffer, buffer_offset, adrs_msg_buffer,
	          msg_len + address_len);

	switch (algorithm) {
	case SPX_MTL_SHA2:
		// H_msg_mtl from draft-harvey-cfrg-mtl-mode-00 Section 10.2.1 
		// hash = SHA-X(R || PK.seed || PK.root || M)
		// H_msg_mtl = MGF1-SHA-X(R || PK.seed || hash, n)
		if (hash_len <= 16) {
			sha256(&hash[0], buffer, buffer_len);
			tmp_hash_len = 32;
		} else {
			sha512(&hash[0], buffer, buffer_len);
			tmp_hash_len = 64;
		}

		buffer_len = rand_len + spx_prop->pk_seed.length + tmp_hash_len;
		buffer_offset = rand_len + spx_prop->pk_seed.length;
		BUFFER_APPEND(buffer, buffer_offset, &hash[0], tmp_hash_len);

		memset(hash, 0, EVP_MAX_MD_SIZE);
		// MGF1-SHA-X(R || PK.seed || hash, n)
		if (hash_len <= 16) {
			mgf1_256(&hash[0], hash_len, buffer, buffer_len);
		} else {
			mgf1_512(&hash[0], hash_len, buffer, buffer_len);
		}
		free(buffer);
		break;
	case SPX_MTL_SHAKE:
		// H_msg_mtl from draft-harvey-cfrg-mtl-mode-00 Section 10.1.1 
		// H_msg_mtl = SHAKE256(R || PK.seed || PK.root || M, 8n)
		shake256(&hash[0], buffer, buffer_len, hash_len);
		free(buffer);
		break;
	default:
		LOG_ERROR("Invalid hashing algorithm");
		break;
	}

	free(adrs_msg_buffer);
	return 0;
}

/*****************************************************************
* Hash the message set with the rand using SHA2 algorithms
******************************************************************
 * @param params:     SPHINCS+ public key seed & key
 * @param rand:       PRF based rand for this message
 * @param rand_len:   Length of the rand byte array
 * @param msg_buffer: Byte array of the message that will be added
 * @param msg_len:    Length of the msg_buffer array
 * @param hash:       Pointer to byte array where hash is stored
 * @param hash_len:   Length of hash byte array
 * @return 0 if successful
 */
uint8_t spx_mtl_node_set_hash_message_sha2(void *params,
					   SERIESID * sid,
					   uint32_t node_id,
					   uint8_t * rand,
					   uint32_t rand_len,
					   uint8_t * msg_buffer,
					   uint32_t msg_len, uint8_t * hash,
					   uint32_t hash_len)
{
	return spx_mtl_node_set_hash_message(params, sid, node_id, rand,
					     rand_len, msg_buffer,
					     msg_len, hash, hash_len,
					     SPX_MTL_SHA2);
}

/*****************************************************************
* Hash the message set with the rand using SHAKE algorithms
******************************************************************
 * @param params:     SPHINCS+ public key seed & key
 * @param rand:       PRF based rand for this message
 * @param rand_len:   Length of the rand byte array
 * @param msg_buffer: Byte array of the message that will be added
 * @param msg_len:    Length of the msg_buffer array
 * @param hash:       Pointer to byte array where hash is stored
 * @param hash_len:   Length of hash byte array
 * @return 0 if successful
 */
uint8_t spx_mtl_node_set_hash_message_shake(void *params,
					    SERIESID * sid,
					    uint32_t node_id,
					    uint8_t * rand,
					    uint32_t rand_len,
					    uint8_t * msg_buffer,
					    uint32_t msg_len, uint8_t * hash,
					    uint32_t hash_len)
{
	return spx_mtl_node_set_hash_message(params, sid, node_id, rand,
					     rand_len, msg_buffer,
					     msg_len, hash, hash_len,
					     SPX_MTL_SHAKE);
}

/*****************************************************************
* Algorithm 1: Hashing a Data Value to Produce a Leaf Node.
******************************************************************
 * @param params:     SPHINCS+ public key seed & key
 * @param sid:        Series ID generated for the MTL node set
 * @param node_id:     Message leaf index
 * @param msg_buffer: Byte array of the message that will be added
 * @param msg_len:    Length of the msg_buffer array
 * @param hash:       Pointer to byte array where hash is stored
 * @param hash_len:   Length of hash byte array
 * @param algorithm:  Type of algorithm used (#defined values) 
 * @return 0 if successful 
 */
uint8_t spx_mtl_node_set_hash_leaf(void *params,
				   SERIESID * sid,
				   uint32_t node_id,
				   uint8_t * msg_buffer,
				   uint32_t msg_len, uint8_t * hash,
				   uint32_t hash_len, uint8_t algorithm)
{
	uint32_t ADRSLen = 0;
	uint8_t ADRS[32] = { 0 };
	SPX_PARAMS *spx_prop = params;
	uint8_t result;
	uint8_t *bitmask = NULL;
	uint8_t *mask_buffer = NULL;
	uint32_t mask_buffer_len = 0;
	uint8_t *tmp_buffer = NULL;
	uint32_t index = 0;

	if ((msg_buffer == NULL) || (hash == NULL) || (hash_len == 0)) {
		LOG_ERROR("Null parameters");
		return 1;
	}

	switch (algorithm) {
	case SPX_MTL_SHA2:
		// Create address structure (Compressed)
		ADRSLen =
		    mtlns_adrs_compressed((uint8_t *) & ADRS, SPX_ADRS_MTL_DATA,
					  sid, node_id, node_id);
		break;
	case SPX_MTL_SHAKE:
		// Create address structure (Full)
		ADRSLen =
		    mtlns_adrs_full((uint8_t *) & ADRS, SPX_ADRS_MTL_DATA, sid,
				    node_id, node_id);
		break;
	default:
		LOG_ERROR("Invalid hashing algorithm");
		break;
	}

	// H_msg_mtl from draft-harvey-cfrg-mtl-mode-00 Section 8.2.1
	// spx.F(seed, dataADRS.bytes(), data_value)

	tmp_buffer = calloc(1, msg_len);
	// If robust variation hash address for mask and xor with data
	if (spx_prop->robust) {
		bitmask = calloc(1, msg_len);
		mask_buffer_len = spx_prop->pk_seed.length + ADRS_ADDR_SIZE_C;
		mask_buffer = calloc(1, mask_buffer_len);
		memcpy(mask_buffer, spx_prop->pk_seed.seed,
		       spx_prop->pk_seed.length);
		memcpy(mask_buffer, ADRS, ADRS_ADDR_SIZE_C);

		switch (algorithm) {
		case SPX_MTL_SHA2:
			// F from draft-harvey-cfrg-mtl-mode-00 Section 10.2.3          
			// M_1* = M_1 xor MGF1_X(PK.seed, ADRS, 8n)
			// length is already in bytes so is already 8n                  
			if (hash_len <= 16) {
				mgf1_256(bitmask, msg_len, mask_buffer,
					 mask_buffer_len);
			} else {
				mgf1_512(bitmask, msg_len, mask_buffer,
					 mask_buffer_len);
			}
			break;
		case SPX_MTL_SHAKE:
			// F from draft-harvey-cfrg-mtl-mode-00 Section 10.1.3          
			// M_1* = M_1 xor SHAKE256(PK.seed, ADRS, 8n)
			// length is already in bytes so is already 8n
			shake256(bitmask, mask_buffer, mask_buffer_len,
				 msg_len);
			break;
		default:
			LOG_ERROR("Invalid hashing algorithm");
			break;
		}

		// Apply the bit mask by XOR with the data
		for (index = 0; index < msg_len; index++) {
			tmp_buffer[index] = msg_buffer[index] ^ bitmask[index];
		}

		free(bitmask);
		free(mask_buffer);
	} else {
		memcpy(tmp_buffer, msg_buffer, msg_len);
	}

	// Hash the buffer for the leaf node
	switch (algorithm) {
	case SPX_MTL_SHA2:
		// F from draft-harvey-cfrg-mtl-mode-00 Section 10.2.3 
		// SHA2-256(BlockPad(PK.seed) || ADRS^c || M_1)
		result =
		    spx_sha2(spx_prop->pk_seed.seed, spx_prop->pk_seed.length,
			     &ADRS[0], ADRSLen, tmp_buffer, msg_len, &hash[0],
			     hash_len);
		break;
	case SPX_MTL_SHAKE:
		// F from draft-harvey-cfrg-mtl-mode-00 Section 10.1.3 
		// SHAKE256(PK.seed||ADRS||M_1, n)
		result =
		    spx_shake(spx_prop->pk_seed.seed, spx_prop->pk_seed.length,
			      &ADRS[0], ADRSLen, tmp_buffer, msg_len, &hash[0],
			      hash_len);
		break;
	default:
		LOG_ERROR("Invalid hashing algorithm");
		break;
	}

	free(tmp_buffer);
	return result;
}

/*****************************************************************
* Algorithm 1: SHA2 Hashing a Data Value to Produce a Leaf Node.
******************************************************************
 * @param params:     SPHINCS+ public key seed & key
 * @param sid:        Series ID generated for the MTL node set
 * @param node_id:     Message leaf index
 * @param msg_buffer: Byte array of the message that will be added
 * @param msg_len:    Length of the msg_buffer array
 * @param hash:       Pointer to byte array where hash is stored
 * @param hash_len:   Length of hash byte array
 * @return 0 if successful 
 */
uint8_t spx_mtl_node_set_hash_leaf_sha2(void *params,
					SERIESID * sid,
					uint32_t node_id,
					uint8_t * msg_buffer,
					uint32_t msg_len, uint8_t * hash,
					uint32_t hash_len)
{
	return spx_mtl_node_set_hash_leaf(params, sid, node_id, msg_buffer,
					  msg_len, hash, hash_len,
					  SPX_MTL_SHA2);
}

/*****************************************************************
* Algorithm 1: SHAKE Hashing a Data Value to Produce a Leaf Node.
******************************************************************
 * @param params:     SPHINCS+ public key seed & key
 * @param sid:        Series ID generated for the MTL node set
 * @param node_id:     Message leaf index
 * @param msg_buffer: Byte array of the message that will be added
 * @param msg_len:    Length of the msg_buffer array
 * @param hash:       Pointer to byte array where hash is stored
 * @param hash_len:   Length of hash byte array
 * @return 0 if successful 
 */
uint8_t spx_mtl_node_set_hash_leaf_shake(void *params,
					 SERIESID * sid,
					 uint32_t node_id,
					 uint8_t * msg_buffer,
					 uint32_t msg_len,
					 uint8_t * hash, uint32_t hash_len)
{
	return spx_mtl_node_set_hash_leaf(params, sid, node_id, msg_buffer,
					  msg_len, hash, hash_len,
					  SPX_MTL_SHAKE);
}

/*****************************************************************
* Algorithm 2: Hashing Two Child Nodes to Produce an Internal Node.
******************************************************************
 * @param params:     SPHINCS+ public key seed & key
 * @param sid:        Series ID generated for the MTL node set
 * @param node_left:   Node Id for the left child node
 * @param node_right:  Node Id for the right child node
 * @param hash_left:   Pointer to byte array for left child hash
 * @param hash_right:  Pointer to byte array for right child hash
 * @param hash:       Pointer where the resulting hash is placed
 * @param hash_len:   Length of hash byte array
 * @param algorithm:  Type of algorithm used (#defined values) 
 * @return 0 if successful 
 */
uint8_t spx_mtl_node_set_hash_int(void *params,
				  SERIESID * sid,
				  uint32_t node_left,
				  uint32_t node_right,
				  uint8_t * hash_left,
				  uint8_t * hash_right, uint8_t * hash,
				  uint32_t hash_len, uint8_t algorithm)
{
	uint32_t ADRSLen = ADRS_ADDR_SIZE_C;
	uint8_t ADRS[32] = { 0 };
	uint8_t *buffer;
	SPX_PARAMS *spx_prop = params;
	uint8_t result;
	uint32_t buffer_len = hash_len * 2;
	uint8_t *tmp_buffer = NULL;
	uint8_t *bitmask = NULL;
	uint8_t *mask_buffer = NULL;
	uint32_t mask_buffer_len = 0;
	uint32_t index;

	if (hash == NULL) {
		LOG_ERROR("Null parameters");
		return 1;
	}
	// spx.H(seed, mtlnsADRS.bytes(), (left_hash, right_hash))
	switch (algorithm) {
	case SPX_MTL_SHA2:
		// Create address structure (Compressed)
		ADRSLen =
		    mtlns_adrs_compressed((uint8_t *) & ADRS, SPX_ADRS_MTL_TREE,
					  sid, node_left, node_right);
		break;
	case SPX_MTL_SHAKE:
		// Create address structure (Full)
		ADRSLen =
		    mtlns_adrs_full((uint8_t *) & ADRS, SPX_ADRS_MTL_TREE, sid,
				    node_left, node_right);
		break;
	default:
		LOG_ERROR("Invalid hashing algorithm");
		break;
	}

	// Concatenate the left and right hashes
	buffer = malloc(buffer_len);
	if (buffer == NULL) {
		LOG_ERROR("Unable to allocate buffer");
		return 1;
	}
	memcpy(buffer, hash_left, hash_len);
	memcpy(buffer + hash_len, hash_right, hash_len);

	// If robust variation hash address for mask and xor with data
	if (spx_prop->robust) {
		tmp_buffer = calloc(1, buffer_len);
		bitmask = calloc(1, buffer_len);
		mask_buffer_len = spx_prop->pk_seed.length + ADRS_ADDR_SIZE_C;
		mask_buffer = calloc(1, mask_buffer_len);
		memcpy(mask_buffer, spx_prop->pk_seed.seed,
		       spx_prop->pk_seed.length);
		memcpy(mask_buffer, ADRS, ADRS_ADDR_SIZE_C);

		switch (algorithm) {
		case SPX_MTL_SHA2:
			// from draft-harvey-cfrg-mtl-mode-00 Section 10.2.3
			// (M_1 || M_2)* = (M_1 || M_2)* xor MFG1_X(PK.seed, ADRS, 16n) 
			// length is already in bytes so is already 8n  
			if (hash_len <= 16) {
				mgf1_256(bitmask, buffer_len, mask_buffer,
					 mask_buffer_len);
			} else {
				mgf1_512(bitmask, buffer_len, mask_buffer,
					 mask_buffer_len);
			}
			break;
		case SPX_MTL_SHAKE:
			// from draft-harvey-cfrg-mtl-mode-00 Section 10.1.3 
			// (M_1 || M_2)* = (M_1 || M_2)* xor SHAKE256(PK.seed, ADRS, 16n)                       
			// length is already in bytes so is already 8n
			shake256(bitmask, mask_buffer, mask_buffer_len,
				 buffer_len);
			break;
		default:
			LOG_ERROR("Invalid hashing algorithm");
			break;
		}

		// XOR the bitmask with the buffer
		for (index = 0; index < buffer_len; index++) {
			tmp_buffer[index] = buffer[index] ^ bitmask[index];
		}

		memcpy(buffer, tmp_buffer, buffer_len);
		free(bitmask);
		free(tmp_buffer);
		free(mask_buffer);
	}

	switch (algorithm) {
	case SPX_MTL_SHA2:
		// H from draft-harvey-cfrg-mtl-mode-00 Section 10.2.3 
		// SHA-X(BlockPad(PK.seed) || ADRS^c || (M_1 ||M_2)*)   
		result = spx_sha2(spx_prop->pk_seed.seed,
				  spx_prop->pk_seed.length, &ADRS[0], ADRSLen,
				  buffer, buffer_len, &hash[0], hash_len);
		break;
	case SPX_MTL_SHAKE:
		// H from draft-harvey-cfrg-mtl-mode-00 Section 10.1.3 
		// SHAKE256(PK.seed || ADRS || (M_1 ||M_2)*, 8n)
		result = spx_shake(spx_prop->pk_seed.seed,
				   spx_prop->pk_seed.length, &ADRS[0], ADRSLen,
				   buffer, buffer_len, &hash[0], hash_len);
		break;
	default:
		LOG_ERROR("Invalid hashing algorithm");
		break;
	}

	free(buffer);
	return result;
}

/*****************************************************************
* Algorithm 2: SHA2 Hashing Child Nodes to Produce an Internal Node.
******************************************************************
 * @param params:     SPHINCS+ public key seed & key
 * @param sid:        Series ID generated for the MTL node set
 * @param node_left:   Node Id for the left child node
 * @param node_right:  Node Id for the right child node
 * @param hash_left:   Pointer to byte array for left child hash
 * @param hash_right:  Pointer to byte array for right child hash
 * @param hash:       Pointer where the resulting hash is placed
 * @param hash_len:   Length of hash byte array
 * @return 0 if successful 
 */
uint8_t spx_mtl_node_set_hash_int_sha2(void *params,
				       SERIESID * sid,
				       uint32_t node_left,
				       uint32_t node_right,
				       uint8_t * hash_left,
				       uint8_t * hash_right, uint8_t * hash,
				       uint32_t hash_len)
{
	return spx_mtl_node_set_hash_int(params, sid, node_left, node_right,
					 hash_left, hash_right, hash, hash_len,
					 SPX_MTL_SHA2);
}

/*****************************************************************
* Algorithm 2: SHAKE Hashing Child Nodes to Produce an Internal Node.
******************************************************************
 * @param params:     SPHINCS+ public key seed & key
 * @param sid:        Series ID generated for the MTL node set
 * @param node_left:   Node Id for the left child node
 * @param node_right:  Node Id for the right child node
 * @param hash_left:   Pointer to byte array for left child hash
 * @param hash_right:  Pointer to byte array for right child hash
 * @param hash:       Pointer where the resulting hash is placed
 * @param hash_len:   Length of hash byte array
 * @return 0 if successful 
 */
uint8_t spx_mtl_node_set_hash_int_shake(void *params,
					SERIESID * sid,
					uint32_t node_left,
					uint32_t node_right,
					uint8_t * hash_left,
					uint8_t * hash_right, uint8_t * hash,
					uint32_t hash_len)
{
	return spx_mtl_node_set_hash_int(params, sid, node_left, node_right,
					 hash_left, hash_right, hash, hash_len,
					 SPX_MTL_SHAKE);
}
