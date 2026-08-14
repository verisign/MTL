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
#include <arpa/inet.h>
#include <math.h>
#include <openssl/hmac.h>
#include <string.h>

#include "mtl_hash.h"
#include "mtl_error.h"

#define BUFFER_APPEND(ptr, offset, data, datalen)  {memcpy(ptr + offset, data, datalen); offset += datalen;}

/** bytepad(encode_string(cstr))
 * \todo update to real fixed customization string once MTL_OID is assigned
 */
#define MTL_FIXED_CSTR_LEN 8
uint8_t MTL_FIXED_CSTR[MTL_FIXED_CSTR_LEN] = {1,6,'M','T','L','O','I','D'};


/*****************************************************************
* cSHA2-X Hash Function - Based on OpenSSL EVP API
* Uses fixed customization string MTL_FIXED_CSTR for cSHA2-X
******************************************************************
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @param out_len: Desired output size. Also interpreted as security parameter
 * @return MTL_OK on success
 */
MTLSTATUS mtl_hash_sha2(uint8_t * out, const uint8_t * in, size_t in_len, size_t out_len)
{
	EVP_MD *hash_func = NULL;
	EVP_MD_CTX *mdctx = NULL;
	unsigned char hash[EVP_MAX_MD_SIZE];
	size_t blocksize;
	uint8_t* blockpadded_cstr = NULL;

	if ((out == NULL) || (in == NULL) || (in_len == 0) || (out_len == 0)) {
		return MTL_NULL_PTR;
	}
	// Create the SHA instantiation
	switch(out_len) {
		case 16:
			hash_func = (EVP_MD *) EVP_sha256();
			break;
		case 24:
		case 32:
			hash_func = (EVP_MD *) EVP_sha512();
			break;
		default:
			LOG_ERROR("Invalid security parameter");
			return MTL_BAD_PARAM;
	}
	mdctx = EVP_MD_CTX_new();

	// Initalize the digest
	if (1 != EVP_DigestInit_ex(mdctx, hash_func, NULL)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to allocate hash function");
		return MTL_ERROR;
	}
	// Add customization string
	blocksize = EVP_MD_block_size(hash_func);
	blockpadded_cstr = calloc(blocksize, 1);
	if (blockpadded_cstr == NULL) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to add cstr to digest");
		return MTL_RESOURCE_FAIL;
	}
	memcpy(blockpadded_cstr, MTL_FIXED_CSTR, MTL_FIXED_CSTR_LEN);
	if (1 != EVP_DigestUpdate(mdctx, blockpadded_cstr, blocksize)) {
		EVP_MD_CTX_free(mdctx);
		free(blockpadded_cstr);
		LOG_ERROR("Unable to add cstr to digest");
		return MTL_ERROR;
	}
	// Add the data buffer
	if (1 != EVP_DigestUpdate(mdctx, in, in_len)) {
		EVP_MD_CTX_free(mdctx);
		free(blockpadded_cstr);
		LOG_ERROR("Unable to add message to digest");
		return MTL_ERROR;
	}
	// Finalize the digest
	if (1 != EVP_DigestFinal_ex(mdctx, hash, NULL)) {
		free(blockpadded_cstr);
		LOG_ERROR("Unable to finalize digest");
		return MTL_ERROR;
	}
	memcpy(out, hash, out_len);
	free(blockpadded_cstr);

	EVP_MD_CTX_free(mdctx);
	return MTL_OK;
}


/*****************************************************************
* cSHAKE Hash Function - Based on OpenSSL EVP API.
* Automatically uses cSHAKE128 or cSHAKE256 based on hash_len. 
* Uses fixed customization strings for leaf and internal nodes from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.2
* NOTE: cSHAKE not yet supported by OpenSSL stable versions. For now, we use SHAKE as a placeholder. 
******************************************************************
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @param hash_len: Desired output size. Also interpreted as security parameter
 * @return MTL_OK on success
 */
MTLSTATUS mtl_hash_shake(uint8_t * out, const uint8_t * in, size_t in_len, size_t out_len)
{
	EVP_MD *hash_func = NULL;
	EVP_MD_CTX *mdctx = NULL;

	if ((out == NULL) || (in == NULL) || (in_len == 0) || (out_len == 0)) {
		return MTL_NULL_PTR;
	}

	// Create the SHAKE instantiation
	switch(out_len) {
		case 16:
			hash_func = (EVP_MD *) EVP_shake128();
			break;
		case 24:
		case 32:
			hash_func = (EVP_MD *) EVP_shake256();
			break;
		default:
			LOG_ERROR("Invalid security parameter");
			return MTL_BAD_PARAM;
	}
	mdctx = EVP_MD_CTX_new();

	// Initalize the digest
	if (1 != EVP_DigestInit_ex(mdctx, hash_func, NULL)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to allocate hash function");
		return MTL_ERROR;
	}
	// Add the data buffer
	if (1 != EVP_DigestUpdate(mdctx, in, in_len)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to add message to digest");
		return MTL_ERROR;
	}
	// Finalize the digest
	if (1 != EVP_DigestFinalXOF(mdctx, out, out_len)) {
		LOG_ERROR("Unable to compute digest");
		return MTL_ERROR;
	}

	EVP_MD_CTX_free(mdctx);
	return MTL_OK;
}

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
 * @param ctx:        Context string for this message; MUST be null as per draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00
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
					  uint8_t algorithm)
{
	uint8_t *buffer = NULL;
	uint32_t buffer_len = 0;
	uint32_t buffer_offset = 0;
	MTLSTATUS result;
	if ((sid == NULL) || (sid->length) == 0 || (rand == NULL) || (rand_len == 0)
	    || (msg_buffer == NULL) || (msg_len == 0) || (hash_out == NULL)
	    || (hash_len == 0)) {
		LOG_ERROR("Null parameters");
		return MTL_NULL_PTR;
	}
	if((hash_len != 16) && (hash_len != 24) && (hash_len != 32))
	{
		LOG_ERROR("Unsupported security parameter");
		return MTL_BAD_PARAM;
	}
	if ( (rand_len != hash_len) || (sid->length != 2*hash_len) ) {
		LOG_ERROR("Component security parameters mismatch");
		return MTL_BAD_PARAM;
	}

	// H_leaf from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.2
	// Buffer is SID || Rand || leaf index || octet(OLEN(ctx)) || ctx || M
	buffer_len = sid->length + rand_len + sizeof(node_index) + 1 + ctx_len + msg_len;

	buffer = malloc(buffer_len);
	if(buffer == NULL) {
		LOG_ERROR("failed allocating data buffer");
		return MTL_RESOURCE_FAIL;
	}
	BUFFER_APPEND(buffer, buffer_offset, sid->id, sid->length);
	BUFFER_APPEND(buffer, buffer_offset, rand, rand_len);
	mtl_index_to_bytes(buffer+buffer_offset, node_index);
	buffer_offset += sizeof(MTL_INDEX);
	BUFFER_APPEND(buffer, buffer_offset, &ctx_len, 1);
	BUFFER_APPEND(buffer, buffer_offset, ctx, ctx_len);
	BUFFER_APPEND(buffer, buffer_offset, msg_buffer, msg_len);


	switch (algorithm) {
	case MTL_HASH_SHA2:
		result = mtl_hash_sha2(hash_out, buffer, buffer_len, hash_len);
		break;
	case MTL_HASH_SHAKE:
		result = mtl_hash_shake(hash_out, buffer, buffer_len, hash_len);
		break;
	default:
		LOG_ERROR("Invalid hashing algorithm");
		result = MTL_BAD_PARAM;
		break;
	}

	free(buffer);
	return result;
}

/*****************************************************************
* SHA2 Hashing a message and randomizer to produce a leaf node.
******************************************************************
 * @param sid:        Series identifier for this MTL node set
 * @param node_index:    Node identifier for this message
 * @param rand:       Randomizer for this message
 * @param rand_len:   Length of the rand byte array
 * @param msg_buffer: Byte array of the message that will be added
 * @param msg_len:    Length of the msg_buffer array
 * @param hash_out:       Pointer to byte array where hash is stored
 * @param hash_len:   Length of hash byte array. Also interpreted as security parameter
 * @param ctx:        Context string for this message; MUST be null as per draft-kaizer-dnsop-ml-dsa-mtl-dnssec
 * @param algorithm:  Type of algorithm used (#defined values) 
 * @return MTL_OK if successful
 */
MTLSTATUS mtl_node_set_hash_leaf_sha2(
					  SERIESID * sid,
				      MTL_INDEX node_index,
				      uint8_t * msg_buffer, uint32_t msg_len,
					  uint8_t * ctx, uint32_t ctx_len,
				      uint8_t * rand, uint32_t rand_len,
				      uint8_t * hash_out, uint32_t hash_len)
{
	return mtl_node_set_hash_leaf(sid, node_index, 
					  msg_buffer, msg_len, ctx, ctx_len,
					  rand, rand_len, hash_out, hash_len,
					  MTL_HASH_SHA2);
}

/*****************************************************************
* SHAKE Hashing a message and randomizer to produce a leaf node.
******************************************************************
 * @param sid:        Series identifier for this MTL node set
 * @param node_index:    Node identifier for this message
 * @param rand:       Randomizer for this message
 * @param rand_len:   Length of the rand byte array
 * @param msg_buffer: Byte array of the message that will be added
 * @param msg_len:    Length of the msg_buffer array
 * @param hash_out:       Pointer to byte array where hash is stored
 * @param hash_len:   Length of hash byte array. Also interpreted as security parameter
 * @param ctx:        Context string for this message; MUST be null as per draft-kaizer-dnsop-ml-dsa-mtl-dnssec
 * @param algorithm:  Type of algorithm used (#defined values) 
 * @return MTL_OK if successful
 */
MTLSTATUS mtl_node_set_hash_leaf_shake(
					  SERIESID * sid,
				      MTL_INDEX node_index,
				      uint8_t * msg_buffer, uint32_t msg_len,
					  uint8_t * ctx, uint32_t ctx_len,
				      uint8_t * rand, uint32_t rand_len,
				      uint8_t * hash_out, uint32_t hash_len)
{
	return mtl_node_set_hash_leaf(sid, node_index, 
					  msg_buffer, msg_len, ctx, ctx_len,
					  rand, rand_len, hash_out, hash_len,
					  MTL_HASH_SHAKE);
}

/*****************************************************************
* Hashing Two Child Nodes to Produce an Internal Node.
******************************************************************
 * @param sid:        Series ID generated for the MTL node set
 * @param index_left:   Left index of this node's address
 * @param index_right:  Right index of this node's address
 * @param hash_left:   Pointer to byte array for left child hash
 * @param hash_right:  Pointer to byte array for right child hash
 * @param hash_out:       Pointer where the resulting hash is placed
 * @param hash_len:   Length of hash byte arrays
 * @param algorithm:  Type of algorithm used (#defined values) 
 * @return MTL_OK if successful 
 */
MTLSTATUS mtl_node_set_hash_int(
				  SERIESID * sid,
				  MTL_INDEX index_left,
				  MTL_INDEX index_right,
				  uint8_t * hash_left,
				  uint8_t * hash_right, uint8_t * hash_out,
				  uint32_t hash_len, uint8_t algorithm)
{
	uint8_t *buffer;
	uint32_t buffer_offset = 0;
	MTLSTATUS result;
	uint32_t buffer_len = 0;

	if (sid == NULL || hash_left == NULL || hash_right == NULL || hash_out == NULL) {
		LOG_ERROR("Null parameters");
		return MTL_NULL_PTR;
	}
	if (sid->length != 2*hash_len) {
		LOG_ERROR("Invalid parameters");
		return MTL_BAD_PARAM;
	}

	// H_int from draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.2
	// H(SID || index_left || index_right || hash_left || hash_right)
	buffer_len = sid->length + 2*sizeof(index_left) + 2*hash_len;
	buffer = malloc(buffer_len);
	if (buffer == NULL) {
		LOG_ERROR("Unable to allocate buffer");
		return MTL_RESOURCE_FAIL;
	}
	BUFFER_APPEND(buffer, buffer_offset, sid->id, sid->length);
	mtl_index_to_bytes(buffer+buffer_offset, index_left);
	buffer_offset += sizeof(MTL_INDEX);
	mtl_index_to_bytes(buffer+buffer_offset, index_right);
	buffer_offset += sizeof(MTL_INDEX); 
	BUFFER_APPEND(buffer, buffer_offset, hash_left, hash_len);
	BUFFER_APPEND(buffer, buffer_offset, hash_right, hash_len);


	switch (algorithm) {
	case MTL_HASH_SHA2:
		result = mtl_hash_sha2(hash_out, buffer, buffer_len, hash_len);
		break;
	case MTL_HASH_SHAKE:
		result = mtl_hash_shake(hash_out, buffer, buffer_len, hash_len);
		break;
	default:
		LOG_ERROR("Invalid hashing algorithm");
		result = MTL_BAD_PARAM;
		break;
	}

	free(buffer);
	return result;
}

/*****************************************************************
* SHA2 Hashing Child Nodes to Produce an Internal Node.
******************************************************************
 * @param sid:        Series ID generated for the MTL node set
 * @param index_left:   Node Id for the left child node
 * @param index_right:  Node Id for the right child node
 * @param hash_left:   Pointer to byte array for left child hash
 * @param hash_right:  Pointer to byte array for right child hash
 * @param hash:       Pointer where the resulting hash is placed
 * @param hash_len:   Length of hash byte array
 * @return MTL_OK if successful 
 */
MTLSTATUS mtl_node_set_hash_int_sha2(
				       SERIESID * sid,
				       MTL_INDEX index_left,
				       MTL_INDEX index_right,
				       uint8_t * hash_left,
				       uint8_t * hash_right, uint8_t * hash,
				       uint32_t hash_len)
{
	return mtl_node_set_hash_int(sid, index_left, index_right,
					 hash_left, hash_right, hash, hash_len,
					 MTL_HASH_SHA2);
}

/*****************************************************************
* SHAKE Hashing Child Nodes to Produce an Internal Node.
******************************************************************
 * @param sid:        Series ID generated for the MTL node set
 * @param index_left:   Node Id for the left child node
 * @param index_right:  Node Id for the right child node
 * @param hash_left:   Pointer to byte array for left child hash
 * @param hash_right:  Pointer to byte array for right child hash
 * @param hash:       Pointer where the resulting hash is placed
 * @param hash_len:   Length of hash byte array
 * @return MTL_OK if successful 
 */
MTLSTATUS mtl_node_set_hash_int_shake(
					SERIESID * sid,
					MTL_INDEX index_left,
					MTL_INDEX index_right,
					uint8_t * hash_left,
					uint8_t * hash_right, uint8_t * hash,
					uint32_t hash_len)
{
	return mtl_node_set_hash_int(sid, index_left, index_right,
					 hash_left, hash_right, hash, hash_len,
					 MTL_HASH_SHAKE);
}
