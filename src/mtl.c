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

#include "mtl.h"
#include "mtl_node_set.h"
#include "mtl_error.h"

/*****************************************************************
 * Set the MTL Scheme Functions
******************************************************************
 * @param ctx,  the context for this MTL Node Set
 * @param randomize, flag indicating if randomization of messages
 *                   should be used
 * @param hash_msg, the scheme specific hash_msg function
 * @param hash_leaf, the scheme specific leaf hash function
 * @param hash_node, the scheme specific node hash function
 * @return MTLSTATUS: MTL_OK if successful
 */
MTLSTATUS mtl_set_scheme_functions(MTL_CTX * ctx,
				   uint8_t randomize,
				   H_LEAF * hash_leaf,
				   H_INT * hash_int)
{

	if (ctx == NULL) {
		return MTL_NULL_PTR;
	}
	if (randomize != 1) {
		LOG_ERROR("Pseudorandom sampling is not currently supported");
		return MTL_BAD_PARAM;
	}

	ctx->randomize = randomize;
	ctx->hash_leaf = hash_leaf;
	ctx->hash_int = hash_int;

	return MTL_OK;
}

/************************************************************************
 * The following algorithms are implementations from the draft 
 * draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00
 ************************************************************************/

/*****************************************************************
 * Initializing a MTL Node Set.
******************************************************************
 * @param ctx,  the context for this MTL Node Set
 * @param sid,  series identifier for this node set
 * @param pub_key, flag indicating if this is a public key or private key 
 * @return MTLSTATUS: MTL_OK if successful
 */
MTLSTATUS mtl_initns(MTL_CTX ** mtl_ctx, SERIESID * sid, uint8_t pub_key)
{
	if ((mtl_ctx == NULL) || (sid == NULL)) {
		return MTL_NULL_PTR;
	}
	MTL_CTX *ctx = malloc(sizeof(MTL_CTX));
	if (ctx == NULL) {
		return MTL_RESOURCE_FAIL;
	}

	memcpy(&ctx->sid, sid, sizeof(SERIESID));
	ctx->randomize = 0;
	ctx->hash_msg = NULL;
	ctx->hash_leaf = NULL;
	ctx->hash_int = NULL;
	mtl_node_set_init(&ctx->nodes, sid, pub_key);

	*mtl_ctx = ctx;

	return MTL_OK;
}

/*****************************************************************
* MTL Node Set Append.
* Append a data value to a MTL node set, adding a leaf node and internal nodes as needed 
* to produce a new ladder covering the expanded series of data values
******************************************************************
 * @param ctx,  the context for this MTL Node Set
 * @param data_value: byte array of data_value data
 * @param data_value_len: length of the data_value byte array
 * @param ctx_str: byte array of context string
 * @param ctx_str_len: length of the ctx_str byte array
 * @param leaf_index: index of the leaf node that is being appended
 * @return MTL_OK on success
 */
MTLSTATUS mtl_append(MTL_CTX * ctx,
		   uint8_t * data_value,
		   uint16_t data_value_len,
		   uint8_t * ctx_str,
		   uint16_t ctx_str_len,
		   MTL_INDEX leaf_index)
{
	uint8_t hash[EVP_MAX_MD_SIZE];

	if ((ctx == NULL) || (data_value == NULL) || data_value_len == 0) {
		LOG_ERROR("NULL Input Pointers");
		return MTL_NULL_PTR;
	}

	// Generate new randomizer
	RANDOMIZER * mtl_random = NULL;
	if (mtl_generate_randomizer(ctx, &mtl_random) != MTL_OK) {
		LOG_ERROR("Unable to generate node randomizer");
		return MTL_ERROR;
	}

	// Compute and store the leaf node hash value 
	if (ctx->hash_leaf != NULL) {
		if (ctx->hash_leaf(&ctx->sid, leaf_index,
				   data_value, data_value_len, 
				   ctx_str, ctx_str_len,
				   mtl_random->value, mtl_random->length, 
				   &hash[0], ctx->nodes.hash_size) != MTL_OK) {
			LOG_ERROR("Unable to hash leaf node");
			mtl_randomizer_free(mtl_random);
			return MTL_ERROR;
		}
	} else {
		LOG_ERROR("Leaf hash function is not defined");
		mtl_randomizer_free(mtl_random);
		return MTL_ERROR;
	}

	// Add the node to the node set tree
	if (mtl_node_set_insert(&ctx->nodes, leaf_index, leaf_index, &hash[0])
	    != MTL_OK) {
		LOG_ERROR("Unable to add message to node set");
		mtl_randomizer_free(mtl_random);
		return MTL_ERROR;
	}

	if (mtl_node_set_insert_randomizer(&ctx->nodes, leaf_index, mtl_random->value)
	    != MTL_OK) {
		LOG_ERROR("Unable to add randomizer to node set");
		mtl_randomizer_free(mtl_random);
		return MTL_ERROR;
	}
	mtl_randomizer_free(mtl_random);

	if (mtl_node_set_update_parents(ctx, leaf_index) != MTL_OK) {
		LOG_ERROR("Unable to add message to node set");
		return MTL_ERROR;		
	}

	return MTL_OK;
}

/*****************************************************************
* MTL Node Set Update Parent Hashes
******************************************************************
 * @param ctx,  the context for this MTL Node Set
 * @param leaf_index: index of the leaf node that is being appended
 * @return MTL_OK on success
 */
MTLSTATUS mtl_node_set_update_parents(MTL_CTX * ctx, MTL_INDEX leaf_index)
{
	MTL_INDEX index;
	uint8_t *hash_left;
	uint8_t *hash_right;
	uint8_t hash[EVP_MAX_MD_SIZE];
	MTL_INDEX left_index;
	MTL_INDEX mid_index;	
	MTLSTATUS return_code;	

	if (ctx == NULL) {
		LOG_ERROR_WITH_CODE("mtl_node_set_insert", MTL_ERROR);
		return MTL_ERROR;
	}

	// Complete the parent hashes in the tree
	for (index = 1; index <= mtl_lsb(leaf_index + 1); index++) {
		left_index = leaf_index - (1 << index) + 1;
		mid_index = leaf_index - (1 << (index - 1)) + 1;

		if ((mtl_node_set_fetch
		     (&ctx->nodes, left_index, mid_index - 1, &hash_left) == MTL_OK)
		    &&
		    (mtl_node_set_fetch
		     (&ctx->nodes, mid_index, leaf_index, &hash_right) == MTL_OK)) {
			if (ctx->hash_int != NULL) {
				if (ctx->hash_int(&ctx->sid,
						   left_index, leaf_index,
						   hash_left, hash_right,
						   &hash[0], ctx->nodes.hash_size) != MTL_OK) {
					free(hash_left);
					free(hash_right);
					LOG_ERROR("Unable to hash the node");
					return MTL_ERROR;
				}
			} else {
				LOG_ERROR
				    ("Internal node hash function is not defined");
				return MTL_ERROR;
			}
			return_code = mtl_node_set_insert(&ctx->nodes, left_index, leaf_index,
					    &hash[0]);
			if(return_code != MTL_OK) {
				LOG_ERROR_WITH_CODE("mtl_node_set_insert", return_code);
				return MTL_ERROR;
			}
			free(hash_left);
			free(hash_right);
		} else {
			LOG_ERROR
			    ("Unable to fetch hash when appending data_value");
				return MTL_ERROR;
		}
	}
	return MTL_OK;
}


/*****************************************************************
* Computing an Authentication Path for a Data Value.
* From draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.1
******************************************************************
 * @param ctx,  the context for this MTL Node Set 
 * @param leaf_index: leaf node index of the data value to authenticate
 * @return auth_path: authentication path from the leaf node to the
 *                    associated rung, NULL on error
 */
AUTHPATH *mtl_authpath(MTL_CTX * ctx, MTL_INDEX leaf_index)
{
	int64_t index = 0;
	MTL_INDEX left = 0;
	MTL_INDEX right = 0;
	MTL_INDEX pathl = 0;
	MTL_INDEX pathr = 0;
	uint8_t *hash;
	AUTHPATH *auth_path = calloc(1, sizeof(AUTHPATH));

	if(auth_path == NULL) {
		LOG_ERROR("Unable to allocate auth_path");
		return NULL;
	}

	// Check that the leaf is part of this node set
	if (leaf_index >= ctx->nodes.leaf_count) {
		free(auth_path);
		LOG_ERROR("Invalid Auth Path Index");
		return NULL;	// Leaf is outside of node set
	}
	// Find the rung index pair covering the leaf index
	for (index = (int64_t) mtl_msb(ctx->nodes.leaf_count) + 1; index >= 0;
	     index--) {
		if (ctx->nodes.leaf_count & (1 << index)) {
			right = left + (1 << index) - 1;
			if (leaf_index <= right)
				break;
			left = right + 1;
		}
	}

	// Concatenate the sibling nodes from the leaf to the rung
	auth_path->leaf_index = leaf_index;
	memcpy(&auth_path->sid, &ctx->sid, sizeof(SERIESID));
	auth_path->sibling_hash_count = mtl_bit_width(right - left);
	auth_path->sibling_hash =
	    malloc((size_t)auth_path->sibling_hash_count * 
		       (size_t)ctx->nodes.hash_size);
	auth_path->rung_left = left;
	auth_path->rung_right = right;

	// Find the path from the leaf to the sub-tree root
	for (index = 0; index < mtl_bit_width(right - left); index++) {
		if (leaf_index & (1 << index)) {
			pathl =
			    (~((1 << index) - 1) & leaf_index) - (1 << index);
		} else {
			pathl =
			    (~((1 << index) - 1) & leaf_index) + (1 << index);
		}
		pathr = pathl + (1 << index) - 1;
		mtl_node_set_fetch(&ctx->nodes, pathl, pathr, &hash);
		if (index < auth_path->sibling_hash_count) {
			memcpy(auth_path->sibling_hash +
			       (index * ctx->nodes.hash_size), hash,
			       ctx->nodes.hash_size);
		} else {
			LOG_ERROR("Auth Path extends past hash count");
		}

		free(hash);
	}

	return auth_path;
}

/*****************************************************************
 * Computing a Merkle Tree Ladder for a Node Set.
 * From draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1
 ****************************************************************** 
 * @param ctx,  the context for this MTL Node Set 
 * @return ladder, Merkle tree ladder for this node set, NULL on error
 */
LADDER *mtl_ladder(MTL_CTX * ctx)
{
	MTL_INDEX left_index = 0;
	MTL_INDEX right_index = 0;
	int64_t i;
	RUNG *rung;
	LADDER *ladder = NULL;
	uint8_t *hash_ptr;
	uint16_t node_index = 0;

	if (ctx == NULL) {
		LOG_ERROR("Unable to allocate ladder");
		return NULL;
	}

	ladder = calloc(1, sizeof(LADDER));
	if (ladder == NULL) {
		LOG_ERROR("Unable to allocate ladder");
		return NULL;	
	}
	ladder->flags = 0;
	memcpy(&ladder->sid, &ctx->sid, sizeof(SERIESID));
	ladder->rung_count = mtl_bit_width(ctx->nodes.leaf_count);
	ladder->rungs = malloc(sizeof(RUNG) * ladder->rung_count);
	if (ladder->rungs == NULL) {
		LOG_ERROR("Unable to allocate rungs");
		free(ladder);
		return NULL;
	}

	// Concatenate the rungs in the node set
	for (i = mtl_msb(ctx->nodes.leaf_count); i >= 0; i--) {
		if (ctx->nodes.leaf_count & (1 << i)) {
			right_index = left_index + (1 << i) - 1;

			rung =
			    (RUNG *) ((uint8_t *) ladder->rungs +
				      (sizeof(RUNG) * node_index));
			node_index++;

			rung->left_index = left_index;
			rung->right_index = right_index;
			rung->hash_length = ctx->nodes.hash_size;
			if (mtl_node_set_fetch(&ctx->nodes, left_index, right_index,
					   &hash_ptr) != MTL_OK) {
						LOG_ERROR("Error building ladder");
						free(ladder->rungs);
						free(ladder);
						free(hash_ptr);
						return NULL;
					   }
			memcpy(rung->hash, hash_ptr, ctx->nodes.hash_size);
			free(hash_ptr);
			left_index = right_index + 1;
		}
	}

	return ladder;
}

/*****************************************************************
 * Selecting a Ladder Rung.
 * From draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 section 5.1.2.1
 ****************************************************************** 
 * @param auth_path, authentication path that needs to be covered
 * @param ladder, Merkle tree ladder to authenticate relative to
 * @return assoc_rung, the rung in the ladder associated with the
 *     authentication path, NULL on error
 */
RUNG *mtl_rung(AUTHPATH * auth_path, LADDER * ladder)
{
	MTL_INDEX leaf_index = 0;
	uint32_t sibling_hash_count = 0;
	MTL_INDEX left_index;
	MTL_INDEX right_index;
	uint32_t i;
	RUNG *assoc_rung = NULL;
	RUNG *rung = NULL;
	// Minimum degree is updated after first rung is found
	uint32_t min_degree = -1;
	uint32_t degree;
	uint32_t bin_power;

	if ((auth_path == NULL) || (ladder == NULL)) {
		LOG_ERROR("NULL Input Pointers");
		return NULL;
	}
	// Check that authentication path and ladder have same SID
	if (memcmp(auth_path->sid.id, ladder->sid.id, auth_path->sid.length) !=
	    0) {
		LOG_ERROR("SID value not consistent");
		return NULL;
	}

	leaf_index = auth_path->leaf_index;
	sibling_hash_count = auth_path->sibling_hash_count;

	// Check that authentication path is a binary rung strategy path
	bin_power = (1 << sibling_hash_count) - 1;
	left_index = leaf_index & ~bin_power;
	right_index = left_index + bin_power;
	if ((auth_path->rung_left != left_index) ||
	    (auth_path->rung_right != right_index)) {
		LOG_ERROR("Bad Index Not Covered");
		return NULL;
	}
	// Find associated rung with lowest degree, if present
	for (i = 0; i < ladder->rung_count; i++) {
		rung =
		    (RUNG *) ((uint8_t *) ladder->rungs + (sizeof(RUNG) * i));
		// Check if rung index pair would be encountered in
		//     evaluating authentication path for leaf node
		left_index = rung->left_index;
		right_index = rung->right_index;
		if ((left_index <= leaf_index) && (right_index >= leaf_index)) {
			degree = mtl_lsb(right_index - left_index + 1);
			if (((degree <= mtl_lsb(left_index)) ||
			     (mtl_lsb(left_index) == 0)) &&
			    (right_index - left_index + 1 ==
			     (uint32_t) (1 << degree))
			    && (degree <= sibling_hash_count)) {
				if ((assoc_rung == NULL)
				    || (degree < min_degree)) {
					assoc_rung = rung;
					min_degree = degree;
				}
			}
		}
	}

	return assoc_rung;
}

/*****************************************************************
 * Verifying an Authentication Path.
 * From draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00
 ****************************************************************** 
 * @param ctx,  the context for this MTL Node Set  
 * @param data_value: byte array of data_value data
 * @param data_value_len: length of the data_value byte array
 * @param ctx_str: byte array of context string; MUST be null as per draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00
 * @param ctx_str_len: length of the ctx_str byte array; MUST be a 1-octet representation of value 0
 * @param randomizer: (presumed) randomizer for corresponding leaf node
 * @param auth_path, (presumed) authentication path from corresponding
 *     leaf node to rung of ladder covering leaf node
 * @param assoc_rung, Merkle tree rung to authenticate relative to
 * @return MTL_OK if path verifies correctly
 */
MTLSTATUS mtl_verify(MTL_CTX * ctx, 
                  uint8_t * data_value,
                  uint16_t data_value_len, 
                  uint8_t * ctx_str,
                  uint16_t ctx_str_len,
                  RANDOMIZER * randomizer,
				  AUTHPATH * auth_path, RUNG * assoc_rung)
{
	MTLSTATUS result;
	uint8_t output_hash[EVP_MAX_MD_SIZE];
	uint8_t input_hash[EVP_MAX_MD_SIZE];
	MTL_INDEX leaf_index = 0;
	uint32_t sibling_hash_count = 0;
	uint32_t i;
	MTL_INDEX left_index;
	MTL_INDEX right_index;
	MTL_INDEX mid_index;
	uint8_t *sibling_hash;

	if ((ctx == NULL) || (data_value == NULL) || (data_value_len == 0)
		|| (randomizer == NULL) || (randomizer->length == 0)
	    || (auth_path == NULL)
	    || (assoc_rung == NULL)) {
		return MTL_NULL_PTR;
	}
	leaf_index = auth_path->leaf_index;
	sibling_hash_count = auth_path->sibling_hash_count;

	// Recompute leaf node hash value
	if (ctx->hash_leaf != NULL) {
		result =
		    ctx->hash_leaf(&auth_path->sid, leaf_index,
				   data_value, data_value_len,
				   ctx_str, ctx_str_len,
				   randomizer->value, randomizer->length, 
				   &output_hash[0], assoc_rung->hash_length);
	} else {
		LOG_ERROR("Leaf hash function is not defined");
		return MTL_ERROR;
	}

	if (result != MTL_OK) {
		LOG_ERROR("Unable to hash leaf node");
		return MTL_ERROR;
	}
	// Compare leaf node hash value to associated rung hash value if
	//     index pairs match
	if ((leaf_index == assoc_rung->left_index) &&
	    (leaf_index == assoc_rung->right_index)) {
		return memcmp(output_hash, assoc_rung->hash,
			      assoc_rung->hash_length);
	}
	// Recompute internal node hash values and compare to associated
	//     rung hash value if index pairs match
	for (i = 1; i < sibling_hash_count + 1; i++) {
		left_index = leaf_index & ~((1 << i) - 1);
		right_index = left_index + (1 << i) - 1;
		mid_index = left_index + (1 << (i - 1));

		sibling_hash =
		    auth_path->sibling_hash +
		    ((i - 1) * assoc_rung->hash_length);
		memcpy(input_hash, output_hash, assoc_rung->hash_length);
		if (leaf_index < mid_index) {
			if (ctx->hash_int != NULL) {
				result =
				    ctx->hash_int(&auth_path->sid, left_index,
						   right_index, input_hash,
						   sibling_hash, output_hash,
						   assoc_rung->hash_length);
			} else {
				LOG_ERROR
				    ("Internal node hash function is not defined");
					return MTL_ERROR;
			}
		} else {
			if (ctx->hash_int != NULL) {
				result =
				    ctx->hash_int(&auth_path->sid, left_index,
						   right_index, sibling_hash,
						   input_hash, output_hash,
						   assoc_rung->hash_length);
			} else {
				LOG_ERROR
				    ("Internal node hash function is not defined");
					return MTL_ERROR;
			}
		}

		// Break if associated rung reached
		if ((left_index == assoc_rung->left_index) &&
		    (right_index == assoc_rung->right_index)) {
			if( memcmp(output_hash, assoc_rung->hash,
				      assoc_rung->hash_length) == 0 ) {
						return MTL_OK;
					  }
					  else {
						LOG_ERROR("Computed and stored rungs mismatch");
						return MTL_BOGUS;
					  }
		}
	}

	LOG_ERROR("Associated rung not on index's path");
	return MTL_BOGUS;
}

/************************************************************************
 * The following algorithms free the data structures from the previous
 * algorithms.
 ************************************************************************/

/*****************************************************************
 * Free a MTL Context for mtl_initns()
******************************************************************
 * @param ctx,  the context for this MTL Node Set
 * @return MTLSTATUS: MTL_OK if successful
 */
MTLSTATUS mtl_free(MTL_CTX * ctx)
{
	mtl_node_set_free(&ctx->nodes);
	free(ctx);
	ctx = NULL;

	return MTL_OK;
}

/*****************************************************************
* Free Authentication Path for mtl_authpath()
******************************************************************
 * @param path,  Authentication path to ffree
 * @return MTL_OK on success
 */
MTLSTATUS mtl_authpath_free(AUTHPATH * path)
{

	if(path != NULL) {
		free(path->sibling_hash);
	}
	free(path);
	path = NULL;

	return MTL_OK;
}

/*****************************************************************
* Free Ladder for mtl_ladder()
******************************************************************
 * @param ladder,  Ladder to free
 * @return MTL_OK on success
 */
MTLSTATUS mtl_ladder_free(LADDER * ladder)
{
	if (ladder != NULL) {
		free(ladder->rungs);
	}
	free(ladder);
	ladder = NULL;

	return MTL_OK;
}
