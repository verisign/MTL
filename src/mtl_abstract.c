/*
	Copyright (c) 2025, VeriSign, Inc.
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
#include "mtl_spx.h"

#include <openssl/rand.h>

/************************************************************************
 * The following algorithms are abstractions that use the constructs 
 * that are defined in draft-harvey-cfrg-mtl-mode-00 to simplify use.
 ************************************************************************/

/*****************************************************************
* Setup the MTL randomizer value
******************************************************************
 * @param ctx:         the context for this MTL Node Set
 * @param randomizer:  pointer to a randomizer buffer
 * @return MTL_OK on success, others on failure
 */
MTLSTATUS mtl_generate_randomizer(MTL_CTX * ctx, RANDOMIZER ** randomizer)
{
	RANDOMIZER *mtl_random;

	if ((ctx == NULL) || (randomizer == NULL)) {
		LOG_ERROR("Bad parameters");
		return MTL_NULL_PTR;
	}

	mtl_random = malloc(sizeof(RANDOMIZER));

	if (ctx->randomize) {
		mtl_random->length = ctx->nodes.hash_size;
		if ((mtl_random->value = malloc(mtl_random->length)) == NULL) {
			LOG_ERROR("Unable to allocate buffer");
			return MTL_RESOURCE_FAIL;
		}

		// Get random bytes and copy to buffer
        if(!RAND_bytes(mtl_random->value, mtl_random->length)) {
			LOG_ERROR("Unable to generate random data");
			return MTL_RESOURCE_FAIL;
		}
	} else {
		mtl_random->length = ctx->seed.length;
		if ((mtl_random->value = malloc(mtl_random->length)) == NULL) {
			LOG_ERROR("Unable to allocate buffer");
			return MTL_RESOURCE_FAIL;
		}
		memcpy(mtl_random->value, ctx->seed.seed, mtl_random->length);
	}

	*randomizer = mtl_random;

	return MTL_OK;
}

/*****************************************************************
* Free the MTL randomizer value
******************************************************************
 * @param mtl_random:  pointer to a randomizer buffer
 * @return 0 on success int on failure
 */
MTLSTATUS mtl_randomizer_free(RANDOMIZER * mtl_random)
{
	if (mtl_random != NULL) {
		free(mtl_random->value);
		free(mtl_random);
		mtl_random = NULL;
	}
	return MTL_OK;
}

/*****************************************************************
* Generate the message hash with randomization and then append to
* the MTL node set as a leaf node. 
******************************************************************
 * @param ctx:         the context for this MTL Node Set
 * @param message:     byte array of message data
 * @param message_len: byte length of the message data
 * @param node_id:     return value index of the leaf node that was appended
 * @return MTL_OK on success
 */
MTLSTATUS mtl_hash_and_append(MTL_CTX * ctx, uint8_t * message,
			     uint16_t message_len, uint32_t * node_id)
{
	uint32_t leaf_index = 0;
	uint8_t hash[EVP_MAX_MD_SIZE];
	RANDOMIZER *mtl_random;
	uint8_t* rmtl_ptr = NULL;
	uint32_t rmtl_len = 0;
	MTLSTATUS return_code;

	if ((ctx == NULL) || (message == NULL) || message_len == 0 || node_id == NULL) {
		LOG_ERROR("NULL Input Pointers");
		return MTL_NULL_PTR;
	}
	// Generate the randomizer in a buffer
	if (mtl_generate_randomizer(ctx, &mtl_random) != MTL_OK) {
		LOG_ERROR("Unable to get node randomizer");
		return MTL_ERROR;
	}
	// mtl_append from draft-harvey-cfrg-mtl-mode-00 Section 8.4
	leaf_index = ctx->nodes.leaf_count;
	ctx->nodes.leaf_count++;

	// Hash the message
	if (ctx->hash_msg != NULL) {
		if (ctx->hash_msg(ctx->sig_params, &ctx->sid, leaf_index,
				  mtl_random->value, mtl_random->length,
				  message, message_len, &hash[0],
				  ctx->nodes.hash_size, ctx->ctx_str,
				  &rmtl_ptr, &rmtl_len) != MTL_OK) {
			LOG_ERROR("Unable to hash leaf node");
			mtl_randomizer_free(mtl_random);
			return MTL_ERROR;
		}
	} else {
		LOG_ERROR("Message hash function is not defined");
		return MTL_ERROR;
	}

	return_code = mtl_node_set_insert_randomizer(&ctx->nodes, leaf_index,
				       rmtl_ptr);
	if(return_code != MTL_OK){
		LOG_ERROR_WITH_CODE("mtl_node_set_insert_randomizer",return_code);
		return MTL_ERROR;
	}

	free(rmtl_ptr);
	mtl_randomizer_free(mtl_random);

	// Insert the leaf in the MTL node set
	if (mtl_append(ctx, &hash[0], ctx->nodes.hash_size, leaf_index) != MTL_OK) {
		LOG_ERROR("Append Message Error");
		return MTL_ERROR;
	}
	*node_id = leaf_index;
	return MTL_OK;
}

/*****************************************************************
* Get the MTL Auth path and randomizer value
******************************************************************
 * @param ctx,  the context for this MTL Node Set
 * @param leaf_index: index of the leaf node that is being appended
 * @param randomizer: pointer to randomizer buffer 
 * @param auth:       pointer to authpath buffer
 * @return MTL_OK on success
 */
MTLSTATUS mtl_randomizer_and_authpath(MTL_CTX * ctx, uint32_t leaf_index,
				    RANDOMIZER ** randomizer, AUTHPATH ** auth)
{
	RANDOMIZER *mtl_random = NULL;

	if ((ctx == NULL) || (randomizer == NULL) || (auth == NULL)) {
		LOG_ERROR("Null parameters");
		return MTL_NULL_PTR;
	}

	mtl_random = malloc(sizeof(RANDOMIZER));
	mtl_random->length = ctx->nodes.hash_size;

	if (mtl_node_set_get_randomizer
	    (&ctx->nodes, leaf_index, &mtl_random->value) != 0) {
		LOG_ERROR("Randomizer Failure");
		return MTL_ERROR;
	}

	*randomizer = mtl_random;
	*auth = mtl_authpath(ctx, leaf_index);
	if(auth == NULL) {
		LOG_ERROR("Failed generating authpath");
		return MTL_ERROR;
	}

	return MTL_OK;
}

/*****************************************************************
* Generate the message hash with randomization and then verify
* the hash with the authenticaiton path
******************************************************************
 * @param ctx:  the context for this MTL Node Set
 * @param message: message to verify
 * @param message_len: length of the message in bytes
 * @param randomizer: randomizer value for this leaf node
 * @param auth_path: authenticaiton path to verify
 * @param assoc_rung: rung used to verify this auth path
 * @return 0 on success, int on failure
 */
MTLSTATUS mtl_hash_and_verify(MTL_CTX * ctx, uint8_t * message,
			    uint16_t message_len, RANDOMIZER * randomizer,
			    AUTHPATH * auth_path, RUNG * assoc_rung)
{
	uint32_t leaf_index = 0;
	uint8_t data_value[EVP_MAX_MD_SIZE];
	uint8_t rmtl[EVP_MAX_MD_SIZE];
	uint8_t *rmtl_ptr = &rmtl[0];
	uint32_t rmtl_len = 0;

	if ((ctx == NULL) || (message == NULL) || (message_len == 0)
	    || (auth_path == NULL) || (randomizer == NULL)
	    || (assoc_rung == NULL)) {
		LOG_ERROR("NULL input to mtl_hash_and_verify");
		return MTL_NULL_PTR;
	}

	leaf_index = auth_path->leaf_index;

	rmtl_len = randomizer->length;
	memcpy(rmtl_ptr, randomizer->value, randomizer->length);

	// mtl_authpath from draft-harvey-cfrg-mtl-mode-00 Section 8.8
	// Randomize the message digest
	if (ctx->hash_msg != NULL) {
		if (ctx->hash_msg(ctx->sig_params, &ctx->sid, leaf_index,
				  randomizer->value, randomizer->length,
				  message, message_len, &data_value[0],
				  ctx->nodes.hash_size, ctx->ctx_str,
				  &rmtl_ptr, &rmtl_len) != 0) {
			LOG_ERROR("Unable to hash leaf node");
			return MTL_ERROR;
		}
	} else {
		LOG_ERROR("Message hash function is not defined");
		return MTL_ERROR;
	}

	return mtl_verify(ctx, &data_value[0], ctx->nodes.hash_size, auth_path,
			  assoc_rung);
}

/*****************************************************************
* Create buffer for ladder including address separation scheme
******************************************************************
 * @param ctx:  the context for this MTL Node Set
 * @param ladder: ladder buffer pointer
 * @param hash_size: size of the hash in bytes
 * @param buffer: pointer to output buffer 
 * @param oid: pointer to the MTL_OID that represents the signature
 * @param oid_len: length of the oid in bytes
 * @return buffer size
 */
uint32_t mtl_get_scheme_separated_buffer(MTL_CTX * ctx, LADDER * ladder,
					 uint32_t hash_size, uint8_t ** buffer, uint8_t* oid,
					 size_t oid_len)
{
	uint32_t ladder_buffer_size = 0;
	uint8_t *ladder_buffer = NULL;
	uint8_t *underlying_buffer = NULL;
	size_t sep_size;
	uint8_t ctx_str_len = 0;

	// Ladder to buffer
	ladder_buffer_size =
	    mtl_ladder_to_buffer(ladder, hash_size, &ladder_buffer);
	if(ladder_buffer_size == 0){
		LOG_ERROR("Failed creating ladder buffer");
		return 0;
	}

	// Address Scheme Separation from draft-harvey-cfrg-mtl-mode-00 Section 4.5
	// Separator from from draft-harvey-cfrg-mtl-mode-03 Section 4.1
	// sep = octet(MTL_LADDER_SEP) || octet(OLEN(ctx)) || ctx || OID_MTL || ladder

	if(ctx->ctx_str != NULL) {
		ctx_str_len = strlen(ctx->ctx_str);
	}

	sep_size = 2 + ctx_str_len + oid_len;

	// Sign SEP + Ladder_Bytes
	underlying_buffer = malloc(ladder_buffer_size + sep_size);
	if (underlying_buffer == NULL){
		LOG_ERROR("Failed allocating underlying_buffer");
		return 0;
	}
	underlying_buffer[0] = MTL_LADDER_SEP;
	underlying_buffer[1] = ctx_str_len;
	if(ctx_str_len > 0) {
		memcpy(underlying_buffer + 2, ctx->ctx_str, strlen(ctx->ctx_str));
	}
	memcpy(underlying_buffer + 2 + ctx_str_len, oid, oid_len);
	memcpy(underlying_buffer + sep_size, ladder_buffer,
	       ladder_buffer_size);
	free(ladder_buffer);

	*buffer = underlying_buffer;
	return ladder_buffer_size + sep_size;
}
