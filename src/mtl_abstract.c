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

#include <openssl/rand.h>

/************************************************************************
 * The following algorithms are abstractions that use the constructs 
 * that are defined in draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00 to simplify use.
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
	if (mtl_random == NULL) {
		LOG_ERROR("Unable to allocate buffer");
		return MTL_RESOURCE_FAIL;
	}

	if (ctx->randomize) {
		mtl_random->length = ctx->nodes.hash_size;
		if ((mtl_random->value = malloc(mtl_random->length)) == NULL) {
			LOG_ERROR("Unable to allocate buffer");
			free(mtl_random);
			return MTL_RESOURCE_FAIL;
		}

		// Get random bytes and copy to buffer
        if(!RAND_bytes(mtl_random->value, mtl_random->length)) {
			LOG_ERROR("Unable to generate random data");
			free(mtl_random->value);
			free(mtl_random);
			return MTL_RESOURCE_FAIL;
		}
	} else {
		LOG_ERROR("Unsupported randomization parameter");
		return MTL_BAD_PARAM;
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
 * @param ctx_str:     byte array of context string; must be null as per draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00
 * @param ctx_str_len: byte length of the context string; must be a 1-octect representation of value 0
 * @param node_id:     return value index of the leaf node that was appended
 * @return MTL_OK on success
 */
MTLSTATUS mtl_hash_and_append(MTL_CTX * ctx, 
                                uint8_t * message, uint16_t message_len, 
                                uint8_t * ctx_str, uint16_t ctx_str_len,
                                MTL_INDEX * node_id)
{
	MTL_INDEX leaf_index = 0;

	if ((ctx == NULL) || (message == NULL) || message_len == 0 || node_id == NULL) {
		LOG_ERROR("NULL Input Pointers");
		return MTL_NULL_PTR;
	}

	leaf_index = ctx->nodes.leaf_count;
	
	// Insert the leaf in the MTL node set
	if (mtl_append(ctx, message, message_len, ctx_str, ctx_str_len, leaf_index) != MTL_OK) {
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
MTLSTATUS mtl_randomizer_and_authpath(MTL_CTX * ctx, MTL_INDEX leaf_index,
				    RANDOMIZER ** randomizer, AUTHPATH ** auth)
{
	RANDOMIZER *mtl_random = NULL;

	if ((ctx == NULL) || (randomizer == NULL) || (auth == NULL)) {
		LOG_ERROR("Null parameters");
		return MTL_NULL_PTR;
	}

	mtl_random = malloc(sizeof(RANDOMIZER));
	if (mtl_random == NULL) {
		LOG_ERROR("Unable to allocate buffer")
		return MTL_RESOURCE_FAIL;
	}
	mtl_random->length = ctx->nodes.hash_size;

	if (mtl_node_set_get_randomizer
	    (&ctx->nodes, leaf_index, &mtl_random->value) != MTL_OK) {
		LOG_ERROR("Randomizer Failure");
		free(mtl_random);
		return MTL_ERROR;
	}

	*randomizer = mtl_random;
	*auth = mtl_authpath(ctx, leaf_index);
	if(*auth == NULL) {
		LOG_ERROR("Failed generating authpath");
		free(mtl_random);
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
 * @param ctx_str: context string of the message; must be null as per draft-kaizer-dnsop-ml-dsa-mtl-dnssec-00
 * @param ctx_str_len: length of the context string in bytes; must be a 1-octect representation of value 0
 * @param randomizer: randomizer value for this leaf node
 * @param auth_path: authenticaiton path to verify
 * @param assoc_rung: rung used to verify this auth path
 * @return MTL_OK on success, int on failure
 */
MTLSTATUS mtl_hash_and_verify(MTL_CTX * ctx, 
                                uint8_t * message, uint16_t message_len, 
                                uint8_t * ctx_str, uint16_t ctx_str_len,
                                RANDOMIZER * randomizer, 
                                AUTHPATH * auth_path, 
                                RUNG * assoc_rung)
{
	if ((ctx == NULL) || (message == NULL) || (message_len == 0)
	    || (auth_path == NULL) || (randomizer == NULL)
	    || (assoc_rung == NULL)) {
		LOG_ERROR("NULL input to mtl_hash_and_verify");
		return MTL_NULL_PTR;
	}

	return mtl_verify(ctx, message, message_len, ctx_str, ctx_str_len,
			  randomizer, auth_path, assoc_rung);
}