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
 *  \file mtl.h
 *  \brief Primary MTL implemenation functions and APIs.
 *  The general implementation of the MTL Mode functions and APIs.
*/
#ifndef __MTL_IMPL_H__
#define __MTL_IMPL_H__

#define MTL_LIB_VERSION "v1.2.0"

#include <math.h>
#include <openssl/evp.h>
#include <stdint.h>

#include "mtl_node_set.h"
#include "mtl_hash.h"
#include "mtl_util.h"

/** The default MTL Series Identifier Size */ 
#define MTL_SID_SIZE 32

// Data Structures
/**
 * \brief MTL authentication path 
 */
typedef struct AUTHPATH {
	/** MTL bit flags */
	uint16_t flags;
	/** Series ID for the MTL Node Set */
	SERIESID sid;
	/** leaf index represented by the authentication path */
	MTL_INDEX leaf_index;
	/** Left index of the rung that was used to build the path */
	MTL_INDEX rung_left;
	/** Right index of the rung that was used to build the path */
	MTL_INDEX rung_right;
	/** Number of hashes in the sibiling hash path */
	uint16_t sibling_hash_count;
	/** pointer to the byte array for the sibiling hash path */
	uint8_t *sibling_hash;
} AUTHPATH;

/**
 * \brief MTL node randomizer
 */
typedef struct RANDOMIZER {
	/** pointer to the randomizer value (Value max size is OpenSSL EVP_MAX_MD_SIZE - 64 bytes) */
	uint8_t *value;
	/** length of the randomizer value*/
	uint32_t length;
} RANDOMIZER;

/**
 * \brief MTL Rung
 */
typedef struct RUNG {
	/** Left index of this rung */
	MTL_INDEX left_index;
	/** Right index of this rung */
	MTL_INDEX right_index;
	/** Hash value for this rung (Max Size is OpenSSL EVP_MAX_MD_SIZE - 64 bytes) */
	uint8_t hash[EVP_MAX_MD_SIZE];
	/** Hash length in bytes */
	uint16_t hash_length;
} RUNG;

/**
 * \brief MTL Ladder
 */
typedef struct LADDER {
	/** MTL bit flags */	
	uint16_t flags;
	/** Series ID for the MTL Node Set */	
	SERIESID sid;
	/** Count of the rungs included in this ladder */
	uint16_t rung_count;
	/** Pointer to the rung data */
	RUNG *rungs;
} LADDER;

/**
 * \brief MTL Context
 */
typedef struct MTL_CTX {
	/** Series ID for the MTL Node Set */	
	SERIESID sid;
	/** Flag representing if randomization should be used for these nodes */
	uint8_t randomize;
	/** Pointer to the signature specific message hashing function */
	H_MSG * hash_msg;
	/** Pointer to the signature specific leaf hashing function */
	H_LEAF * hash_leaf;
	/** Pointer to the signature specific node hashing function */
	H_INT * hash_int;
	/** MTL node set structure */
	MTLNODES nodes;
} MTL_CTX;

// Abstract Function Prototypes
/**
 * Set the MTL Scheme Functions
 * @param ctx  the context for this MTL Node Set
 * @param randomize flag indicating if randomization of messages should be used
 * @param hash_msg the scheme specific hash_msg function
 * @param hash_leaf the scheme specific leaf hash function
 * @param hash_node the scheme specific node hash function
 * @return MTLSTATUS MTL_OK if successful
 */
MTLSTATUS mtl_set_scheme_functions(MTL_CTX * ctx,
				   uint8_t randomize,
				   H_LEAF * hash_leaf,
				   H_INT * hash_int);

/**
 * Generate the message hash with randomization and then append to
 * the MTL node set as a leaf node. 
 * @param ctx:         the context for this MTL Node Set
 * @param message:     byte array of message data
 * @param message_len: byte length of the message data
 * @param ctx_str:     byte array of context string
 * @param ctx_str_len: byte length of the context string
 * @param node_id:     return value index of the leaf node that was appended
 * @return MTL_OK on success
 */							
MTLSTATUS mtl_hash_and_append(MTL_CTX * ctx, 
								uint8_t * message, uint16_t message_len, 
								uint8_t * ctx_str, uint16_t ctx_str_len,
								MTL_INDEX * node_id);

/**
 * Setup the MTL randomizer value
 * @param ctx:         the context for this MTL Node Set
 * @param randomizer:  pointer to a randomizer buffer
 * @return MTL_OK on success, other on failure
 */				 
MTLSTATUS mtl_generate_randomizer(MTL_CTX * ctx, RANDOMIZER ** randomizer);

/**
 * Free the MTL randomizer value
 * @param mtl_random:  pointer to a randomizer buffer
 * @return 0 on success int on failure
 */
MTLSTATUS mtl_randomizer_free(RANDOMIZER * mtl_random);

/**
 * Get the MTL Auth path and randomizer value
 * @param ctx,  the context for this MTL Node Set
 * @param leaf_index: index of the leaf node that is being appended
 * @param randomizer: pointer to randomizer buffer 
 * @param auth:       pointer to authpath buffer
 * @return MTL_OK on success
 */
MTLSTATUS mtl_randomizer_and_authpath(MTL_CTX * ctx, MTL_INDEX leaf_index,
				    RANDOMIZER ** randomizer, AUTHPATH ** auth);

/**
 * Generate the message hash with randomization and then verify
 * the hash with the authenticaiton path
 * @param ctx:  the context for this MTL Node Set
 * @param message: message to verify
 * @param message_len: length of the message in bytes
 * @param ctx_str:     byte array of context string
 * @param ctx_str_len: byte length of the context string
 * @param randomizer: randomizer value for this leaf node
 * @param auth_path: authenticaiton path to verify
 * @param assoc_rung: rung used to verify this auth path
 * @return MTL_OK on success
 */
MTLSTATUS mtl_hash_and_verify(MTL_CTX * ctx, 
								uint8_t * message, uint16_t message_len, 
								uint8_t * ctx_str, uint16_t ctx_str_len,
								RANDOMIZER * randomizer, 
								AUTHPATH * auth_path, 
								RUNG * assoc_rung);

// MTL Draft Specification Functions
/**
 * Algorithm 3: Initializing a MTL Node Set.
 * mtl_initns from draft-harvey-cfrg-mtl-mode-00 Section 8.3
 * @param ctx  the context for this MTL Node Set
 * @param sid  series identifier for this node set
 * @return MTLSTATUS: MTL_OK if successful
 */
MTLSTATUS mtl_initns(MTL_CTX ** mtl_ctx, SERIESID * sid);

/**
 * Algorithm 4: MTL Node Set Append.
 * mtl_append from draft-harvey-cfrg-mtl-mode-00 Section 8.4
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
                  MTL_INDEX leaf_index);

/*****************************************************************
* MTL Node Set Update Parent Hashes
******************************************************************
 * @param ctx,  the context for this MTL Node Set
 * @param leaf_index: index of the leaf node that is being appended
 * @return MTL_OK on success
 */
MTLSTATUS mtl_node_set_update_parents(MTL_CTX * ctx, MTL_INDEX leaf_index);

/**
 * Algorithm 5: Computing an Authentication Path for a Data Value.
 * mtl_authpath from draft-harvey-cfrg-mtl-mode-00 Section 8.5
 * @param ctx  the context for this MTL Node Set 
 * @param leaf_index leaf node index of the data value to authenticate
 * @return auth_path authentication path from the leaf node to the associated rung, or NULL on error 
 */		   
AUTHPATH *mtl_authpath(MTL_CTX * ctx, MTL_INDEX leaf_index);

/**
 * Algorithm 6: Computing a Merkle Tree Ladder for a Node Set.
 * mtl_ladder from draft-harvey-cfrg-mtl-mode-00 Section 8.6
 * @param ctx  the context for this MTL Node Set 
 * @return ladder Merkle tree ladder for this node set, or NULL on error
 */
LADDER *mtl_ladder(MTL_CTX * ctx);

/**
 * Algorithm 7: Selecting a Ladder Rung.
 * mtl_rung from draft-harvey-cfrg-mtl-mode-00 Section 8.7
 * @param auth_path authentication path that needs to be covered
 * @param ladder Merkle tree ladder to authenticate relative to
 * @return assoc_rung the rung in the ladder associated with the authentication path, or NULL on error
 */
RUNG *mtl_rung(AUTHPATH * auth_path, LADDER * ladder);

/**
 * Algorithm 8: Verifying an Authentication Path.
 * mtl_verify from draft-harvey-cfrg-mtl-mode-00 Section 8.8
 * @param ctx,  the context for this MTL Node Set  
 * @param data_value: byte array of data_value data
 * @param data_value_len: length of the data_value byte array
 * @param ctx_str: byte array of context string
 * @param ctx_str_len: length of the ctx_str byte array
 * @param randomizer: (presumed) randomizer for corresponding leaf node
 * @param auth_path, (presumed) authentication path from corresponding
 *     leaf node to rung of ladder covering leaf node
 * @param assoc_rung, Merkle tree rung to authenticate relative to
 * @return MTL_OK if path verifies correctly
 */
MTLSTATUS mtl_verify(MTL_CTX * ctx, 
            			uint8_t * data_value, uint16_t data_value_len, 
            			uint8_t * ctx_str, uint16_t ctx_str_len,
            			RANDOMIZER * randomizer,
		   				AUTHPATH * auth_path,
						RUNG * assoc_rung);

// Functions to freeing structures from MTL Draft Specification Functions
/**
 * Free a MTL Context for mtl_initns()
 * @param ctx  the context for this MTL Node Set
 * @return MTLSTATUS MTL_OK if successful
 */
MTLSTATUS mtl_free(MTL_CTX * ctx);

/**
 * Free Authentication Path for mtl_authpath()
 * @param path  Authentication path to ffree
 * @return MTL_OK on success
 */
MTLSTATUS mtl_authpath_free(AUTHPATH * path);

/**
 * Free Ladder for mtl_ladder()
 * @param ladder  Ladder to free
 * @return MTL_OK on success
 */
MTLSTATUS mtl_ladder_free(LADDER * ladder);

// MTL Buffer Functions
/**
 * Create MTL Auth Path from a memory buffer
 * @param buffer      Memory buffer
 * @param buffer_size Memory buffer size
 * @param hash_size   Length of hash algorithm output in bytes
 * @param randomized  0 if not randomized, 1 if message was
 * @param auth_path   Pointer to where the auth path is created
 * @return size of the authpath buffer in bytes
 */
uint32_t mtl_auth_path_from_buffer(uint8_t *buffer, size_t buffer_size, 
					uint32_t hash_size, 
					RANDOMIZER ** randomizer, AUTHPATH ** auth_path);
/**
 * Create memory buffer from MTL Auth Path
 * @param randomizer Pointer to the randomizer value for this node
 * @param auth_path  Pointer to the auth path to convert
 * @param hash_size  Length of hash algorithm output in bytes
 * @param buffer     Pointer to where the buffer is created
 * @return size of the authpath buffer in bytes
 */				   
uint32_t mtl_auth_path_to_buffer(RANDOMIZER * randomizer, AUTHPATH * auth_path,
				 uint32_t hash_size, uint8_t ** buffer);

/**
 * Create MTL Ladder from memory buffer
 * @param buffer      Pointer to the buffer to convert
 * @param buffer_size Memory buffer size
 * @param hash_size   Length of hash algorithm output in bytes
 * @param ladder_ptr  Pointer to where the ladder is created
 * @return size of the ladder buffer in bytes
 */
uint32_t mtl_ladder_from_buffer(uint8_t *buffer, size_t buffer_size,
				uint32_t hash_size, LADDER ** ladder_ptr);

/**
 * Create memory buffer from MTL Ladder
 * @param ladder     Pointer to the ladder to convert
 * @param hash_size  Length of hash algorithm output in bytes
 * @param buffer     Pointer to where the buffer is created
 * @return size of the ladder buffer in bytes
 */
uint32_t mtl_ladder_to_buffer(LADDER * ladder, uint32_t hash_size,
			      uint8_t ** buffer);

#endif				// ___MTL_IMPL_H__
