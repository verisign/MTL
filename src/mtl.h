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
#ifndef __MTL_IMPL_H__
#define __MTL_IMPL_H__

#include <math.h>
#include <openssl/evp.h>
#include <stdint.h>

#include "mtl_error.h"
#include "mtl_node_set.h"

#define MTL_SID_SIZE 8

// Return Status Values
typedef enum { MTL_OK, MTL_NULL_PTR, MTL_RESOURCE_FAIL } MTLSTATUS;

// Data Structures
typedef struct AUTHPATH {
	uint16_t flags;
	SERIESID sid;
	uint32_t leaf_index;
	uint32_t rung_left;
	uint32_t rung_right;
	uint16_t sibling_hash_count;
	uint8_t *sibling_hash;
} AUTHPATH;

typedef struct RANDOMIZER {
	uint8_t *value;
	uint32_t length;
} RANDOMIZER;

typedef struct RUNG {
	uint32_t left_index;
	uint32_t right_index;
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_length;
} RUNG;

typedef struct LADDER {
	uint16_t flags;
	SERIESID sid;
	uint16_t rung_count;
	RUNG *rungs;
} LADDER;

typedef struct MTL_CTX {
	SEED seed;
	SERIESID sid;

	uint8_t randomize;
	void *sig_params;
	 uint8_t(*hash_msg) (void *params, SERIESID * sid, uint32_t node_id,
			     uint8_t * randomizer, uint32_t randomizer_len,
			     uint8_t * msg_buffer, uint32_t msg_length,
			     uint8_t * hash, uint32_t hash_length);
	 uint8_t(*hash_leaf) (void *params, SERIESID * sid, uint32_t node_id,
			      uint8_t * msg_buffer, uint32_t msg_length,
			      uint8_t * hash, uint32_t hash_length);
	 uint8_t(*hash_node) (void *params, SERIESID * sid, uint32_t left_index,
			      uint32_t right_index, uint8_t * left_hash,
			      uint8_t * right_hash, uint8_t * hash,
			      uint32_t hash_length);
	MTLNODES nodes;

} MTL_CTX;

// Abstract Function Prototypes
MTLSTATUS mtl_set_scheme_functions(MTL_CTX * ctx, void *parameters,
				   uint8_t randomize,
				   uint8_t(*hash_msg) (void *parameters,
						       SERIESID * sid,
						       uint32_t node_id,
						       uint8_t * randomizer,
						       uint32_t randomizer_len,
						       uint8_t * msg_buffer,
						       uint32_t msg_length,
						       uint8_t * hash,
						       uint32_t hash_length),
				   uint8_t(*hash_leaf) (void *params,
							SERIESID * sid,
							uint32_t node_id,
							uint8_t * msg_buffer,
							uint32_t msg_length,
							uint8_t * hash,
							uint32_t hash_length),
				   uint8_t(*hash_node) (void *params,
							SERIESID * sid,
							uint32_t left_index,
							uint32_t right_index,
							uint8_t * left_hash,
							uint8_t * right_hash,
							uint8_t * hash,
							uint32_t hash_length));
uint32_t mtl_hash_and_append(MTL_CTX * ctx, uint8_t * message,
			     uint16_t message_len);
uint8_t mtl_generate_randomizer(MTL_CTX * ctx, RANDOMIZER ** randomizer);
MTLSTATUS mtl_randomizer_free(RANDOMIZER * mtl_random);
uint8_t mtl_randomizer_and_authpath(MTL_CTX * ctx, uint32_t leaf_index,
				    RANDOMIZER ** randomizer, AUTHPATH ** auth);
uint8_t mtl_hash_and_verify(MTL_CTX * ctx, uint8_t * message,
			    uint16_t message_len, RANDOMIZER * randomizer,
			    AUTHPATH * auth_path, RUNG * assoc_rung);
uint32_t mtl_get_scheme_separated_buffer(MTL_CTX * ctx, LADDER * ladder,
					 uint32_t hash_size, uint8_t ** buffer);

// MTL Draft Specifictaion Functions
MTLSTATUS mtl_initns(MTL_CTX ** ctx, SEED seed, SERIESID * sid);
uint8_t mtl_append(MTL_CTX * ctx, uint8_t * data_value,
		   uint16_t data_value_len, uint32_t leaf_index);
AUTHPATH *mtl_authpath(MTL_CTX * ctx, uint32_t leaf_index);
LADDER *mtl_ladder(MTL_CTX * ctx);
RUNG *mtl_rung(AUTHPATH * auth_path, LADDER * ladder);
uint8_t mtl_verify(MTL_CTX * ctx, uint8_t * data_value,
		   uint16_t data_value_len, AUTHPATH * auth_path,
		   RUNG * assoc_rung);

// Functions to freeing structures from MTL Draft Specification Functions
MTLSTATUS mtl_free(MTL_CTX * ctx);
MTLSTATUS mtl_authpath_free(AUTHPATH * path);
MTLSTATUS mtl_ladder_free(LADDER * ladder);

// MTL Buffer Functions
uint32_t mtl_auth_path_from_buffer(char *buffer, uint32_t hash_size,
				   uint16_t sid_len, RANDOMIZER ** randomizer,
				   AUTHPATH ** auth_path);
uint32_t mtl_auth_path_to_buffer(RANDOMIZER * randomizer, AUTHPATH * auth_path,
				 uint32_t hash_size, uint8_t ** buffer);
uint32_t mtl_ladder_from_buffer(char *buffer, uint32_t hash_size,
				uint16_t sid_len, LADDER ** ladder_ptr);
uint32_t mtl_ladder_to_buffer(LADDER * ladder, uint32_t hash_size,
			      uint8_t ** buffer);

#endif				// ___MTL_IMPL_H__
