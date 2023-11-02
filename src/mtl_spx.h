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
#ifndef __MTL_SPX_IMPL_H__
#define __MTL_SPX_IMPL_H__

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "mtl_node_set.h"
#include <math.h>

// Definitions
#define SPX_ADRS_MTL_MSG 16
#define SPX_ADRS_MTL_DATA 17
#define SPX_ADRS_MTL_TREE 18
#define SPX_ADRS_MTL_LADDER 19

#define ADRS_LAYER_ADDR 0*4
#define ADRS_TREE_ADDR 1*4
#define ADRS_TYPE_ADDR 4*4
#define ADRS_ADDR_1 5*4
#define ADRS_ADDR_2 6*4
#define ADRS_ADDR_3 7*4

#define ADRS_LAYER_ADDR_LEN 4
#define ADRS_TREE_ADDR_LEN 12
#define ADRS_TYPE_ADDR_LEN 4
#define ADRS_ADDR_1_LEN 4
#define ADRS_ADDR_2_LEN 4
#define ADRS_ADDR_3_LEN 4

#define ADRS_LAYER_ADDR_C 0	// 1 1-4
#define ADRS_TREE_ADDR_C  1	// 8 5-16
#define ADRS_TYPE_ADDR_C  9	// 4 17-20
#define ADRS_ADDR_1_C     13	// 1 21-24
#define ADRS_ADDR_2_C     14	// 4 25-28
#define ADRS_ADDR_3_C     18	// 4 29-32

#define ADRS_LAYER_ADDR_C_LEN 1	// 1 1-4
#define ADRS_TREE_ADDR_C_LEN  8	// 8 5-16
#define ADRS_TYPE_ADDR_C_LEN  4	// 4 17-20
#define ADRS_ADDR_1_C_LEN     1	// 1 21-24
#define ADRS_ADDR_2_C_LEN     4	// 4 25-28
#define ADRS_ADDR_3_C_LEN     4	// 4 29-32

#define ADRS_ADDR_SIZE 32
#define ADRS_ADDR_SIZE_C 22

#define SPX_MTL_SHA2 1
#define SPX_MTL_SHAKE 2

// Types & Structures
typedef struct SPK_PUBKEY {
	uint8_t key[EVP_MAX_MD_SIZE];
	uint16_t length;
} SPK_PUBKEY;

typedef struct SPK_PRF {
	uint8_t data[EVP_MAX_MD_SIZE];
	uint16_t length;
} SPK_PRF;

typedef struct SPX_PARAMS {
	SEED pk_seed;
	SPK_PUBKEY pk_root;
	SPK_PRF prf;
	uint8_t robust;
} SPX_PARAMS;

// Function Prototypes
uint8_t spx_mtl_node_set_prf_msg_sha2(uint8_t * skprf, uint32_t skprf_len,
				      uint8_t * optrand, uint32_t optrand_len,
				      uint8_t * message, uint32_t message_len,
				      uint8_t * rmtl, uint32_t hash_len);
uint8_t spx_mtl_node_set_prf_msg_shake(uint8_t * skprf, uint32_t skprf_len,
				       uint8_t * optrand, uint32_t optrand_len,
				       uint8_t * message, uint32_t message_len,
				       uint8_t * rmtl, uint32_t hash_len);
uint8_t mtlns_adrs_compressed(uint8_t * ADRS, uint8_t type, SERIESID * sid,
			      uint32_t left, uint32_t right);
uint8_t mtlns_adrs_full(uint8_t * ADRS, uint32_t type, SERIESID * sid,
			uint32_t left, uint32_t right);

uint8_t spx_mtl_node_set_hash_message_sha2(void *parameters,
					   SERIESID * sid,
					   uint32_t node_id,
					   uint8_t * randomizer,
					   uint32_t randomizer_len,
					   uint8_t * msg_buffer,
					   uint32_t msg_length, uint8_t * hash,
					   uint32_t hash_length);
uint8_t spx_mtl_node_set_hash_message_shake(void *parameters,
					    SERIESID * sid,
					    uint32_t node_id,
					    uint8_t * randomizer,
					    uint32_t randomizer_len,
					    uint8_t * msg_buffer,
					    uint32_t msg_length, uint8_t * hash,
					    uint32_t hash_length);
uint8_t spx_mtl_node_set_hash_message(void *parameters,
				      SERIESID * sid,
				      uint32_t node_id,
				      uint8_t * randomizer,
				      uint32_t randomizer_len,
				      uint8_t * msg_buffer, uint32_t msg_length,
				      uint8_t * hash, uint32_t hash_length,
				      uint8_t algorithm);

uint8_t spx_mtl_node_set_hash_int(void *parameters,
				  SERIESID * sid,
				  uint32_t node_left,
				  uint32_t node_right,
				  uint8_t * hash_left,
				  uint8_t * hash_right, uint8_t * hash,
				  uint32_t hash_len, uint8_t algorithm);
uint8_t spx_mtl_node_set_hash_leaf(void *parameters, SERIESID * sid,
				   uint32_t node_id, uint8_t * msg_buffer,
				   uint32_t msg_buffer_len, uint8_t * hash,
				   uint32_t hash_len, uint8_t algorithm);

uint8_t spx_mtl_node_set_hash_leaf_sha2(void *parameter,
					SERIESID * sid,
					uint32_t node_id,
					uint8_t * msg_buffer,
					uint32_t msg_buffer_len, uint8_t * hash,
					uint32_t hash_len);
uint8_t spx_mtl_node_set_hash_leaf_shake(void *parameters, SERIESID * sid,
					 uint32_t node_id, uint8_t * msg_buffer,
					 uint32_t msg_buffer_len,
					 uint8_t * hash, uint32_t hash_len);

uint8_t spx_mtl_node_set_hash_int_sha2(void *parameters,
				       SERIESID * sid,
				       uint32_t node_left,
				       uint32_t node_right,
				       uint8_t * hash_left,
				       uint8_t * hash_right, uint8_t * hash,
				       uint32_t hash_len);
uint8_t spx_mtl_node_set_hash_int_shake(void *parameters, SERIESID * sid,
					uint32_t node_left, uint32_t node_right,
					uint8_t * hash_left,
					uint8_t * hash_right, uint8_t * hash,
					uint32_t hash_len);

uint8_t spx_sha2(uint8_t * seed, uint32_t seed_len,
		 uint8_t * adrs, uint32_t adrs_len,
		 uint8_t * data, uint32_t data_len,
		 uint8_t * hash, uint32_t hash_len);
uint8_t spx_shake(uint8_t * seed, uint32_t seed_len,
		  uint8_t * adrs, uint32_t adrs_len,
		  uint8_t * data, uint32_t data_len,
		  uint8_t * hash, uint32_t hash_len);

#endif				//__MTL_SPX_IMPL_H__
