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
#ifndef __MTL_NODE_SET_H__
#define __MTL_NODE_SET_H__

#include <math.h>
#include <openssl/evp.h>
#include <stdint.h>

// Definition of constants used in this application
// TODO: Would be nice to make this configurable for the future so
//     that it can be cusomized for different key sets
#define MTL_TREE_MAX_PAGES 1024
#define MTL_TREE_PAGE_SIZE 1048576L
#define MTL_TREE_RANDOMIZER_PAGES 1024

// Data structures
typedef struct SERIESID {
	uint8_t id[EVP_MAX_MD_SIZE];
	uint16_t length;
} SERIESID;

typedef struct SEED {
	uint8_t seed[EVP_MAX_MD_SIZE];
	uint16_t length;
} SEED;

typedef struct MTLNODES {
	uint32_t leaf_count;
	uint16_t hash_size;
	uint8_t *tree_pages[MTL_TREE_MAX_PAGES];
	uint32_t tree_page_size;
	uint8_t *randomizer_pages[MTL_TREE_RANDOMIZER_PAGES];
} MTLNODES;

// Prototypes
void mtl_node_set_init(MTLNODES * nodes, SEED seed, SERIESID * sid);
void mtl_node_set_free(MTLNODES * nodes);
uint8_t mtl_node_set_insert(MTLNODES * nodes, uint32_t left, uint32_t right,
			    uint8_t * hash);
uint8_t mtl_node_set_insert_randomizer(MTLNODES * nodes,
				       uint32_t leaf_index, uint8_t * rand);
uint8_t mtl_node_set_fetch(MTLNODES * node_set, uint32_t left, uint32_t right,
			   uint8_t ** hash);
uint8_t mtl_node_set_get_randomizer(MTLNODES * nodes, uint32_t leaf,
				    uint8_t ** rand);
uint32_t mtl_node_set_int_node_id(uint32_t left, uint32_t right);
uint32_t mtl_bit_width(uint32_t number);
uint32_t mtl_lsb(uint32_t number);
uint32_t mtl_msb(uint32_t number);

#endif
