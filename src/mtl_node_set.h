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
/**
 *  \file mtl_node_set.h
 *  \brief MTL Mode Functions specific to the node sets.
 *  The functions, data, and macros necessary to manage the MTL node set
 *  and allow for lookup, retrieval, and updating of elements in the node set.
*/
#ifndef __MTL_NODE_SET_H__
#define __MTL_NODE_SET_H__

#include <math.h>
#include <openssl/evp.h>
#include <stdint.h>

#include "mtl_error.h"

// Definition of constants used in this application
/** Maximum tree pages allowed to be allocated 
 * \todo Make this configurable for each key set rather than library wide for future use.
*/
#define MTL_TREE_MAX_PAGES 8192
/** Maximum tree pages size in bytes 
 * \todo Make this configurable for each key set rather than library wide for future use.
*/
#define MTL_TREE_PAGE_SIZE 1048576L
/** Maximum randomizer pages allowed to be allocated
 * \todo Make this configurable for each key set rather than library wide for future use.
*/
#define MTL_TREE_RANDOMIZER_PAGES 8192


/** Maximum leaf index supported by a single set
 * 
 */
#define MTL_NODE_SET_MAX_LEAF (uint32_t)0x7fffffff

/** Maximum index supported by an node set
 * 
 */
#define MTL_NODE_SET_MAX_INDEX (2*MTL_NODE_SET_MAX_LEAF)

// Data structures
/**
 * \brief MTL Mode Series ID.
*/
typedef struct SERIESID {
	/** Identfiter Bytes (Max Size is OpenSSL EVP_MAX_MD_SIZE - 64 bytes) */	
	uint8_t id[EVP_MAX_MD_SIZE];
	/** Identifier Length */	
	uint16_t length;
} SERIESID;

/**
 * \brief MTL Mode Seed Value
 */
typedef struct SEED {
	/** Identfiter Bytes (Max Size is OpenSSL EVP_MAX_MD_SIZE - 64 bytes) */	
	uint8_t seed[EVP_MAX_MD_SIZE];
	/** Seed Length */		
	uint16_t length;
} SEED;

/**
 * \brief MTL Node Set Context Structure
 */
typedef struct MTLNODES {
	/** Current count of leaf nodes covered by this node set 
	 * 	We assume leaves are added in order, and any operation 
	 * 	which inserts a node also inserts any lower-index nodes
	 */		
	uint32_t leaf_count;
	/** Size (in bytes) of the hash that is used in the MTL tree */		
	uint16_t hash_size;
	/** Tree page byte buffer allocation pointer */		
	uint8_t *tree_pages[MTL_TREE_MAX_PAGES];
	/** Page size in bytes */		
	uint32_t tree_page_size;
	/** Randomizer page byte buffer allocation pointer */		
	uint8_t *randomizer_pages[MTL_TREE_RANDOMIZER_PAGES];
} MTLNODES;

// Prototypes
/**
 *  MTL node set function to initalize a MTLNS structure
 * @param nodes Pointer to MTL node context to initalize
 * @param seed The seed to use for this MTL node set
 * @param sid series id to use for this MTLNS
 * @return none
 */

void mtl_node_set_init(MTLNODES * nodes, SEED *seed, SERIESID * sid);

/**
 *  MTL node set function to free a MTLNS structure
 * @param nodes Pointer to MTL node context to free
 * @return none
 */

void mtl_node_set_free(MTLNODES * nodes);
/**
 *  MTL node set insert to put the hash value in the MTLNS
 * @param nodes Pointer to the MTLNS structure
 * @param left left index of the node to insert
 * @param right right index of the node to insert
 * @param hash hash value to insert
 * @return MTL_OK if successful
 */
MTLSTATUS mtl_node_set_insert(MTLNODES * nodes, uint32_t left, uint32_t right,
			    uint8_t * hash);

/**
 *  MTL node set insert randomizer
 * @param nodes Pointer to MTL node context to initalize
 * @param leaf_index The leaf index that utilizes the randomizer
 * @param rand randomizer value to insert (NULL for none)
 * @return MTL_OK if successful
 */
MTLSTATUS mtl_node_set_insert_randomizer(MTLNODES * nodes,
				       uint32_t leaf_index, uint8_t * rand);

/**
 *  Fetch the node hash for a given index from the MTLNS
 * @param nodes Pointer to the MTLNS structure
 * @param left left index of the node to fetch
 * @param right right index of the node to fetch
 * @param hash pointer to fill with the hash value (caller must free)
 * @return MTL_OK if successful
 */					   
MTLSTATUS mtl_node_set_fetch(MTLNODES * node_set, uint32_t left, uint32_t right,
			   uint8_t ** hash);

/**
 *  Fetch the randomizer for a given index from the MTLNS
 * @param nodes Pointer to the MTLNS structure
 * @param leaf leaf index of the randomizer to fetch
 * @param rand pointer to fill with the hash value (caller must free)
 * @return MTL_OK if successful
 */			   
MTLSTATUS mtl_node_set_get_randomizer(MTLNODES * nodes, uint32_t leaf,
				    uint8_t ** rand);

/**
 *  MTLNS mapping function from left/right to linear page array
 * @param left: left index of the node to insert
 * @param right: right index of the node to insert
 * @param return_index: output address for index of left and right LCA
 * @return MTL_OK if successful, and *return_index set
 * 			MTL_ERROR if <left,right> is not a valid node
 */
MTLSTATUS mtl_node_set_int_node_id(uint32_t left, uint32_t right, uint32_t * return_index);

/**
 *  MTL implementation of bit_width
 * @param number number to evaluate
 * @return number of 1's in the number
 */
uint32_t mtl_bit_width(uint32_t number);

/**
 *  MTL implementation of lsb
 * @param number number to evaluate
 * @return index of the least significant bit
 */
uint32_t mtl_lsb(uint32_t number);

/**
 *  MTL implementation of msb
 * @param number number to evaluate
 * @return index of the most significant bit
 */
uint32_t mtl_msb(uint32_t number);

#endif
