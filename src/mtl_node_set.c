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
#include <string.h>

#include "mtl_error.h"
#include "mtl_node_set.h"

/*****************************************************************
*  MTL node set function to initalize a MTLNS structure
******************************************************************
 * @param nodes: Pointer to MTL node context to initalize
 * @param seed: The seed to use for this MTL node set
 * @param sid: series id to use for this MTLNS
 * @return none
 */
void mtl_node_set_init(MTLNODES * nodes, SEED seed, SERIESID * sid)
{
	uint16_t index;
	// Reserved for future needs
	sid = sid;

	if (nodes == NULL) {
		LOG_ERROR("Null parameters provided");
		return;
	}

	nodes->leaf_count = 0;
	nodes->hash_size = seed.length;
	nodes->tree_page_size = MTL_TREE_PAGE_SIZE;
	// Initalize the tree pages
	for (index = 0; index < MTL_TREE_MAX_PAGES; index++) {
		nodes->tree_pages[index] = NULL;
	}
	// Initalize the randomizer pages
	for (index = 0; index < MTL_TREE_RANDOMIZER_PAGES; index++) {
		nodes->randomizer_pages[index] = NULL;
	}
}

/*****************************************************************
*  MTL node set function to free a MTLNS structure
******************************************************************
 * @param nodes: Pointer to MTL node context to free
 * @return none
 */
void mtl_node_set_free(MTLNODES * nodes)
{
	uint16_t index;

	if (nodes == NULL) {
		return;
	}
	// Free the tree pages
	for (index = 0; index < MTL_TREE_MAX_PAGES; index++) {
		if (nodes->tree_pages[index] != NULL) {
			free(nodes->tree_pages[index]);
			nodes->tree_pages[index] = NULL;
		}
	}

	// Free the randomizer pages
	for (index = 0; index < MTL_TREE_RANDOMIZER_PAGES; index++) {
		if (nodes->randomizer_pages[index] != NULL) {
			free(nodes->randomizer_pages[index]);
			nodes->randomizer_pages[index] = NULL;
		}
	}

	nodes->leaf_count = 0;
	nodes->hash_size = 0;
	nodes->tree_page_size = 0;
}

/*****************************************************************
*  MTL node set insert to put the hash value in the MTLNS
******************************************************************
 * @param nodes: Pointer to the MTLNS structure
 * @param left: left index of the node to insert
 * @param right: right index of the node to insert
 * @param hash: hash value to insert
 * @param rand: randomizer value to insert (NULL for none)
 * @return 0 if successful
 */
uint8_t mtl_node_set_insert(MTLNODES * nodes, uint32_t left, uint32_t right,
			    uint8_t * hash)
{
	uint32_t index;
	uint16_t page;
	uint64_t offset;

	if ((nodes == NULL) || (hash == NULL)) {
		LOG_ERROR("Null parameters provided");
		return 1;
	}

	index = mtl_node_set_int_node_id(left, right);
	page = (index * nodes->hash_size) / nodes->tree_page_size;
	offset = (index * nodes->hash_size) % nodes->tree_page_size;

	if (page >= MTL_TREE_MAX_PAGES) {
		LOG_ERROR("Tree entry out of range");
		return 1;
	}
	// Add a new tree page if memory is not already allocated
	if (nodes->tree_pages[page] == NULL) {
		nodes->tree_pages[page] = calloc(1, nodes->tree_page_size);
		if (nodes->tree_pages[page] == NULL) {
			LOG_ERROR("Unable to allocate memory");
			return 2;
		}
	}

	uint8_t *buffer = nodes->tree_pages[page] + offset;
	memcpy(buffer, hash, nodes->hash_size);

	return 0;
}

uint8_t mtl_node_set_insert_randomizer(MTLNODES * nodes,
				       uint32_t leaf_index, uint8_t * rand)
{
	uint16_t page;
	uint64_t offset;

	if ((nodes == NULL) || (rand == NULL)) {
		LOG_ERROR("Null parameters provided");
		return 1;
	}

	page = (leaf_index * nodes->hash_size) / nodes->tree_page_size;
	offset = (leaf_index * nodes->hash_size) % nodes->tree_page_size;

	if (page >= MTL_TREE_RANDOMIZER_PAGES) {
		LOG_ERROR("Tree entry out of range");
		return 1;
	}

	if (nodes->randomizer_pages[page] == NULL) {
		nodes->randomizer_pages[page] =
		    calloc(1, nodes->tree_page_size);
		if (nodes->randomizer_pages[page] == NULL) {
			LOG_ERROR("Unable to allocate memory");
			return 2;
		}
	}

	uint8_t *buffer = nodes->randomizer_pages[page] + offset;
	memcpy(buffer, rand, nodes->hash_size);

	return 0;
}

/*****************************************************************
*  Fetch the node hash for a given index from the MTLNS
******************************************************************
 * @param nodes: Pointer to the MTLNS structure
 * @param left: left index of the node to fetch
 * @param right: right index of the node to fetch
 * @param hash: pointer to fill with the hash value (caller must free)
 * @return 0 if successful
 */
uint8_t mtl_node_set_fetch(MTLNODES * nodes, uint32_t left, uint32_t right,
			   uint8_t ** hash)
{
	if ((nodes == NULL) || (hash == NULL)) {
		LOG_ERROR("Null parameters provided");
		return 1;
	}

	uint32_t index = mtl_node_set_int_node_id(left, right);
	uint16_t page = (index * nodes->hash_size) / nodes->tree_page_size;
	uint64_t offset = (index * nodes->hash_size) % nodes->tree_page_size;

	// Check that the page exists
	if ((page >= MTL_TREE_MAX_PAGES) || (nodes->tree_pages[page] == NULL)) {
		*hash = NULL;
		LOG_ERROR("Null parameters provided");
		return 1;
	}

	*hash = malloc(nodes->hash_size);
	if (*hash == NULL) {
		LOG_ERROR("Unable to allocate memory");
		return 2;
	}
	uint8_t *buffer = nodes->tree_pages[page] + offset;
	memcpy(*hash, buffer, nodes->hash_size);
	return 0;
}

/*****************************************************************
*  Fetch the randomizer for a given index from the MTLNS
******************************************************************
 * @param nodes: Pointer to the MTLNS structure
 * @param leaf: leaf index of the randomizer to fetch
 * @param rand: pointer to fill with the hash value (caller must free)
 * @return 0 if successful
 */
uint8_t mtl_node_set_get_randomizer(MTLNODES * nodes, uint32_t leaf,
				    uint8_t ** rand)
{
	uint16_t page;
	uint64_t offset;

	if ((nodes == NULL) || (rand == NULL)) {
		LOG_ERROR("Null parameters provided");
		return 1;
	}

	*rand = NULL;
	page = (leaf * nodes->hash_size) / nodes->tree_page_size;
	offset = (leaf * nodes->hash_size) % nodes->tree_page_size;

	// Check that the page exists
	if ((page >= MTL_TREE_RANDOMIZER_PAGES)
	    || (nodes->randomizer_pages[page] == NULL)) {
		LOG_ERROR("Invalid id provided");
		return 2;
	}

	*rand = malloc(nodes->hash_size);
	uint8_t *buffer = nodes->randomizer_pages[page] + offset;
	memcpy(*rand, buffer, nodes->hash_size);

	return 0;
}

/*****************************************************************
*  MTLNS mapping function from left/right to linear page array
******************************************************************
 * @param left: left index of the node to insert
 * @param right: right index of the node to insert
 * @return array index
 */
uint32_t mtl_node_set_int_node_id(uint32_t left, uint32_t right)
{
	return 2 * (right + 1) - mtl_bit_width(right + 1) - mtl_lsb(right + 1) +
	    mtl_msb(right - left + 1) - 1;;
}

/*****************************************************************
*  MTL implementation of bit_width
******************************************************************
 * @param number: number to evaluate
 * @return number of 1's in the number
 */
uint32_t mtl_bit_width(uint32_t number)
{
	return __builtin_popcountl(number);
}

/*****************************************************************
*  MTL implementation of lsb
******************************************************************
 * @param number: number to evaluate
 * @return index of the least significant bit
 */
uint32_t mtl_lsb(uint32_t number)
{
	return __builtin_ffsl(number) - 1;
}

/*****************************************************************
*  MTL implementation of msb
******************************************************************
 * @param number: number to evaluate
 * @return index of the most significant bit
 */
uint32_t mtl_msb(uint32_t number)
{
	if (number == 0)
		return 0;
	return (sizeof(uint32_t) * 8) - __builtin_clz(number) - 1;
}
