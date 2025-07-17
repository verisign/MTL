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
void mtl_node_set_init(MTLNODES * nodes, SEED *seed, SERIESID * sid)
{
	uint16_t index;
	// Reserved for future needs
	sid = sid;

	if (nodes == NULL) {
		LOG_ERROR("Null parameters provided");
		return;
	}

	nodes->leaf_count = 0;
	nodes->hash_size = seed->length;
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
 * @return MTL_OK if successful
 */
MTLSTATUS mtl_node_set_insert(MTLNODES * nodes, uint32_t left, uint32_t right,
			    uint8_t * hash)
{
	uint32_t index;
	uint16_t page;
	uint64_t offset;

	if ((nodes == NULL) || (hash == NULL)) {
		LOG_ERROR("Null parameters provided");
		return MTL_BAD_PARAM;
	}

	if (mtl_node_set_int_node_id(left, right, &index) != MTL_OK)
	{
		LOG_ERROR("Attempted to insert invalid node");
		return MTL_BAD_PARAM;
	}
	page = (index * nodes->hash_size) / nodes->tree_page_size;
	offset = (index * nodes->hash_size) % nodes->tree_page_size;

	if (page >= MTL_TREE_MAX_PAGES) {
		LOG_ERROR("Tree entry out of range");
		return MTL_BAD_PARAM;
	}
	// Add a new tree page if memory is not already allocated
	if (nodes->tree_pages[page] == NULL) {
		nodes->tree_pages[page] = calloc(1, nodes->tree_page_size);
		if (nodes->tree_pages[page] == NULL) {
			LOG_ERROR("Unable to allocate memory");
			return MTL_RESOURCE_FAIL;
		}
	}

	uint8_t *buffer = nodes->tree_pages[page] + offset;
	memcpy(buffer, hash, nodes->hash_size);

	// Update leaf count
	// We assume all nodes lower than current leaf are added atomically
	nodes-> leaf_count = right+1 > nodes->leaf_count ? right+1 : nodes->leaf_count;

	return MTL_OK;
}

/*****************************************************************
*  MTL node set insert randomizer
******************************************************************
 * @param nodes: Pointer to MTL node context to initalize
 * @param leaf_index: The leaf index that utilizes the randomizer
 * @param rand: randomizer value to insert (NULL for none)
 * @return MTL_OK on success
 */
MTLSTATUS mtl_node_set_insert_randomizer(MTLNODES * nodes,
				       uint32_t leaf_index, uint8_t * rand)
{
	uint16_t page;
	uint64_t offset;
	uint32_t index;

	if ((nodes == NULL) || (rand == NULL)) {
		LOG_ERROR("Null parameters provided");
		return MTL_BAD_PARAM;
	}
	if (mtl_node_set_int_node_id(leaf_index, leaf_index, &index) != MTL_OK)
	{
		LOG_ERROR("Attempted to insert invalid node randomizer");
		return MTL_BAD_PARAM;
	}

	page = (leaf_index * nodes->hash_size) / nodes->tree_page_size;
	offset = (leaf_index * nodes->hash_size) % nodes->tree_page_size;

	if (page >= MTL_TREE_RANDOMIZER_PAGES) {
		LOG_ERROR("Tree entry out of range");
		return MTL_BAD_PARAM;
	}

	if (nodes->randomizer_pages[page] == NULL) {
		nodes->randomizer_pages[page] =
		    calloc(1, nodes->tree_page_size);
		if (nodes->randomizer_pages[page] == NULL) {
			LOG_ERROR("Unable to allocate memory");
			return MTL_RESOURCE_FAIL;
		}
	}

	uint8_t *buffer = nodes->randomizer_pages[page] + offset;
	memcpy(buffer, rand, nodes->hash_size);

	return MTL_OK;
}

/*****************************************************************
*  Fetch the node hash for a given index from the MTLNS
******************************************************************
 * @param nodes: Pointer to the MTLNS structure
 * @param left: left index of the node to fetch
 * @param right: right index of the node to fetch
 * @param hash: pointer to fill with the hash value (caller must free)
 * @return MTL_OK if successful
 */
MTLSTATUS mtl_node_set_fetch(MTLNODES * nodes, uint32_t left, uint32_t right,
			   uint8_t ** hash)
{
	if ((nodes == NULL) || (hash == NULL)) {
		LOG_ERROR("Null parameters provided");
		return MTL_BAD_PARAM;
	}

	uint32_t index;
	if (mtl_node_set_int_node_id(left, right, &index) != MTL_OK)
	{
		LOG_ERROR("Attempted to fetch invalid node");
		return MTL_BAD_PARAM;
	}
	if (right+1 > nodes->leaf_count)
	{
		LOG_ERROR("Attempted to fetch node before insert");
		return MTL_ERROR;
	}
	uint16_t page = (index * nodes->hash_size) / nodes->tree_page_size;
	uint64_t offset = (index * nodes->hash_size) % nodes->tree_page_size;

	// Check that the page exists
	if ((page >= MTL_TREE_MAX_PAGES) || (nodes->tree_pages[page] == NULL)) {
		*hash = NULL;
		LOG_ERROR("Null parameters provided");
		return MTL_BAD_PARAM;
	}

	*hash = malloc(nodes->hash_size);
	if (*hash == NULL) {
		LOG_ERROR("Unable to allocate memory");
		return MTL_RESOURCE_FAIL;
	}
	uint8_t *buffer = nodes->tree_pages[page] + offset;
	memcpy(*hash, buffer, nodes->hash_size);
	return MTL_OK;
}

/*****************************************************************
*  Fetch the randomizer for a given index from the MTLNS
******************************************************************
 * @param nodes: Pointer to the MTLNS structure
 * @param leaf: leaf index of the randomizer to fetch
 * @param rand: pointer to fill with the hash value (caller must free)
 * @return MTL_OK if successful
 */
MTLSTATUS mtl_node_set_get_randomizer(MTLNODES * nodes, uint32_t leaf,
				    uint8_t ** rand)
{
	uint16_t page;
	uint64_t offset;
	uint32_t index;

	if ((nodes == NULL) || (rand == NULL)) {
		LOG_ERROR("Null parameters provided");
		return MTL_BAD_PARAM;
	}
	if (mtl_node_set_int_node_id(leaf, leaf, &index) != MTL_OK)
	{
		LOG_ERROR("Attempted to get invalid node randomizer");
		return MTL_BAD_PARAM;
	}
	// We assume leaves and their randomizers are set at the same time
	if (leaf+1 > nodes->leaf_count)
	{
		LOG_ERROR("Attempted to fetch randomizer before insert");
		return MTL_ERROR;
	}

	*rand = NULL;
	page = (leaf * nodes->hash_size) / nodes->tree_page_size;
	offset = (leaf * nodes->hash_size) % nodes->tree_page_size;

	// Check that the page exists
	if ((page >= MTL_TREE_RANDOMIZER_PAGES)
	    || (nodes->randomizer_pages[page] == NULL)) {
		LOG_ERROR("Invalid id provided");
		return MTL_ERROR;
	}

	*rand = malloc(nodes->hash_size);
	if (*rand == NULL) {
		LOG_ERROR_WITH_CODE("mtl_node_set_get_randomizer",MTL_NULL_PTR);
	}
	uint8_t *buffer = nodes->randomizer_pages[page] + offset;
	memcpy(*rand, buffer, nodes->hash_size);

	return MTL_OK;
}

/*****************************************************************
*  Determine if two leaves bound a complete subtree
******************************************************************
 * @param left: left index of the tested subtree
 * @param right: right index of the tested subtree
 * @return MTL_OK if the indices are valid, MTL_BAD_PARAM if not
 */
MTLSTATUS mtl_node_is_valid_subtree(uint32_t left, uint32_t right)
{
	uint32_t prefix_bitmask, postfix_bitmask, i;

	// Subtree must have non-negative size
	if ( right < left )
	{
		return MTL_BAD_PARAM;
	}
	// Both indices must be valid leaf indices
	if ( right > MTL_NODE_SET_MAX_LEAF || left > MTL_NODE_SET_MAX_LEAF )
	{
		return MTL_BAD_PARAM;
	}
	// Subtree is defined by a common prefix
	prefix_bitmask = 0xffffffff;
	for (i = 0; i < 32; i++)
	{
		if( (left & prefix_bitmask) == (right & prefix_bitmask) )
		{
			break;
		}
		// remove bits on the right until the prefixes match
		prefix_bitmask -= (1 << i);
	}
	// Leftmost node of subtree is all 0 after prefix; rightmost is all 1
	postfix_bitmask = ~prefix_bitmask;
	if ( (left & postfix_bitmask) != 0 
		|| (right & postfix_bitmask) != postfix_bitmask )
	{
		return MTL_BAD_PARAM;
	}

	return MTL_OK;
		
}

/*****************************************************************
*  MTLNS mapping function from left/right to linear page array
******************************************************************
 * @param left: left index of the node to insert
 * @param right: right index of the node to insert
 * @param return_index: output address for index of left and right LCA
 * @return MTL_OK if successful, and *return_index set
 * 			MTL_ERROR if <left,right> is not a valid node
 */
MTLSTATUS mtl_node_set_int_node_id(uint32_t left, uint32_t right, uint32_t * return_index)
{
	if ( return_index == NULL ) 
	{
		LOG_ERROR("Input null pointer to interior node calculation");
		return MTL_NULL_PTR;
	}
	// int_node_id function is only defined over valid subtrees
	if ( mtl_node_is_valid_subtree(left, right) != MTL_OK )
	{
		LOG_ERROR("Tried to access invalid subtree");
		return MTL_BAD_PARAM;
	}
	else {
		*return_index =  2 * (right + 1) - mtl_bit_width(right + 1) 
			- mtl_lsb(right + 1) + mtl_msb(right - left + 1) - 1;
	}
	return MTL_OK;
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
