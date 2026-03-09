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
#include <stdio.h>
#include "mtl_error.h"
#include "mtl_node_set.h"
#include <assert.h>
#include <string.h>

#include "mtltest.h"

// Prototypes for testing functions
uint8_t mtltest_mtl_node_set_init(void);
uint8_t mtltest_mtl_node_set_init_null(void);
uint8_t mtltest_mtl_node_set_insert(void);
uint8_t mtltest_mtl_node_set_fetch(void);
uint8_t mtltest_mtl_node_set_get_randomizer(void);
uint8_t mtltest_mtl_node_set_get_randomizer_null(void);
uint8_t mtltest_mtl_node_set_maximum(void);

uint8_t mtltest_mtl_lsb(void);
uint8_t mtltest_mtl_msb(void);
uint8_t mtltest_mtl_bit_width(void);
uint8_t mtltest_mtl_node_id(void);
uint8_t mtltest_mtl_node_id_invalid(void);

uint8_t mtltest_mtl_node_set(void)
{
	NEW_TEST("MTL Node Set Tests");

	RUN_TEST(mtltest_mtl_lsb, "Verify the lsb function");
	RUN_TEST(mtltest_mtl_msb, "Verify the msb function");
	RUN_TEST(mtltest_mtl_bit_width, "Verify the bit_width function");
	RUN_TEST(mtltest_mtl_node_id, "Verify the hash tree id map");
	RUN_TEST(mtltest_mtl_node_id_invalid, "Verify the hash tree id map w/invalid parameters");

	RUN_TEST(mtltest_mtl_node_set_init, "Verify node set initalization");
	RUN_TEST(mtltest_mtl_node_set_init_null,
		 "Verify node set initalization w/null parameter");
	RUN_TEST(mtltest_mtl_node_set_insert,
		 "Verify node set insert operations");
	RUN_TEST(mtltest_mtl_node_set_fetch,
		 "Verify node set fetch operations");
	RUN_TEST(mtltest_mtl_node_set_get_randomizer,
		 "Verify randomizer fetch operations");
	RUN_TEST(mtltest_mtl_node_set_get_randomizer_null,
		 "Verify randomizer fetch operations w/null parameters");

// This test has a long runtime, so it's optional during development
// Recommended to run it before release
#ifdef TEST_FULL
	RUN_TEST(mtltest_mtl_node_set_maximum, "Testing maximum-size tree");
#endif
	return 0;
}

/**
 * Test the mtl node id initialzation function
 * This is the successful allocation and free test
 */
uint8_t mtltest_mtl_node_set_init(void)
{
	MTLNODES nodes;
	uint32_t index;
	SERIESID sid;
	uint16_t hash_len = 16;
	uint8_t sid_val[] = {  // Randomly generated test value
		0x16, 0x37, 0xfb, 0x9b, 0x83, 0xef, 0xe1, 0xf7, 
		0x8e, 0x5d, 0xa5, 0x12, 0xb5, 0x75, 0xd7, 0xe1, 
		0x19, 0x12, 0x58, 0x20, 0x76, 0x5f, 0xb6, 0x06, 
		0x1c, 0xad, 0x3c, 0xfc, 0xe5, 0x85, 0xbd, 0xfa, 
	};

	sid.length = 32;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == hash_len);
	assert(nodes.tree_page_size == MTL_TREE_PAGE_SIZE);

	for (index = 0; index < MTL_TREE_MAX_PAGES; index++) {
		assert(nodes.tree_pages[index] == NULL);
	}

	// Cleanup and verify clean up works
	mtl_node_set_free(&nodes);
	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == 0);
	assert(nodes.tree_page_size == 0);

	for (index = 0; index < MTL_TREE_MAX_PAGES; index++) {
		assert(nodes.tree_pages[index] == NULL);
	}

	mtl_node_set_free(&nodes);

	return 0;
}

/**
 * Test the mtl node id initialzation function
 * This is verifies that NULL parameters do not break things.
 */
uint8_t mtltest_mtl_node_set_init_null(void)
{
	SERIESID sid;
	uint8_t sid_val[] = {  // Randomly generated test value
		0x16, 0x37, 0xfb, 0x9b, 0x83, 0xef, 0xe1, 0xf7, 
		0x8e, 0x5d, 0xa5, 0x12, 0xb5, 0x75, 0xd7, 0xe1, 
		0x19, 0x12, 0x58, 0x20, 0x76, 0x5f, 0xb6, 0x06, 
		0x1c, 0xad, 0x3c, 0xfc, 0xe5, 0x85, 0xbd, 0xfa, 
	};

	sid.length = 32;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(NULL, &sid);
	// Verifying that this doesn't crash or cause strange behaviors

	return 0;
}

/**
 * Test the mtl node set inserting function
 */
uint8_t mtltest_mtl_node_set_insert(void)
{
	SERIESID sid;
	MTLNODES nodes;
	uint32_t node_index, page_index;
	uint8_t buffer[32];
	uint32_t hash_len = 16;
	uint32_t test_page_size = 8;
	uint8_t sid_val[] = { // Randomly generated test value
		0x16, 0x37, 0xfb, 0x9b, 0x83, 0xef, 0xe1, 0xf7, 
		0x8e, 0x5d, 0xa5, 0x12, 0xb5, 0x75, 0xd7, 0xe1, 
		0x19, 0x12, 0x58, 0x20, 0x76, 0x5f, 0xb6, 0x06, 
		0x1c, 0xad, 0x3c, 0xfc, 0xe5, 0x85, 0xbd, 0xfa, 
	};
	// Partial reverse-mapping of mtl_node_set_int_node_id
	uint32_t reverse_map_left[32] = { 0, 1, 0, 2, 3, 2, 0, 4, 
		5, 4, 6, 7, 6, 4, 0, 8, 
		9, 8, 10, 11, 10, 8, 12, 13, 
		12, 14, 15, 14, 12, 8, 0, 16
	};
	uint32_t reverse_map_right[32] = { 0, 1, 1, 2, 3, 3, 3, 4, 
		5, 5, 6, 7, 7, 7, 7, 8,
		9, 9, 10, 11, 11, 11, 12, 13,
		13, 14, 15, 15, 15, 15, 15, 16
	};

	sid.length = 32;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == hash_len);
	assert(nodes.tree_pages[0] == NULL);
	nodes.tree_page_size = test_page_size * hash_len;

	// Insert the first node
	memset(buffer, 0xff, hash_len);
	assert(mtl_node_set_insert(&nodes, 0, 0, buffer) == MTL_OK);

	// Insert the first full page
	for (node_index = 1; node_index < test_page_size; node_index++) {
		memset(buffer, 0xff - node_index, hash_len);
		assert(mtl_node_set_insert(&nodes, reverse_map_left[node_index], 
			reverse_map_right[node_index], buffer) == MTL_OK);
		// Test correct pages added
		assert(nodes.tree_pages[0] != NULL);
		for (page_index = 1; page_index < MTL_TREE_MAX_PAGES; page_index++) {
			assert(nodes.tree_pages[page_index] == NULL);
		}
	}


	// Add a second page
	for (node_index = test_page_size; node_index < 2*test_page_size; node_index++) {
		memset(buffer, 0xff - node_index, hash_len);
		assert(mtl_node_set_insert(&nodes, reverse_map_left[node_index], 
			reverse_map_right[node_index], buffer) == MTL_OK);
		// Test correct pages added
		assert(nodes.tree_pages[0] != NULL);
		assert(nodes.tree_pages[1] != NULL);
		for (page_index = 2; page_index < MTL_TREE_MAX_PAGES; page_index++) {
			assert(nodes.tree_pages[page_index] == NULL);
		}
	}

	// Add a third page
	for (node_index = 2*test_page_size; node_index < 3*test_page_size; node_index++) {
		memset(buffer, 0xff - node_index, hash_len);
		assert(mtl_node_set_insert(&nodes, reverse_map_left[node_index], 
			reverse_map_right[node_index], buffer) == MTL_OK);
		// Test correct pages added
		assert(nodes.tree_pages[0] != NULL);
		assert(nodes.tree_pages[1] != NULL);
		assert(nodes.tree_pages[2] != NULL);
		for (page_index = 3; page_index < MTL_TREE_MAX_PAGES; page_index++) {
			assert(nodes.tree_pages[page_index] == NULL);
		}
	}

	// Cleanup and verify clean up works
	mtl_node_set_free(&nodes);
	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == 0);
	assert(nodes.tree_page_size == 0);

	for (page_index = 0; page_index < MTL_TREE_MAX_PAGES; page_index++) {
		assert(nodes.tree_pages[page_index] == NULL);
	}

	mtl_node_set_free(&nodes);

	return 0;
}

/**
 * Test the mtl node set fetching function
 */
uint8_t mtltest_mtl_node_set_fetch(void)
{
	SERIESID sid;
	MTLNODES nodes;
	uint32_t index;
	uint8_t buffer[32];
	uint8_t *hash;
	uint32_t hash_len = 16;
	uint8_t sid_val[] = { // Randomly generated test value
		0x16, 0x37, 0xfb, 0x9b, 0x83, 0xef, 0xe1, 0xf7, 
		0x8e, 0x5d, 0xa5, 0x12, 0xb5, 0x75, 0xd7, 0xe1, 
		0x19, 0x12, 0x58, 0x20, 0x76, 0x5f, 0xb6, 0x06, 
		0x1c, 0xad, 0x3c, 0xfc, 0xe5, 0x85, 0xbd, 0xfa, 
	};

	sid.length = 32;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == hash_len);
	assert(nodes.tree_pages[0] == NULL);
	nodes.tree_page_size = 8 * hash_len;

	// Insert test nodes
	for (index = 0; index < 100; index++) {
		// Fetching nodes not yet inserted should fail
		assert(mtl_node_set_fetch(&nodes, index, index, &hash) == MTL_ERROR);

		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_insert(&nodes, index, index, buffer)
		       == MTL_OK);

		// Fetching nodes after insertion should succeed
		assert(mtl_node_set_fetch(&nodes, index, index, &hash) == MTL_OK);
		free(hash);
	}

	// Fetch the different nodes and verify the hash values
	for (index = 0; index < 100; index++) {
		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_fetch(&nodes, index, index, &hash) == MTL_OK);
		assert(memcmp(buffer, hash, hash_len) == 0);
		free(hash);
	}

	// Fetch a node that doesn't exist in the set
	assert(mtl_node_set_fetch(&nodes, 120, 120, &hash) == MTL_ERROR);

	// Cleanup and verify clean up works
	mtl_node_set_free(&nodes);
	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == 0);
	assert(nodes.tree_page_size == 0);

	for (index = 0; index < MTL_TREE_MAX_PAGES; index++) {
		assert(nodes.tree_pages[index] == NULL);
	}

	mtl_node_set_free(&nodes);

	return 0;
}

/**
 * Test the randomizer retrieval operations
 */
uint8_t mtltest_mtl_node_set_get_randomizer(void)
{
	SERIESID sid;
	MTLNODES nodes;
	uint32_t index;
	uint8_t buffer[32];
	uint8_t *buffer_ptr = &buffer[0];
	uint8_t random[32];
	uint32_t hash_len = 16;
	uint8_t sid_val[] = {  // Randomly generated test value
		0x16, 0x37, 0xfb, 0x9b, 0x83, 0xef, 0xe1, 0xf7, 
		0x8e, 0x5d, 0xa5, 0x12, 0xb5, 0x75, 0xd7, 0xe1, 
		0x19, 0x12, 0x58, 0x20, 0x76, 0x5f, 0xb6, 0x06, 
		0x1c, 0xad, 0x3c, 0xfc, 0xe5, 0x85, 0xbd, 0xfa, 
	};

	sid.length = 32;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == hash_len);
	assert(nodes.tree_pages[0] == NULL);
	nodes.tree_page_size = 8 * hash_len;

	// Insert test nodes
	for (index = 0; index < 10; index++) {
		memset(buffer, 0xff - index, hash_len);
		memset(random, index + 1, hash_len);
		mtl_node_set_insert(&nodes, index, index, buffer); // hash and randomness must be set atomically
		assert(mtl_node_set_insert_randomizer(&nodes, index, random)
		       == MTL_OK);
	}

	for (index = 0; index < 10; index++) {
		assert(mtl_node_set_get_randomizer(&nodes, index, &buffer_ptr)
		       == MTL_OK);
		memset(random, index + 1, hash_len);
		assert(memcmp(buffer_ptr, random, hash_len) == 0);
		free(buffer_ptr);
	}

	// Fetch randomizer that doesn't exist in the set
	assert(mtl_node_set_get_randomizer(&nodes, 10, &buffer_ptr) == MTL_ERROR);
	assert(mtl_node_set_get_randomizer(&nodes, MTL_NODE_SET_MAX_LEAF, &buffer_ptr) == MTL_ERROR);
	// Fetch randomizer for invalid index
	assert(mtl_node_set_get_randomizer(&nodes, MTL_NODE_SET_MAX_LEAF+1, &buffer_ptr) == MTL_BAD_PARAM);
	assert(mtl_node_set_get_randomizer(&nodes, MTL_NODE_SET_MAX_INDEX, &buffer_ptr) == MTL_BAD_PARAM);
	assert(mtl_node_set_get_randomizer(&nodes, MTL_NODE_SET_MAX_INDEX+1, &buffer_ptr) == MTL_BAD_PARAM);

	mtl_node_set_free(&nodes);

	return 0;
}

/**
 * Test the randomizer retrieval operations w/null parameters
 */
uint8_t mtltest_mtl_node_set_get_randomizer_null(void)
{
	SERIESID sid;
	MTLNODES nodes;
	uint32_t index;
	uint8_t buffer[32];
	uint8_t *buffer_ptr;
	uint32_t hash_len = 16;
	uint8_t sid_val[] = {  // Randomly generated test value
		0x16, 0x37, 0xfb, 0x9b, 0x83, 0xef, 0xe1, 0xf7, 
		0x8e, 0x5d, 0xa5, 0x12, 0xb5, 0x75, 0xd7, 0xe1, 
		0x19, 0x12, 0x58, 0x20, 0x76, 0x5f, 0xb6, 0x06, 
		0x1c, 0xad, 0x3c, 0xfc, 0xe5, 0x85, 0xbd, 0xfa, 
	};

	sid.length = 32;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == hash_len);
	assert(nodes.tree_pages[0] == NULL);
	nodes.tree_page_size = 8 * hash_len;

	// Test if 
	for (index = 0; index < 10; index++) {
		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_insert(&nodes, index, index, buffer)
		       == MTL_OK);
	}

	for (index = 0; index < 10; index++) {
		buffer_ptr = &buffer[0];
		assert(mtl_node_set_get_randomizer(&nodes, index, &buffer_ptr)
		       == MTL_ERROR);
	}

	assert(mtl_node_set_get_randomizer(NULL, index, &buffer_ptr) == MTL_BAD_PARAM);
	assert(mtl_node_set_get_randomizer(&nodes, index, NULL) == MTL_BAD_PARAM);

	mtl_node_set_free(&nodes);

	return 0;
}

/**
 * Test the mtl node id mapping function
 * Node ID pairs (x,y) are mapped to a linear space
 * for arranging the hashes in memory.
 */
uint8_t mtltest_mtl_node_id(void)
{
	MTL_INDEX output;
	assert(mtl_node_set_int_node_id(0, 0, &output) == MTL_OK);
	assert(output == 0);
	assert(mtl_node_set_int_node_id(1, 1, &output) == MTL_OK);
	assert(output == 1);
	assert(mtl_node_set_int_node_id(0, 1, &output) == MTL_OK);
	assert(output == 2);
	assert(mtl_node_set_int_node_id(2, 2, &output) == MTL_OK);
	assert(output == 3);
	assert(mtl_node_set_int_node_id(3, 3, &output) == MTL_OK);
	assert(output == 4);
	assert(mtl_node_set_int_node_id(2, 3, &output) == MTL_OK);
	assert(output == 5);
	assert(mtl_node_set_int_node_id(0, 3, &output) == MTL_OK);
	assert(output == 6);
	assert(mtl_node_set_int_node_id(4, 4, &output) == MTL_OK);
	assert(output == 7);
	assert(mtl_node_set_int_node_id(5, 5, &output) == MTL_OK);
	assert(output == 8);
	assert(mtl_node_set_int_node_id(4, 5, &output) == MTL_OK);
	assert(output == 9);
	assert(mtl_node_set_int_node_id(6, 6, &output) == MTL_OK);
	assert(output == 10);
	assert(mtl_node_set_int_node_id(7, 7, &output) == MTL_OK);
	assert(output == 11);
	assert(mtl_node_set_int_node_id(6, 7, &output) == MTL_OK);
	assert(output == 12);
	assert(mtl_node_set_int_node_id(4, 7, &output) == MTL_OK);
	assert(output == 13);
	assert(mtl_node_set_int_node_id(0, 7, &output) == MTL_OK);
	assert(output == 14);
	assert(mtl_node_set_int_node_id(8, 8, &output) == MTL_OK);
	assert(output == 15);
	assert(mtl_node_set_int_node_id(9, 9, &output) == MTL_OK);
	assert(output == 16);
	assert(mtl_node_set_int_node_id(8, 9, &output) == MTL_OK);
	assert(output == 17);
	assert(mtl_node_set_int_node_id(10, 10, &output) == MTL_OK);
	assert(output == 18);
	assert(mtl_node_set_int_node_id(11, 11, &output) == MTL_OK);
	assert(output == 19);
	assert(mtl_node_set_int_node_id(10, 11, &output) == MTL_OK);
	assert(output == 20);
	assert(mtl_node_set_int_node_id(0, 15, &output) == MTL_OK);
	assert(output == 30);
	// Check largest allowed index
	assert(mtl_node_set_int_node_id(0, MTL_NODE_SET_MAX_LEAF, &output) == MTL_OK);
	assert(output == MTL_NODE_SET_MAX_INDEX);

	return 0;
}

/**
 * Test the mtl node id mapping function
 * returns errors for invalid inputs
 */
uint8_t mtltest_mtl_node_id_invalid(void)
{
	MTL_INDEX out;
	// Null check
	assert(mtl_node_set_int_node_id(0, 0, NULL) == MTL_NULL_PTR);

	// Left > Right error
	assert(mtl_node_set_int_node_id(1, 0, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(3, 2, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(3, 0, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(5, 4, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(7, 6, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(7, 4, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(7, 0, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(9, 8, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(11, 10, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(16, 0, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(0x7fffffff, 0, &out) == MTL_BAD_PARAM);

	// Indices don't cover a complete subtree
	assert(mtl_node_set_int_node_id(0, 2, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(1, 3, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(2, 4, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(0, 4, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(1, 16, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(16, 32, &out) == MTL_BAD_PARAM);

	// Leaf index out-of-bounds error
	assert(mtl_node_set_int_node_id(0, MTL_NODE_SET_MAX_LEAF + 1, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(MTL_NODE_SET_MAX_LEAF + 1, MTL_NODE_SET_MAX_LEAF + 1, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(MTL_NODE_SET_MAX_LEAF, MTL_NODE_SET_MAX_LEAF + 1, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(MTL_NODE_SET_MAX_LEAF + 1, MTL_NODE_SET_MAX_LEAF + 2, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(MTL_NODE_SET_MAX_LEAF + 2, MTL_NODE_SET_MAX_LEAF + 3, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(0, MTL_NODE_SET_MAX_INDEX, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(MTL_NODE_SET_MAX_INDEX, MTL_NODE_SET_MAX_INDEX, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(MTL_NODE_SET_MAX_INDEX, MTL_NODE_SET_MAX_INDEX + 1, &out) == MTL_BAD_PARAM);
	MTL_INDEX uint_max = (MTL_INDEX)(-1);
	assert(mtl_node_set_int_node_id(0, uint_max, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(uint_max, uint_max, &out) == MTL_BAD_PARAM);
	assert(mtl_node_set_int_node_id(uint_max, uint_max + 1, &out) == MTL_BAD_PARAM);

	return 0;
}

/**
 * Test the mtl lsb function
 * returns the position of the least significant bit of x,
 * where bit positions start at 1 and lsb(0) = 0
 */
uint8_t mtltest_mtl_lsb(void)
{
	uint16_t index;

	// Make sure that all bit positions work
	for (index = 0; index < 8*sizeof(MTL_INDEX); index++) {
		assert(mtl_lsb(((MTL_INDEX)1) << index) == index);
	}

	// Test out multiple bit numbers
	assert(mtl_lsb(7) == 0);
	assert(mtl_lsb(10) == 1);
	assert(mtl_lsb(0xAAAA0000) == 17);
	assert(mtl_lsb(0xC0000000) == 30);

	return 0;
}

/**
 * Test the mtl bit width function
 * bit_width (x) returns the number of 1 value bits in x. 
 */
uint8_t mtltest_mtl_bit_width(void)
{

	assert(mtl_bit_width(0) == 0);
	assert(mtl_bit_width(0xFF) == 8);
	assert(mtl_bit_width(0xFFFF) == 16);
	assert(mtl_bit_width(0xFFFFFF) == 24);
	assert(mtl_bit_width(0xFFFFFFFF) == 32);

	assert(mtl_bit_width(0x5555) == 8);
	assert(mtl_bit_width(0x55550000) == 8);
	assert(mtl_bit_width(0x50505050) == 8);
	assert(mtl_bit_width(0x55555555) == 16);
	assert(mtl_bit_width(0xAAAA) == 8);
	assert(mtl_bit_width(0xAAAAAAAA) == 16);
	assert(mtl_bit_width(0xAA00AA00) == 8);
	assert(mtl_bit_width(0x00AA00AA) == 8);

	assert(mtl_bit_width(0x0FF0) == 8);
	assert(mtl_bit_width(0xF00F) == 8);

	assert(mtl_bit_width(0xAAAA0000) == 8);
	assert(mtl_bit_width(0xC0000000) == 2);

	// Test "overflow"
	assert(mtl_bit_width((uint32_t) 0xC00000000L) == 0);

	return 0;
}

/**
 * Test the mtl msb function
 * returns the position of the most significant bit of x
 */
uint8_t mtltest_mtl_msb(void)
{
	uint16_t index;

	// Make sure that all 32 bit positions work
	for (index = 0; index < 32; index++) {
		assert(mtl_msb(1ULL << index) == index);
	}

	// Test out multiple bit numbers
	assert(mtl_msb(7) == 2);
	assert(mtl_msb(10) == 3);
	assert(mtl_msb(0xAAAA0000) == 31);
	assert(mtl_msb(0xC0000000) == 31);

	return 0;
}

/**
 * Test operations on maximum-size tree
 */
uint8_t mtltest_mtl_node_set_maximum(void)
{
	SERIESID sid;
	MTLNODES nodes;
	MTL_INDEX index, left_index, right_index, width_index;
	uint8_t write_buffer[32], read_buffer[32];
	uint8_t *hash;
	uint32_t hash_len = 32;
	uint8_t sid_val[] = {  // Randomly generated test value
		0x16, 0x37, 0xfb, 0x9b, 0x83, 0xef, 0xe1, 0xf7, 
		0x8e, 0x5d, 0xa5, 0x12, 0xb5, 0x75, 0xd7, 0xe1, 
		0x19, 0x12, 0x58, 0x20, 0x76, 0x5f, 0xb6, 0x06, 
		0x1c, 0xad, 0x3c, 0xfc, 0xe5, 0x85, 0xbd, 0xfa, 
	};

	// initialize distinct hash value into buffers
	for (index = 0; index < hash_len; index++)
	{
		write_buffer[index] = 0xff-index;
		read_buffer[index] = write_buffer[index];
	}

	sid.length = 32;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, &sid);

	// Build complete tree
	for (width_index = 1; width_index && width_index <= MTL_NODE_SET_MAX_LEAF+1; width_index *= 2)
	{
		for (left_index = 0; left_index <= MTL_NODE_SET_MAX_LEAF; left_index += width_index)
		{
			// Check leaf_count is being updated correctly
			if (width_index == 1)
			{
				assert(nodes.leaf_count == left_index);
			}
			else
			{
				assert(nodes.leaf_count == MTL_NODE_SET_MAX_LEAF+1);
			}
			// Insert node
			right_index = left_index + width_index - 1;
			assert(right_index <= MTL_NODE_SET_MAX_LEAF);
			assert(mtl_node_set_insert(&nodes, left_index, right_index, write_buffer) == MTL_OK);
			// Set different hash value for each index
			write_buffer[left_index % 32]--;
		}
	}

	// Test reading from tree after build
	for (width_index = 1; width_index <= MTL_NODE_SET_MAX_LEAF+1; width_index *= 2)
	{
		for (left_index = 0; left_index <= MTL_NODE_SET_MAX_LEAF; left_index += width_index)
		{
			// Read node
			right_index = left_index + width_index - 1;
			assert(mtl_node_set_fetch(&nodes, left_index, right_index, &hash) == MTL_OK);
			assert(memcmp(read_buffer, hash, hash_len) == 0);
			free(hash);
			// Compute next index hash value
			read_buffer[left_index % 32]--;
		}
	}

	return 0;
}