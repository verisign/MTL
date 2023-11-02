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
#include <config.h>
#include <stdio.h>
#include "mtl_spx.h"
#include "spx_funcs.h"
#include <assert.h>
#include <string.h>

#include "mtltest.h"

// Prototypes for testing functionsß
uint8_t mtltest_mtl_node_set_init(void);
uint8_t mtltest_mtl_node_set_init_null(void);
uint8_t mtltest_mtl_node_set_insert(void);
uint8_t mtltest_mtl_node_set_fetch(void);
uint8_t mtltest_mtl_node_set_get_randomizer(void);
uint8_t mtltest_mtl_node_set_get_randomizer_null(void);

uint8_t mtltest_mtl_lsb(void);
uint8_t mtltest_mtl_msb(void);
uint8_t mtltest_mtl_bit_width(void);
uint8_t mtltest_mtl_node_id(void);

uint8_t mtltest_mtl_node_set(void)
{
	NEW_TEST("MTL Node Set Tests");

	RUN_TEST(mtltest_mtl_lsb, "Verify the lsb function");
	RUN_TEST(mtltest_mtl_msb, "Verify the msb function");
	RUN_TEST(mtltest_mtl_bit_width, "Verify the bit_width function");
	RUN_TEST(mtltest_mtl_node_id, "Verify the hash tree id map");

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

	return 0;
}

/**
 * Test the mtl node id initialzation function
 * This is the successful allocation and free test
 */
uint8_t mtltest_mtl_node_set_init(void)
{
	SEED seed;
	MTLNODES nodes;
	uint32_t index;
	SERIESID sid;
	uint8_t sid_val[] = { 0x28, 0xe7, 0x56, 0xf0, 0xb4, 0x61, 0xf6, 0x79 };
	uint8_t seed_val[] = { 0x66, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
		0x06, 0xb5, 0x59, 0x89, 0x75, 0x08, 0xe7, 0x2c,
		0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
		0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
	};

	seed.length = 32;
	memcpy(seed.seed, seed_val, seed.length);
	sid.length = 8;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, seed, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == seed.length);
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
	SEED seed;
	SERIESID sid;
	uint8_t sid_val[] = { 0x28, 0xe7, 0x56, 0xf0, 0xb4, 0x61, 0xf6, 0x79 };
	uint8_t seed_val[] = { 0x66, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
		0x06, 0xb5, 0x59, 0x89, 0x75, 0x08, 0xe7, 0x2c,
		0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
		0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
	};

	sid.length = 8;
	memcpy(sid.id, sid_val, sid.length);
	seed.length = 32;
	memcpy(seed.seed, seed_val, seed.length);

	mtl_node_set_init(NULL, seed, &sid);
	// Verifying that this doesn't crash or cause strange behaviors

	return 0;
}

/**
 * Test the mtl node set inserting function
 */
uint8_t mtltest_mtl_node_set_insert(void)
{
	SEED seed;
	SERIESID sid;
	MTLNODES nodes;
	uint32_t index;
	uint8_t buffer[32];
	uint32_t hash_len = 32;
	uint8_t sid_val[] = { 0x28, 0xe7, 0x56, 0xf0, 0xb4, 0x61, 0xf6, 0x79 };
	uint8_t seed_val[] = { 0x66, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
		0x06, 0xb5, 0x59, 0x89, 0x75, 0x08, 0xe7, 0x2c,
		0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
		0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
	};

	seed.length = hash_len;
	memcpy(seed.seed, seed_val, seed.length);
	sid.length = 8;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, seed, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == seed.length);
	assert(nodes.tree_pages[0] == NULL);
	nodes.tree_page_size = 8 * hash_len;

	// Insert the first node
	memset(buffer, 0xff, hash_len);
	assert(mtl_node_set_insert(&nodes, 0, 0, buffer) == 0);

	// Insert the first full page
	for (index = 1; index < 5; index++) {
		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_insert(&nodes, index, index, buffer)
		       == 0);
	}
	assert(nodes.tree_pages[0] != NULL);
	for (index = 1; index < MTL_TREE_MAX_PAGES; index++) {
		assert(nodes.tree_pages[index] == NULL);
	}

	// Add a second page
	for (index = 5; index < 9; index++) {
		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_insert(&nodes, index, index, buffer)
		       == 0);
	}
	assert(nodes.tree_pages[0] != NULL);
	assert(nodes.tree_pages[1] != NULL);
	for (index = 2; index < MTL_TREE_MAX_PAGES; index++) {
		assert(nodes.tree_pages[index] == NULL);
	}

	// Add a third page
	for (index = 9; index < 12; index++) {
		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_insert(&nodes, index, index, buffer)
		       == 0);
	}
	assert(nodes.tree_pages[0] != NULL);
	assert(nodes.tree_pages[1] != NULL);
	assert(nodes.tree_pages[2] != NULL);
	for (index = 3; index < MTL_TREE_MAX_PAGES; index++) {
		assert(nodes.tree_pages[index] == NULL);
	}

	for (index = 12; index < 14; index++) {
		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_insert(&nodes, index, index, buffer)
		       == 0);
	}
	assert(nodes.tree_pages[0] != NULL);
	assert(nodes.tree_pages[1] != NULL);
	assert(nodes.tree_pages[2] != NULL);
	for (index = 3; index < MTL_TREE_MAX_PAGES; index++) {
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
 * Test the mtl node set fetching function
 */
uint8_t mtltest_mtl_node_set_fetch(void)
{
	SEED seed;
	SERIESID sid;
	MTLNODES nodes;
	uint32_t index;
	uint8_t buffer[32];
	uint8_t *hash;
	uint32_t hash_len = 32;
	uint8_t sid_val[] = { 0x28, 0xe7, 0x56, 0xf0, 0xb4, 0x61, 0xf6, 0x79 };
	uint8_t seed_val[] = { 0x66, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
		0x06, 0xb5, 0x59, 0x89, 0x75, 0x08, 0xe7, 0x2c,
		0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
		0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
	};

	seed.length = hash_len;
	memcpy(seed.seed, seed_val, seed.length);
	sid.length = 0;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, seed, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == seed.length);
	assert(nodes.tree_pages[0] == NULL);
	nodes.tree_page_size = 8 * hash_len;

	// Insert test nodes
	for (index = 0; index < 100; index++) {
		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_insert(&nodes, index, index, buffer)
		       == 0);
	}

	// Fetch the different nodes and verify the hash values
	for (index = 0; index < 100; index++) {
		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_fetch(&nodes, index, index, &hash) == 0);
		assert(memcmp(buffer, hash, hash_len) == 0);
		free(hash);
	}

	// Fetch a node that doesn't exist in the set
	assert(mtl_node_set_fetch(&nodes, 120, 120, &hash) == 1);

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
	SEED seed;
	SERIESID sid;
	MTLNODES nodes;
	uint32_t index;
	uint8_t buffer[32];
	uint8_t random[32];
	uint32_t hash_len = 32;
	uint8_t sid_val[] = { 0x28, 0xe7, 0x56, 0xf0, 0xb4, 0x61, 0xf6, 0x79 };
	uint8_t seed_val[] = { 0x66, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
		0x06, 0xb5, 0x59, 0x89, 0x75, 0x08, 0xe7, 0x2c,
		0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
		0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
	};

	seed.length = hash_len;
	memcpy(seed.seed, seed_val, seed.length);
	sid.length = 0;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, seed, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == seed.length);
	assert(nodes.tree_pages[0] == NULL);
	nodes.tree_page_size = 8 * hash_len;

	// Insert test nodes
	for (index = 0; index < 10; index++) {
		memset(buffer, 0xff - index, hash_len);
		memset(random, index + 1, hash_len);
		assert(mtl_node_set_insert_randomizer(&nodes, index, random)
		       == 0);
	}

	for (index = 0; index < 10; index++) {
		uint8_t *buffer_ptr = &buffer[0];
		assert(mtl_node_set_get_randomizer(&nodes, index, &buffer_ptr)
		       == 0);
		memset(random, index + 1, hash_len);
		assert(memcmp(buffer_ptr, random, hash_len) == 0);
		free(buffer_ptr);
	}

	mtl_node_set_free(&nodes);

	return 0;
}

/**
 * Test the randomizer retrieval operations w/null parameters
 */
uint8_t mtltest_mtl_node_set_get_randomizer_null(void)
{
	SEED seed;
	SERIESID sid;
	MTLNODES nodes;
	uint32_t index;
	uint8_t buffer[32];
	uint8_t *buffer_ptr;
	uint32_t hash_len = 32;
	uint8_t sid_val[] = { 0x28, 0xe7, 0x56, 0xf0, 0xb4, 0x61, 0xf6, 0x79 };
	uint8_t seed_val[] = { 0x66, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
		0x06, 0xb5, 0x59, 0x89, 0x75, 0x08, 0xe7, 0x2c,
		0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
		0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
	};

	seed.length = hash_len;
	memcpy(seed.seed, seed_val, seed.length);
	sid.length = 0;
	memcpy(sid.id, sid_val, sid.length);

	mtl_node_set_init(&nodes, seed, &sid);

	assert(nodes.leaf_count == 0);
	assert(nodes.hash_size == seed.length);
	assert(nodes.tree_pages[0] == NULL);
	nodes.tree_page_size = 8 * hash_len;

	// Test if 
	for (index = 0; index < 10; index++) {
		memset(buffer, 0xff - index, hash_len);
		assert(mtl_node_set_insert(&nodes, index, index, buffer)
		       == 0);
	}

	for (index = 0; index < 10; index++) {
		buffer_ptr = &buffer[0];
		assert(mtl_node_set_get_randomizer(&nodes, index, &buffer_ptr)
		       == 2);
	}

	assert(mtl_node_set_get_randomizer(NULL, index, &buffer_ptr) == 1);
	assert(mtl_node_set_get_randomizer(&nodes, index, NULL) == 1);

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
	assert(mtl_node_set_int_node_id(0, 0) == 0);
	assert(mtl_node_set_int_node_id(1, 1) == 1);
	assert(mtl_node_set_int_node_id(0, 1) == 2);
	assert(mtl_node_set_int_node_id(2, 2) == 3);
	assert(mtl_node_set_int_node_id(3, 3) == 4);
	assert(mtl_node_set_int_node_id(2, 3) == 5);
	assert(mtl_node_set_int_node_id(0, 3) == 6);
	assert(mtl_node_set_int_node_id(4, 4) == 7);
	assert(mtl_node_set_int_node_id(5, 5) == 8);
	assert(mtl_node_set_int_node_id(4, 5) == 9);
	assert(mtl_node_set_int_node_id(6, 6) == 10);
	assert(mtl_node_set_int_node_id(7, 7) == 11);
	assert(mtl_node_set_int_node_id(6, 7) == 12);
	assert(mtl_node_set_int_node_id(4, 7) == 13);
	assert(mtl_node_set_int_node_id(0, 7) == 14);
	assert(mtl_node_set_int_node_id(8, 8) == 15);
	assert(mtl_node_set_int_node_id(9, 9) == 16);
	assert(mtl_node_set_int_node_id(8, 9) == 17);
	assert(mtl_node_set_int_node_id(10, 10) == 18);
	assert(mtl_node_set_int_node_id(11, 11) == 19);
	assert(mtl_node_set_int_node_id(10, 11) == 20);

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

	// Make sure that all 32 bit positions work
	for (index = 0; index < 32; index++) {
		assert(mtl_lsb(1 << index) == index);
	}

	// Test out multiple bit numbers
	assert(mtl_lsb(7) == 0);
	assert(mtl_lsb(10) == 1);
	assert(mtl_lsb(0xAAAA0000) == 17);
	assert(mtl_lsb(0xC0000000) == 30);

	// Test "overflow"
	for (index = 32; index < 64; index++) {
		assert(mtl_lsb((1L << index)) == 0xffffffff);
	}

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
		assert(mtl_msb(1 << index) == index);
	}

	// Test out multiple bit numbers
	assert(mtl_msb(7) == 2);
	assert(mtl_msb(10) == 3);
	assert(mtl_msb(0xAAAA0000) == 31);
	assert(mtl_msb(0xC0000000) == 31);

	// Test "overflow"
	for (index = 32; index < 64; index++) {
		assert(mtl_msb((1L << index)) == 0);
	}

	return 0;
}
