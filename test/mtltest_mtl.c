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
#include <assert.h>
#include <string.h>

#include "mtltest.h"
#include "mtl_node_set.h"
#include "mtl_error.h"
#include "mtl.h"
#include "mtltest_mock.h"

// Prototypes for testing functions
uint8_t mtltest_mtl_initns(void);
uint8_t mtltest_mtl_initns_null(void);
uint8_t mtltest_mtl_set_scheme_functions(void);
uint8_t mtltest_mtl_set_scheme_functions_null(void);
uint8_t mtltest_mtl_append(void);
uint8_t mtltest_mtl_append_random(void);
uint8_t mtltest_mtl_append_null(void);
uint8_t mtltest_mtl_node_set_update_parents(void);
uint8_t mtltest_mtl_node_set_update_parents_null(void);
uint8_t mtltest_mtl_authpath_multi(void);
uint8_t mtltest_mtl_authpath_null(void);
uint8_t mtltest_mtl_ladder_multi(void);
uint8_t mtltest_mtl_ladder_null(void);
uint8_t mtltest_mtl_rung(void);
uint8_t mtltest_mtl_rung_null(void);
//uint8_t mtltest_mtl_verify(void);
uint8_t mtltest_mtl_verify_rand(void);
uint8_t mtltest_mtl_verify_null(void);

uint8_t mtltest_mtl(void)
{
	NEW_TEST("MTL Tests");

	RUN_TEST(mtltest_mtl_initns, "Verify MTL initialization");
	RUN_TEST(mtltest_mtl_initns_null,
		 "Verify MTL initialization w/null parameters");
	RUN_TEST(mtltest_mtl_set_scheme_functions,
		 "Verify MTL underlying scheme function");
	RUN_TEST(mtltest_mtl_set_scheme_functions_null,
		 "Verify MTL underlying scheme function w/null parameters");
//	RUN_TEST(mtltest_mtl_append, "Verify MTL append function");
	RUN_TEST(mtltest_mtl_append_random,
		 "Verify MTL append function w/randomizer");
	RUN_TEST(mtltest_mtl_append_null,
		 "Verify MTL append function w/null parameters");
	RUN_TEST(mtltest_mtl_node_set_update_parents,
		 "Verify the MTL node set parent hash function");
	RUN_TEST(mtltest_mtl_node_set_update_parents_null,
		 "Verify the MTL node set parent hash function w/null parameters");		 
	RUN_TEST(mtltest_mtl_authpath_multi,
		 "Verify MTL authentication path function w/multiple rungs");
	RUN_TEST(mtltest_mtl_authpath_null,
		 "Verify MTL authentication path function w/null parameters");
	RUN_TEST(mtltest_mtl_ladder_multi,
		 "Verify MTL ladder function w/multiple rungs");
	RUN_TEST(mtltest_mtl_ladder_null,
		 "Verify MTL ladder function w/null parameters");
	RUN_TEST(mtltest_mtl_rung, "Verify MTL rung function");
	RUN_TEST(mtltest_mtl_rung_null,
		 "Verify MTL rung function w/null parameters");
//	RUN_TEST(mtltest_mtl_verify, "Verify MTL verify function");
	RUN_TEST(mtltest_mtl_verify_rand,
		 "Verify MTL verify function with randomization");
	RUN_TEST(mtltest_mtl_verify_null,
		 "Verify MTL verify function w/null parameters");

	return 0;
}

/**
 * Test the mtl initialization routines
 */
uint8_t mtltest_mtl_initns(void)
{
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 32;

    assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
    assert(&mtl_ctx->sid != &sid);
    assert(mtl_ctx->sid.length == sid.length);
    assert(memcmp(&mtl_ctx->sid.id, &sid.id, sid.length) == 0);
    assert(mtl_ctx->randomize == 0);
    assert(mtl_ctx->hash_leaf == NULL);
    assert(mtl_ctx->hash_int == NULL);

    assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Test the mtl initialization routines with NULL parameters
 */
uint8_t mtltest_mtl_initns_null(void)
{
	MTL_CTX *ctx;
	SERIESID sid;
	sid.length = 32;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(NULL, &sid) == MTL_NULL_PTR);
	assert(mtl_initns(&ctx, NULL) == MTL_NULL_PTR);

	return 0;
}

/**
 * Test the mtl scheme setup function
 */
uint8_t mtltest_mtl_set_scheme_functions(void)
{
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;

	sid.length = 32;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(sid.length == 32);
	assert(memcmp(&mtl_ctx->sid.id, &sid.id, sid.length) == 0);
	assert(mtl_ctx->randomize == 0);
	assert(mtl_ctx->hash_leaf == NULL);
	assert(mtl_ctx->hash_int == NULL);

	// Test with stub functions
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);
	assert(mtl_ctx->randomize == 1);
	assert(mtl_ctx->hash_leaf == mtl_test_hash_leaf);
	assert(mtl_ctx->hash_int == mtl_test_hash_int);

	assert(mtl_free(mtl_ctx) == MTL_OK);
	return 0;
}

/**
 * Test the mtl scheme setup function with NULL parameters
 */
uint8_t mtltest_mtl_set_scheme_functions_null(void)
{
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;

	sid.length = MTL_SID_SIZE;
	memset(&sid.id, 0, MTL_SID_SIZE);


	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_ctx->sid.length == sid.length);
	assert(memcmp(mtl_ctx->sid.id, &sid.id, sid.length) == 0);
	assert(mtl_ctx->randomize == 0);
	assert(mtl_ctx->hash_leaf == NULL);
	assert(mtl_ctx->hash_int == NULL);


	// NULL Context
	assert(mtl_set_scheme_functions(NULL, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) ==
	       MTL_NULL_PTR);

	// NULL Leaf Hash
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					NULL, mtl_test_hash_int) == MTL_OK);
	assert(mtl_ctx->randomize == 1);
	assert(mtl_ctx->hash_leaf == NULL);
	assert(mtl_ctx->hash_int == mtl_test_hash_int);

	// NULL Internal Node Hash
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf, NULL) == MTL_OK);
	assert(mtl_ctx->randomize == 1);
	assert(mtl_ctx->hash_leaf == mtl_test_hash_leaf);
	assert(mtl_ctx->hash_int == NULL);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/** \todo revisit once PRF randomizers are implemented
 * Test the mtl append function
 *
uint8_t mtltest_mtl_append(void)
{
	MTL_CTX *mtl_ctx = NULL;
	SEED pk_seed;
	SERIESID sid;
	uint16_t i;
	uint8_t *hash;
	uint8_t ref_val[32];
	uint8_t authpath[8][32] =
	    { {0x45, 0x32, 0x02, 0x36, 0x48, 0x70, 0x92, 0x96,
	       0x31, 0x6c, 0xaa, 0x8a, 0x24, 0x08, 0xea, 0x36,
	       0xe3, 0xb8, 0x04, 0xcf, 0x80, 0xf1, 0xab, 0x5e,
	       0x39, 0xbc, 0xc7, 0x9c, 0xea, 0xfb, 0x5b, 0x4e},
	{0xe6, 0x20, 0xbe, 0x4a, 0xf8, 0x85, 0xef, 0x18,
	 0xa2, 0x83, 0xf7, 0x8a, 0x4c, 0xc6, 0x97, 0x0c,
	 0xbe, 0x6c, 0xb1, 0x6a, 0x2c, 0x2b, 0x37, 0xf5,
	 0xc2, 0xf5, 0xf2, 0x5e, 0xb4, 0xfa, 0xd7, 0x47},
	{0x26, 0xd5, 0x19, 0xf5, 0x59, 0x2f, 0xf8, 0xf6,
	 0xbb, 0x9f, 0xf2, 0x62, 0x62, 0xa3, 0xde, 0x2d,
	 0x99, 0xde, 0xc5, 0xf8, 0x00, 0xcc, 0x19, 0xab,
	 0x47, 0xf4, 0xfe, 0xc4, 0xcf, 0x61, 0xb9, 0x43},
	{0xfe, 0x4e, 0x22, 0xcf, 0x8a, 0x62, 0x0d, 0x58,
	 0xa3, 0x0b, 0x5b, 0x2c, 0x85, 0x59, 0xfc, 0x6f,
	 0xc0, 0x5f, 0x10, 0x2b, 0xcc, 0x85, 0x07, 0x19,
	 0x21, 0x08, 0x26, 0xc7, 0x7e, 0xa9, 0xc7, 0x94},
	{0xd6, 0x9b, 0x13, 0xe2, 0x00, 0xad, 0xbe, 0x34,
	 0x40, 0x43, 0x0c, 0xde, 0x02, 0x91, 0x62, 0x0b,
	 0x57, 0x4b, 0xb2, 0x58, 0x02, 0x72, 0x22, 0x12,
	 0x04, 0x9b, 0xac, 0x65, 0xc9, 0x5e, 0xde, 0x22},
	{0x27, 0x87, 0x75, 0x92, 0x14, 0x33, 0xf9, 0x3d,
	 0x62, 0xf7, 0xcc, 0xb1, 0x15, 0x52, 0xc5, 0xf1,
	 0xdd, 0x3d, 0xdc, 0x8d, 0x45, 0x26, 0x13, 0xdf,
	 0x20, 0xef, 0xd0, 0x34, 0x0e, 0x17, 0xc8, 0xb7},
	{0xfb, 0x46, 0xec, 0xda, 0xf8, 0x7e, 0x2b, 0x33,
	 0xa6, 0xe8, 0x3d, 0x94, 0x58, 0x87, 0x6c, 0xc8,
	 0x4b, 0x15, 0x5e, 0x38, 0xc0, 0x53, 0xb9, 0xa3,
	 0x16, 0xd4, 0xf8, 0x32, 0x1a, 0x84, 0x2a, 0x8a},
	{0xab, 0x6a, 0xcd, 0xfe, 0xa1, 0x35, 0xf5, 0x12,
	 0xc0, 0x0b, 0x54, 0x9f, 0x5a, 0xf0, 0xaf, 0xd7,
	 0x5c, 0x6f, 0x5a, 0x0d, 0x3f, 0x14, 0x4d, 0x70,
	 0x62, 0xa3, 0xe6, 0xbf, 0xde, 0x15, 0x18, 0x7b}
	};
	uint32_t target_nodeid = MTL_TREE_PAGE_SIZE / 2 / 32;

	memset(&ref_val[0], 0, 32);

	sid.length = 8;
	memset(&sid.id, 0, sid.length);
	pk_seed.length = 32;
	memset(pk_seed.seed, 0, 32);

	assert(mtl_initns(&mtl_ctx, &pk_seed, &sid, NULL) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 0,
					mtl_test_hash_msg,
					mtl_test_hash_leaf,
					mtl_test_hash_int, NULL) == MTL_OK);

	for (i = 0; i < 8; i++) {
		assert(mtl_append
		       (mtl_ctx, (uint8_t *) "Test Data String", 16, i) == MTL_OK);
		assert(mtl_node_set_fetch(&mtl_ctx->nodes, i, i, &hash) == MTL_OK);
		assert(memcmp(&hash[0], &authpath[i][0], 32) == 0); 

		free(hash);
	}
	for (i = 8; i <= target_nodeid; i++) {
		assert(mtl_append
		       (mtl_ctx, (uint8_t *) "Test Data String", 16, i) == MTL_OK);
		assert(mtl_node_set_fetch(&mtl_ctx->nodes, i, i, &hash) == MTL_OK);
		free(hash);
	}

	assert(mtl_node_set_fetch
	       (&mtl_ctx->nodes, target_nodeid, target_nodeid, &hash) == MTL_OK);
	free(hash);
	assert(mtl_node_set_fetch
	       (&mtl_ctx->nodes, target_nodeid + 1, target_nodeid + 1,
		&hash) == MTL_ERROR);

	assert(mtl_free(mtl_ctx) == MTL_OK);
	return 0;
}
*/

/**
 * Test the mtl append function with the randomizer
 */
uint8_t mtltest_mtl_append_random(void)
{
	MTL_CTX *mtl_ctx = NULL;
	SERIESID sid;
	uint16_t i;
	uint8_t *hash;
	uint8_t ref_val[32];
	uint8_t authpath[8][32] =
	    { {0xe2, 0xc2, 0x5a, 0x9e, 0x5b, 0xa4, 0xe4, 0x47,
	       0x73, 0xb6, 0x3b, 0x71, 0xc9, 0x68, 0xa0, 0x64,
	       0xa1, 0xee, 0xe2, 0x8b, 0xf6, 0x50, 0x6d, 0xfb,
	       0x47, 0x59, 0x96, 0x16, 0x25, 0x13, 0x9c, 0x0b},
	{0x1d, 0x6d, 0xbb, 0xb6, 0x97, 0x07, 0x22, 0x4c,
	 0xbd, 0xac, 0x3e, 0x02, 0x6a, 0xde, 0x16, 0x0d,
	 0xae, 0xf9, 0x31, 0x9b, 0x37, 0x8b, 0x84, 0x51,
	 0x52, 0x35, 0xa3, 0xcc, 0x72, 0xc9, 0x29, 0xd6},
	{0x50, 0x6c, 0x91, 0x5c, 0x9b, 0xf7, 0xb9, 0xb2,
	 0x04, 0xae, 0xd9, 0x26, 0x37, 0x67, 0x36, 0xdf,
	 0xe3, 0xa1, 0x68, 0x4f, 0x9c, 0xe8, 0x9e, 0xfb,
	 0x1d, 0x8b, 0xd6, 0xd4, 0x5c, 0x0b, 0x0f, 0xe3},
	{0x63, 0xc2, 0x65, 0xd8, 0x08, 0x61, 0x52, 0xce,
	 0x47, 0xd6, 0x17, 0x8f, 0x25, 0x08, 0x05, 0x4c,
	 0x42, 0x0d, 0xb9, 0x76, 0x6a, 0x79, 0x5c, 0xdf,
	 0x7c, 0xd7, 0xce, 0xd7, 0xb5, 0x24, 0x49, 0x0b},
	{0xdb, 0x2f, 0x3c, 0x18, 0x65, 0xb8, 0xf6, 0x8b,
	 0x07, 0x31, 0x10, 0x54, 0x3a, 0xd6, 0xe0, 0xbc,
	 0x5f, 0xe7, 0x86, 0x03, 0x26, 0x8d, 0x6d, 0x03,
	 0x98, 0x85, 0x2f, 0x5f, 0x9f, 0x57, 0x1e, 0x4e},
	{0xb6, 0x6c, 0x86, 0xd1, 0x5e, 0x92, 0x83, 0xa8,
	 0xdf, 0x98, 0x20, 0x56, 0x05, 0xeb, 0x46, 0x8d,
	 0x62, 0x2a, 0xee, 0xf2, 0xfb, 0x1d, 0xc5, 0xc1,
	 0xd2, 0x1b, 0xf6, 0x58, 0x89, 0x4f, 0xbb, 0x63},
	{0x6c, 0xff, 0xff, 0xd3, 0x90, 0x13, 0xf3, 0x9a,
	 0xb3, 0x0c, 0xf8, 0x4b, 0x48, 0x4a, 0x74, 0xa7,
	 0x9f, 0xe4, 0xfd, 0x61, 0xc4, 0x2c, 0xee, 0x86,
	 0xad, 0x9f, 0xb9, 0x7d, 0x02, 0xad, 0xb3, 0xda},
	{0x5b, 0x29, 0xa9, 0x80, 0x02, 0x0c, 0xa5, 0x62,
	 0xb2, 0x36, 0xaa, 0xe0, 0xc3, 0x43, 0x41, 0x69,
	 0xc9, 0x13, 0x0e, 0x50, 0x51, 0x53, 0xbd, 0x0a,
	 0xbb, 0x95, 0xbd, 0x1d, 0xbf, 0xeb, 0xaa, 0x41}
	};
	uint32_t target_nodeid = MTL_TREE_PAGE_SIZE / 2 / 32;

	memset(&ref_val[0], 0, 32);

	sid.length = 8;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	for (i = 0; i < 8; i++) {
		assert(mtl_append
		       (mtl_ctx, (uint8_t *) "Test Data String", 16, NULL, 0, i) == MTL_OK);
		assert(mtl_node_set_fetch(&mtl_ctx->nodes, i, i, &hash) == MTL_OK);
		assert(memcmp(&hash[0], &authpath[i][0], 32) != 0);
		free(hash);
	}
	for (i = 8; i <= target_nodeid; i++) {
		assert(mtl_append
		       (mtl_ctx, (uint8_t *) "Test Data String", 16, NULL, 0, i) == MTL_OK);
		assert(mtl_node_set_fetch(&mtl_ctx->nodes, i, i, &hash) == MTL_OK);
		free(hash);
	}

	assert(mtl_node_set_fetch
	       (&mtl_ctx->nodes, target_nodeid, target_nodeid, &hash) == MTL_OK);
	free(hash);
	assert(mtl_node_set_fetch
	       (&mtl_ctx->nodes, target_nodeid + 1, target_nodeid + 1,
		&hash) == MTL_ERROR);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Test the mtl append function with NULL parameters
 */
uint8_t mtltest_mtl_append_null(void)
{
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;

	sid.length = 8;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	assert(mtl_append(NULL, (uint8_t *) "Test Data String", 16, NULL, 0, 0) == MTL_NULL_PTR);
	assert(mtl_append(mtl_ctx, NULL, 16, NULL, 0, 0) == MTL_NULL_PTR);
	assert(mtl_append(mtl_ctx, (uint8_t *) "Test Data String", 0, NULL, 0, 0) == MTL_NULL_PTR);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Test the mtl node set update parent hash function
 */
uint8_t mtltest_mtl_node_set_update_parents(void) {
	uint32_t hash_len = 16;
	uint8_t *test_hash;
	uint8_t empty_node[32];
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;

	// Expected hash values
	uint8_t leaf_0[16];
	memset(leaf_0, 0x11, hash_len);
	uint8_t leaf_1[16];
	memset(leaf_1, 0x22, hash_len);
	uint8_t leaf_2[16];
	memset(leaf_2, 0x44, hash_len);
	uint8_t leaf_3[16];
	memset(leaf_3, 0x88, hash_len);
	// test_hash_int(left,right) == left ^ right
	uint8_t node_0_1[16];
	memset(node_0_1, 0x33, 16);
	uint8_t node_2_3[16];
	memset(node_2_3, 0xcc, 16);
	uint8_t node_0_3[16];
	memset(node_0_3, 0xff, 16);

	sid.length = 2*hash_len;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	// Add hashes for leaves 0-3
	assert(mtl_node_set_insert(&mtl_ctx->nodes, 0, 0, leaf_0) == MTL_OK);
	assert(mtl_node_set_insert(&mtl_ctx->nodes, 1, 1, leaf_1) == MTL_OK);
	assert(mtl_node_set_insert(&mtl_ctx->nodes, 2, 2, leaf_2) == MTL_OK);
	assert(mtl_node_set_insert(&mtl_ctx->nodes, 3, 3, leaf_3) == MTL_OK);

	// Verify the leaf hashes are correct
	memset(empty_node, 0x00, hash_len);		
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 0, &test_hash) == MTL_OK);
	assert(memcmp(leaf_0, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 1, 1, &test_hash) == MTL_OK);
	assert(memcmp(leaf_1, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 2, 2, &test_hash) == MTL_OK);
	assert(memcmp(leaf_2, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 3, 3, &test_hash) == MTL_OK);
	assert(memcmp(leaf_3, test_hash, hash_len) == 0);	
	free(test_hash);

	// Check parent hashes are blank
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 1, &test_hash) == MTL_OK);	
	assert(memcmp(empty_node, test_hash, hash_len) == 0);		
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 2, 3, &test_hash) == MTL_OK);
	assert(memcmp(empty_node, test_hash, hash_len) == 0);		
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 3, &test_hash) == MTL_OK);
	assert(memcmp(empty_node, test_hash, hash_len) == 0);		
	free(test_hash);

	// Update parent hashe for leaf 0
	assert(mtl_node_set_update_parents(mtl_ctx, 0) == MTL_OK);

	// Verify leaf hashes unchanged
	memset(empty_node, 0x00, hash_len);		
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 0, &test_hash) == MTL_OK);
	assert(memcmp(leaf_0, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 1, 1, &test_hash) == MTL_OK);
	assert(memcmp(leaf_1, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 2, 2, &test_hash) == MTL_OK);
	assert(memcmp(leaf_2, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 3, 3, &test_hash) == MTL_OK);
	assert(memcmp(leaf_3, test_hash, hash_len) == 0);	
	free(test_hash);

	// Verify parent hashes are still blank
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 1, &test_hash) == MTL_OK);		
	assert(memcmp(empty_node, test_hash, hash_len) == 0);		
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 2, 3, &test_hash) == MTL_OK);
	assert(memcmp(empty_node, test_hash, hash_len) == 0);		
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 3, &test_hash) == MTL_OK);	
	assert(memcmp(empty_node, test_hash, hash_len) == 0);		
	free(test_hash);

	// Update parent hashes for leaf 1
	assert(mtl_node_set_update_parents(mtl_ctx, 1) == MTL_OK);

	// Verify child hashes are unchanged
	memset(empty_node, 0x00, hash_len);		
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 0, &test_hash) == MTL_OK);
	assert(memcmp(leaf_0, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 1, 1, &test_hash) == MTL_OK);
	assert(memcmp(leaf_1, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 2, 2, &test_hash) == MTL_OK);
	assert(memcmp(leaf_2, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 3, 3, &test_hash) == MTL_OK);
	assert(memcmp(leaf_3, test_hash, hash_len) == 0);	
	free(test_hash);

	// Verify only [0,1] updated
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 1, &test_hash) == MTL_OK);	
	assert(memcmp(node_0_1, test_hash, hash_len) == 0);		
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 2, 3, &test_hash) == MTL_OK);		
	assert(memcmp(empty_node, test_hash, hash_len) == 0);		
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 3, &test_hash) == MTL_OK);	
	assert(memcmp(empty_node, test_hash, hash_len) == 0);		
	free(test_hash);

	// Update parent hashes for leaf 2 & 3
	assert(mtl_node_set_update_parents(mtl_ctx, 2) == MTL_OK);
	assert(mtl_node_set_update_parents(mtl_ctx, 3) == MTL_OK);

	// Verify child hashes are unchanged
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 0, &test_hash) == MTL_OK);
	assert(memcmp(leaf_0, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 1, 1, &test_hash) == MTL_OK);
	assert(memcmp(leaf_1, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 2, 2, &test_hash) == MTL_OK);
	assert(memcmp(leaf_2, test_hash, hash_len) == 0);
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 3, 3, &test_hash) == MTL_OK);
	assert(memcmp(leaf_3, test_hash, hash_len) == 0);	
	free(test_hash);

	// Verify all hashes updated
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 1, &test_hash) == MTL_OK);
	assert(memcmp(node_0_1, test_hash, hash_len) == 0);				
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 2, 3, &test_hash) == MTL_OK);
	assert(memcmp(node_2_3, test_hash, hash_len) == 0);			
	free(test_hash);
	assert(mtl_node_set_fetch(&mtl_ctx->nodes, 0, 3, &test_hash) == MTL_OK);
	assert(memcmp(node_0_3, test_hash, hash_len) == 0);			
	free(test_hash);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Test the mtl node set update parent hash function w/null parameters
 */
uint8_t mtltest_mtl_node_set_update_parents_null(void) {
	assert(mtl_node_set_update_parents(NULL, 5) == MTL_ERROR);
	return 0;
}


/**
 * Test the mtl authentication path function
 */
uint8_t mtltest_mtl_authpath_multi(void)
{
	MTL_CTX *mtl_ctx = NULL;
	SERIESID sid;
	MTL_INDEX i, j;
	AUTHPATH *auth;

	// Expected nodes in the tree
	uint8_t nodes[6][6][16];
	memset(nodes[0][0], 0x01, 16);
	memset(nodes[1][1], 0x02, 16);
	memset(nodes[2][2], 0x04, 16);
	memset(nodes[3][3], 0x08, 16);
	memset(nodes[4][4], 0x0a, 16);
	memset(nodes[5][5], 0x10, 16);
	// test_hash_int(left,right) == left ^ right
	memset(nodes[0][1], 0x03, 16);
	memset(nodes[2][3], 0x0c, 16);
	memset(nodes[0][3], 0x0f, 16);
	memset(nodes[4][5], 0x1a, 16);

	sid.length = 32;
	memset(sid.id, 0, MTL_SID_SIZE);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	for (i = 0; i < 6; i++) {
		assert(mtl_hash_and_append
		       (mtl_ctx, nodes[i][i], 16, NULL, 0, &j) == MTL_OK);
		assert(j == i);
	}

	// Check the auth paths for the added messages
	for (i = 0; i < 4; i++) {
		// Verify the first tree 0:3
		auth = mtl_authpath(mtl_ctx, i);
		assert(auth != NULL);

		// Verify the auth path is correct
		assert(auth->flags == 0);
		assert(auth->sid.length == sid.length);
		assert(memcmp(auth->sid.id, sid.id, sid.length) == 0);
		assert(auth->leaf_index == i);
		assert(auth->rung_left == 0);
		assert(auth->rung_right == 3);
		assert(auth->sibling_hash_count == 2);
		uint8_t sibling_1 = i^0x1;
		uint8_t sibling_2 = (i^0x2) & 0xfe;
		assert(memcmp(auth->sibling_hash, nodes[sibling_1][sibling_1], 16) == 0);
		assert(memcmp(auth->sibling_hash+16, nodes[sibling_2][sibling_2+1], 16) == 0);
		
		/** \todo update expected output buffers
	 	* assert(memcmp(auth->sibling_hash, authpath[i], 64) == 0);
		*/

		assert(mtl_authpath_free(auth) == MTL_OK);
	}
	for (i = 4; i < 6; i++) {
		// Verify the second tree 4:5
		auth = mtl_authpath(mtl_ctx, i);

		// Verify the auth path is correct
		assert(auth->flags == 0);
		assert(auth->sid.length == sid.length);
		assert(memcmp(auth->sid.id, sid.id, sid.length) == 0);
		assert(auth->leaf_index == i);
		assert(auth->rung_left == 4);
		assert(auth->rung_right == 5);
		assert(auth->sibling_hash_count == 1);
		uint8_t sibling = i ^ 0x01;
		assert(memcmp(auth->sibling_hash, nodes[sibling][sibling], 16) == 0);

		assert(mtl_authpath_free(auth) == MTL_OK);

	}
	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Test the mtl authentication path function with NULL parameters
 */
uint8_t mtltest_mtl_authpath_null(void)
{
	MTL_CTX *mtl_ctx = NULL;
	SERIESID sid;
	AUTHPATH *auth;

	sid.length = 32;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	auth = mtl_authpath(mtl_ctx, 4);
	assert(auth == NULL);
	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Test the mtl ladder function
 */
uint8_t mtltest_mtl_ladder_multi(void)
{
	MTL_CTX *mtl_ctx = NULL;
	SERIESID sid;
	MTL_INDEX i, j;
	LADDER *ladder;
	
	// Expected nodes in the tree
	uint8_t nodes[6][6][16];
	memset(nodes[0][0], 0x01, 16);
	memset(nodes[1][1], 0x02, 16);
	memset(nodes[2][2], 0x04, 16);
	memset(nodes[3][3], 0x08, 16);
	memset(nodes[4][4], 0x0a, 16);
	memset(nodes[5][5], 0x10, 16);
	// test_hash_int(left,right) == left ^ right
	memset(nodes[0][1], 0x03, 16);
	memset(nodes[2][3], 0x0c, 16);
	memset(nodes[0][3], 0x0f, 16);
	memset(nodes[4][5], 0x1a, 16);

	sid.length = 32;
	memset(sid.id, 0, MTL_SID_SIZE);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	for (i = 0; i < 6; i++) {
		assert(mtl_hash_and_append
		       (mtl_ctx, nodes[i][i], 16, NULL, 0, &j) == MTL_OK);
		assert(j == i);
	}

	ladder = mtl_ladder(mtl_ctx);
	assert(ladder->flags == 0);
	assert(ladder->sid.length == sid.length);
	assert(memcmp(ladder->sid.id, sid.id, sid.length) == 0);
	assert(ladder->rung_count == 2);

	RUNG *rung_ptr = ladder->rungs;

	assert(rung_ptr[0].left_index == 0);
	assert(rung_ptr[0].right_index == 3);
	assert(rung_ptr[0].hash_length == 16);
	assert(memcmp(rung_ptr[0].hash, nodes[0][3], 16) == 0);
	

	assert(rung_ptr[1].left_index == 4);
	assert(rung_ptr[1].right_index == 5);
	assert(rung_ptr[1].hash_length == 16);
	assert(memcmp(rung_ptr[1].hash, nodes[4][5], 16) == 0);

	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Test the mtl ladder function with NULL parameters
 */
uint8_t mtltest_mtl_ladder_null(void)
{
	MTL_CTX *mtl_ctx = NULL;
	SERIESID sid;
	LADDER *ladder;

	sid.length = 32;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	assert(mtl_ladder(NULL) == NULL);
	ladder = mtl_ladder(mtl_ctx);
	assert(ladder != NULL);
	assert(ladder->flags == 0);
	assert(ladder->sid.length == sid.length);
	assert(memcmp(ladder->sid.id, sid.id, sid.length) == 0);
	assert(ladder->rung_count == 0);
	assert(ladder->rungs != NULL);

	assert(mtl_ladder_free(ladder) == MTL_OK);
 	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Test the mtl rung function
 */
uint8_t mtltest_mtl_rung(void)
{
	MTL_CTX *mtl_ctx = NULL;
	SERIESID sid;
	MTL_INDEX i, j;
	LADDER *ladder;
	AUTHPATH *auth;
	RUNG *rung;

	// Expected nodes in the tree
	uint8_t nodes[6][6][16];
	memset(nodes[0][0], 0x01, 16);
	memset(nodes[1][1], 0x02, 16);
	memset(nodes[2][2], 0x04, 16);
	memset(nodes[3][3], 0x08, 16);
	memset(nodes[4][4], 0x0a, 16);
	memset(nodes[5][5], 0x10, 16);
	// test_hash_int(left,right) == left ^ right
	memset(nodes[0][1], 0x03, 16);
	memset(nodes[2][3], 0x0c, 16);
	memset(nodes[0][3], 0x0f, 16);
	memset(nodes[4][5], 0x1a, 16);

	sid.length = 32;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	for (i = 0; i < 6; i++) {
		assert(mtl_hash_and_append
		       (mtl_ctx, nodes[i][i], 16, NULL, 0, &j) == MTL_OK);
		assert(j == i);
	}

	ladder = mtl_ladder(mtl_ctx);
	// Verify rungs are fetched in the first tree 0:3
	auth = mtl_authpath(mtl_ctx, 1);
	rung = mtl_rung(auth, ladder);

	assert(rung != NULL);
	assert(rung->left_index == 0);
	assert(rung->right_index == 3);
	assert(rung->hash_length == 16);
	assert(memcmp(rung->hash, nodes[0][3], 16) == 0);

	// Rung is a pointer into the ladder and thus does not need free
	assert(mtl_authpath_free(auth) == MTL_OK);

	// Verify rungs are fetched in the first tree 4:5
	auth = mtl_authpath(mtl_ctx, 4);
	rung = mtl_rung(auth, ladder);

	assert(rung != NULL);
	assert(rung->left_index == 4);
	assert(rung->right_index == 5);
	assert(rung->hash_length == 16);
	assert(memcmp(rung->hash, nodes[4][5], 16) == 0);


	// Rung is a pointer into the ladder and thus does not need free
	assert(mtl_authpath_free(auth) == MTL_OK);
	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Test the mtl rung function with NULL parameters
 */
uint8_t mtltest_mtl_rung_null(void)
{
	MTL_CTX *mtl_ctx = NULL;
	SERIESID sid;
	MTL_INDEX i, j;
	RUNG *rung;
	LADDER *ladder;
	AUTHPATH *auth;

	// Expected nodes in the tree
	uint8_t nodes[6][6][16];
	memset(nodes[0][0], 0x01, 16);
	memset(nodes[1][1], 0x02, 16);
	memset(nodes[2][2], 0x04, 16);
	memset(nodes[3][3], 0x08, 16);
	memset(nodes[4][4], 0x0a, 16);
	memset(nodes[5][5], 0x10, 16);
	// test_hash_int(left,right) == left ^ right
	memset(nodes[0][1], 0x03, 16);
	memset(nodes[2][3], 0x0c, 16);
	memset(nodes[0][3], 0x0f, 16);
	memset(nodes[4][5], 0x1a, 16);

	sid.length = 32;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	for (i = 0; i < 6; i++) {
		assert(mtl_hash_and_append
		       (mtl_ctx, nodes[i][i], 16, NULL, 0, &j) == MTL_OK);
		assert(j == i);
	}

	ladder = mtl_ladder(mtl_ctx);
	auth = mtl_authpath(mtl_ctx, 1);

	// Verify null parameters are handled appropriately
	rung = mtl_rung(NULL, ladder);
	assert(rung == NULL);

	rung = mtl_rung(auth, NULL);
	assert(rung == NULL);

	// Verify incompatible auth path 
	auth->leaf_index = 6;
	rung = mtl_rung(auth, ladder);
	assert(rung == NULL);
	auth->leaf_index = 1;

	// Verify incompatible auth path 
	auth->sibling_hash_count = 1;
	rung = mtl_rung(auth, ladder);
	assert(rung == NULL);
	auth->sibling_hash_count = 2;

	// Verify invalid ladder
	ladder->rungs[0].left_index = 6;
	ladder->rungs[0].right_index = 10;
	rung = mtl_rung(auth, ladder);
	assert(rung == NULL);
	ladder->rungs[0].left_index = 0;
	ladder->rungs[0].right_index = 3;

	// Mismatching SID
	auth->sid.length = 32;
	memset(auth->sid.id, 0xff, auth->sid.length);
	rung = mtl_rung(auth, ladder);
	assert(rung == NULL);

	// Rung is a pointer into the ladder and thus does not need free
	assert(mtl_authpath_free(auth) == MTL_OK);
	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/** \todo Revist once PRF randomizers are implemented
 * Test the mtl verify function
 *
uint8_t mtltest_mtl_verify(void)
{
	MTL_CTX *mtl_ctx = NULL;
	MTL_CTX *mtl_verify_ctx = NULL;
	SERIESID sid;
	SEED pk_seed;
	uint32_t i, j;
	RUNG *rung;
	LADDER *ladder;
	AUTHPATH *auth;
	RANDOMIZER *mtl_random;
	uint8_t data_value[EVP_MAX_MD_SIZE];

	sid.length = 8;
	memset(sid.id, 0, sid.length);
	pk_seed.length = 32;
	memset(pk_seed.seed, 0, 32);

	assert(mtl_initns(&mtl_ctx, &pk_seed, &sid, NULL) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 0,
					mtl_test_hash_msg,
					mtl_test_hash_leaf,
					mtl_test_hash_int, NULL) == MTL_OK);

	for (i = 0; i < 6; i++) {
		assert(mtl_hash_and_append
		       (mtl_ctx, (uint8_t *) "Test Data String", 16, &j) == MTL_OK);
		assert(j == i);
	}

	ladder = mtl_ladder(mtl_ctx);
	assert(mtl_randomizer_and_authpath(mtl_ctx, 1, &mtl_random, &auth) == MTL_OK);
	rung = mtl_rung(auth, ladder);

	// Make a new context for verfication (it doesn't have the secret key data)
	assert(mtl_initns(&mtl_verify_ctx, &pk_seed, &sid, NULL) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_verify_ctx, 0,
					mtl_test_hash_msg,
					mtl_test_hash_leaf,
					mtl_test_hash_int, NULL) == MTL_OK);

	// Test verification function with good randomizer
	mtl_test_hash_msg(mtl_verify_ctx->sig_params, &mtl_verify_ctx->sid, 1,
			  mtl_random->value, mtl_random->length,
			  (uint8_t *) "Test Data String", 16, &data_value[0],
			  mtl_verify_ctx->nodes.hash_size, NULL, &mtl_random->value, &mtl_random->length);
				  
	assert(mtl_verify
	       (mtl_verify_ctx, data_value, mtl_verify_ctx->nodes.hash_size,
				mtl_random, auth, rung) == MTL_OK);

	assert(mtl_authpath_free(auth) == MTL_OK);
	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);
	assert(mtl_free(mtl_verify_ctx) == MTL_OK);
	free(mtl_random->value);
	free(mtl_random);

	return 0;
}
*/

/**
 * Test the mtl verify function with randomization
 */
uint8_t mtltest_mtl_verify_rand(void)
{
	MTL_CTX *mtl_ctx = NULL;
	MTL_CTX *mtl_verify_ctx = NULL;
	SERIESID sid;
	MTL_INDEX i, j;
	RUNG *rung;
	LADDER *ladder;
	AUTHPATH *auth;
	RANDOMIZER *mtl_random;
	uint8_t* rmtl_ptr = NULL;

	sid.length = 32;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_node_set_hash_leaf_sha2,
					mtl_node_set_hash_int_sha2) == MTL_OK);

	for (i = 0; i < 6; i++) {
		assert(mtl_hash_and_append
		       (mtl_ctx, (uint8_t *) "Test Data String", 16, NULL, 0, &j) == MTL_OK);
		assert(j == i);
	}

	ladder = mtl_ladder(mtl_ctx);
	assert(ladder != NULL);
	assert(mtl_randomizer_and_authpath(mtl_ctx, 1, &mtl_random, &auth) == MTL_OK);
	rung = mtl_rung(auth, ladder);
	assert(rung != NULL);

	// Make a new context for verfication (it doesn't have the secret key data)
	assert(mtl_initns(&mtl_verify_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_verify_ctx, 1,
					mtl_node_set_hash_leaf_sha2,
					mtl_node_set_hash_int_sha2) == MTL_OK);

	// Test verification function with different randomizer
	mtl_random->value[3] = ~mtl_random->value[3];
	assert(mtl_verify
	       (mtl_verify_ctx, (uint8_t *)"Test Data String", mtl_verify_ctx->nodes.hash_size,
				NULL, 0, mtl_random, auth, rung) == MTL_BOGUS);
	

	// Rung is a pointer into the ladder and thus does not need free
	assert(mtl_randomizer_free(mtl_random) == MTL_OK);
	assert(mtl_authpath_free(auth) == MTL_OK);
	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);
	assert(mtl_free(mtl_verify_ctx) == MTL_OK);
	free(rmtl_ptr);

	return 0;
}

/**
 * Test the mtl verify function with NULL parameters
 */
uint8_t mtltest_mtl_verify_null(void)
{
	MTL_CTX *mtl_ctx = NULL;
	MTL_CTX *mtl_verify_ctx = NULL;
	SERIESID sid;
	MTL_INDEX i, j;
	RUNG *rung;
	LADDER *ladder;
	AUTHPATH *auth;
	RANDOMIZER *mtl_rand;

	sid.length = 8;
	memset(sid.id, 0, sid.length);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	for (i = 0; i < 6; i++) {
		assert(mtl_hash_and_append
		       (mtl_ctx, (uint8_t *) "Test Data String", 16, NULL, 0, &j) == MTL_OK);
		assert(j == i);
	}

	ladder = mtl_ladder(mtl_ctx);
	assert(mtl_randomizer_and_authpath(mtl_ctx, 1, &mtl_rand, &auth) == MTL_OK);
	rung = mtl_rung(auth, ladder);

	// Make a new context for verfication (it doesn't have the secret key data)
	assert(mtl_initns(&mtl_verify_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_verify_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	// NULL CTX
	assert(mtl_verify
	       (NULL, (uint8_t *) "Test Data String", 16, NULL, 0, mtl_rand, auth, rung) == MTL_NULL_PTR);
	// NULL message
	assert(mtl_verify(mtl_verify_ctx, NULL, 16, NULL, 0, mtl_rand, auth, rung) == MTL_NULL_PTR);
	assert(mtl_verify
	       (mtl_verify_ctx, (uint8_t *) "Test Data String", 0, NULL, 0,
				mtl_rand, auth, rung) == MTL_NULL_PTR);
	// NULL Randomizer
	assert(mtl_verify
	       (mtl_verify_ctx, (uint8_t *) "Test Data String", 16, NULL, 0,
				NULL, auth, rung) == MTL_NULL_PTR);
	// NULL Auth
	assert(mtl_verify
	       (mtl_verify_ctx, (uint8_t *) "Test Data String", 16, NULL, 0,
				mtl_rand, NULL, rung) == MTL_NULL_PTR);
	// NULL Rung
	assert(mtl_verify
	       (mtl_verify_ctx, (uint8_t *) "Test Data String", 16, NULL, 0,
				mtl_rand, auth, NULL) == MTL_NULL_PTR);

	// Rung is a pointer into the ladder and thus does not need free
	assert(mtl_randomizer_free(mtl_rand) == MTL_OK);
	assert(mtl_authpath_free(auth) == MTL_OK);
	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);
	assert(mtl_free(mtl_verify_ctx) == MTL_OK);

	return 0;
}
