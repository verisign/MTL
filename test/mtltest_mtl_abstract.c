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
uint8_t mtltest_mtl_generate_randomizer(void);
//uint8_t mtltest_mtl_hash_and_append(void);
uint8_t mtltest_mtl_hash_and_append_random(void);
//uint8_t mtltest_mtl_hash_and_verify(void);
uint8_t mtltest_mtl_hash_and_verify_random(void);
//uint8_t mtltest_mtl_randomizer_and_authpath(void);
uint8_t mtltest_mtl_randomizer_and_authpath_random(void);

uint8_t mtltest_mtl_abstract(void)
{
	NEW_TEST("MTL Abstract Functions");

	RUN_TEST(mtltest_mtl_generate_randomizer,
		 "Test MTL Randomizer Generation");
//	RUN_TEST(mtltest_mtl_hash_and_append, "Test MTL hash and append");
	RUN_TEST(mtltest_mtl_hash_and_append_random,
		 "Test MTL hash and append w/randomization");
//	RUN_TEST(mtltest_mtl_hash_and_verify, "Test MTL hash and verify");
	RUN_TEST(mtltest_mtl_hash_and_verify_random,
		 "Test MTL hash and verify w/randomization");
//	RUN_TEST(mtltest_mtl_randomizer_and_authpath,
//		 "Test MTL get randomizer and authpath");
	RUN_TEST(mtltest_mtl_randomizer_and_authpath_random,
		 "Test MTL get randomizer and authpath w/randomization");

	return 0;
}

/**
 * Verify the MTL randomizer generator
 */
uint8_t mtltest_mtl_generate_randomizer(void)
{
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	RANDOMIZER *randomizer;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 32;

	assert(mtl_initns(&mtl_ctx, &sid, MTL_PRIVATE_KEY) == MTL_OK);

	/** \todo Revisit this test when PRF randomizer support enabled
	// Check that the seed is used for the randomizer
	mtl_ctx->randomize = 0;
	assert(mtl_generate_randomizer(mtl_ctx, &randomizer) == MTL_OK);
	assert(randomizer->length == mtl_ctx->nodes.hash_size);
	assert(mtl_randomizer_free(randomizer) == MTL_OK);

	// Check that randomizer is not the seed when configured
	mtl_ctx->randomize = 1;
	assert(mtl_generate_randomizer(mtl_ctx, &randomizer) == MTL_OK);
	assert(randomizer->length == pk_seed.length);
	assert(memcmp(randomizer->value, pk_seed.seed, pk_seed.length) != 0);
	assert(mtl_randomizer_free(randomizer) == MTL_OK);
	*/

	// Check NULL parameters
	mtl_ctx->randomize = 0;
	assert(mtl_generate_randomizer(NULL, &randomizer) == MTL_NULL_PTR);
	assert(mtl_generate_randomizer(mtl_ctx, NULL) == MTL_NULL_PTR);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/** \todo Revisit this test once PRF randomization implemented
 * Verify message hashing and appending w/random.
 *
uint8_t mtltest_mtl_hash_and_append(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	uint32_t index, added_index;
	static const SPX_PARAMS params;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;

	memset(&pk_seed, 0, sizeof(SEED));
	pk_seed.length = 32;
	memset(pk_seed.seed, 0x55, 32);

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, (void*)&params, 0,
					mtl_test_hash_leaf,
					mtl_test_hash_int, NULL) == MTL_OK);

	// Verify inserting records
	for (index = 0; index < 16; index++) {
		assert(mtl_ctx->nodes.leaf_count == index);
		sprintf(message_buffer, "Verification Msg %d\n", index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer), &added_index) == MTL_OK);
		assert(added_index == index);
		assert(mtl_ctx->nodes.leaf_count == index+1);
	}

	assert(mtl_ctx->nodes.leaf_count == 16);
	assert(mtl_ctx->nodes.hash_size == 32);
	assert(mtl_ctx->nodes.tree_pages[0] != NULL);
	assert(mtl_ctx->nodes.tree_pages[1] == NULL);

	// Verify NULL parameters
	assert(mtl_hash_and_append
	       (NULL, (unsigned char *)message_buffer,
		strlen(message_buffer), &added_index) == MTL_NULL_PTR);
	assert(mtl_hash_and_append(mtl_ctx, NULL, strlen(message_buffer), &added_index) ==
	       MTL_NULL_PTR);
	assert(mtl_hash_and_append(mtl_ctx, (unsigned char *)message_buffer, 0, &added_index)
	       == MTL_NULL_PTR);
	assert(mtl_hash_and_append(mtl_ctx, (unsigned char *)message_buffer, strlen(message_buffer), NULL ) == MTL_NULL_PTR);


	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}
*/

/**
 * Verify message hashing and appending.
 */
uint8_t mtltest_mtl_hash_and_append_random(void)
{
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	size_t message_buffer_len = 19;
	char message_buffer[] = "Test Message Buffer";
	MTL_INDEX index, added_index;
	uint8_t *rand = NULL;
	uint8_t *hash_buffer = NULL;
	uint8_t *hash_buffer_l2 = NULL;
	uint8_t *hash_buffer_l3 = NULL;
	uint8_t *hash_buffer_l4 = NULL;
	uint8_t *hash_buffer_l5 = NULL;
	uint32_t i;

	// input messages
	uint8_t msgs[16][32];
	for (i = 0; i < 16; i++) {
		memset(msgs[i], 1 << i, 32);
	}
	// expected hash values
	uint8_t hashes[16][16][16]; // left_index, right_index, bytes
	for (i = 0; i < 16; i++) {
		memset(hashes[i][i], 1<< (i%8), 16);
	}
	for (i = 0; i < 16; i+=2) {
		memset(hashes[i][i+1], 3 << (i%8), 16);
	}
	for (i = 0; i < 16; i+=4) {
		memset(hashes[i][i+3], 0x0f << (i%8), 16);
	}
	for (i = 0; i < 16; i+=8) {
		memset(hashes[i][i+7], 0xff, 16);
	}
	memset(hashes[0][15], 0, 16);

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 32;

	assert(mtl_initns(&mtl_ctx, &sid, MTL_PRIVATE_KEY) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	// Verify inserting records
	for (index = 0; index < 16; index++) {
		// Nodes don't exist before append
		assert(mtl_node_set_fetch(&mtl_ctx->nodes, index, index, &hash_buffer) != MTL_OK);
		assert(mtl_node_set_get_randomizer(&mtl_ctx->nodes, index, &rand) != MTL_OK);
		// Also check parent hashes
		if (index % 2 == 1) {
			if (index % 4 == 3) {
				if (index % 8 == 7) {
					if (index == 15) {
						assert(mtl_node_set_fetch(&mtl_ctx->nodes, index, index, &hash_buffer_l5) != MTL_OK);
					}
					assert(mtl_node_set_fetch(&mtl_ctx->nodes, index, index, &hash_buffer_l4) != MTL_OK);
				}
				assert(mtl_node_set_fetch(&mtl_ctx->nodes, index, index, &hash_buffer_l3) != MTL_OK);
			}
			assert(mtl_node_set_fetch(&mtl_ctx->nodes, index, index, &hash_buffer_l2) != MTL_OK);
		}

		assert(mtl_ctx->nodes.leaf_count == index);
		assert(mtl_hash_and_append
		       (mtl_ctx, hashes[index][index],
			16, NULL, 0, &added_index) == MTL_OK);
		assert(added_index == index);
		assert(mtl_ctx->nodes.leaf_count == index+1);

		// after append nodes exist
		assert(mtl_node_set_fetch(&mtl_ctx->nodes, index, index, &hash_buffer) == MTL_OK);
		assert(mtl_node_set_get_randomizer(&mtl_ctx->nodes, added_index, &rand) == MTL_OK);
		// Also check parent hashes
		if (index % 2 == 1) {
			if (index % 4 == 3) {
				if (index % 8 == 7) {
					if (index == 15) {
						assert(mtl_node_set_fetch(&mtl_ctx->nodes, index-15, index, &hash_buffer_l5) == MTL_OK);
					}
					assert(mtl_node_set_fetch(&mtl_ctx->nodes, index-7, index, &hash_buffer_l4) == MTL_OK);
				}
				assert(mtl_node_set_fetch(&mtl_ctx->nodes, index-3, index, &hash_buffer_l3) == MTL_OK);
			}
			assert(mtl_node_set_fetch(&mtl_ctx->nodes, index-1, index, &hash_buffer_l2) == MTL_OK);
		}

		// node hashes match expected values
		assert(memcmp(hash_buffer, hashes[index][index], 16) == 0);
		// parent hashes match expected values
		if (index % 2 == 1) {
			if (index % 4 == 3) {
				if (index % 8 == 7) {
					if (index == 15) {
						assert(memcmp(hash_buffer_l5, hashes[index-15][index], 16) == 0);
						free(hash_buffer_l5);
					}
					assert(memcmp(hash_buffer_l4, hashes[index-7][index], 16) == 0);
					free(hash_buffer_l4);
				}
				assert(memcmp(hash_buffer_l3, hashes[index-3][index], 16) == 0);
				free(hash_buffer_l3);
			}
			assert(memcmp(hash_buffer_l2, hashes[index-1][index], 16) == 0);
			free(hash_buffer_l2);
		}
		free(hash_buffer);
		free(rand);
	}

	assert(mtl_ctx->nodes.leaf_count == 16);
	assert(mtl_ctx->nodes.hash_size == 16);
	assert(mtl_ctx->nodes.tree_pages[0] != NULL);
	assert(mtl_ctx->nodes.tree_pages[1] == NULL);

	// Verify NULL parameters
	assert(mtl_hash_and_append
	       (NULL, (unsigned char *)message_buffer,
		message_buffer_len, NULL, 0, &added_index) == MTL_NULL_PTR);
	assert(mtl_hash_and_append(mtl_ctx, NULL, message_buffer_len, NULL, 0, &added_index) ==
	       MTL_NULL_PTR);
	assert(mtl_hash_and_append(mtl_ctx, (unsigned char *)message_buffer, 0, NULL, 0, &added_index)
	       == MTL_NULL_PTR);
	assert(mtl_hash_and_append(mtl_ctx, (unsigned char *)message_buffer, message_buffer_len, NULL, 0, NULL ) == MTL_NULL_PTR);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}



/** \todo Revisit this test once PRF randomization implemented
 * Verify fetching the randomizer and authpath
 *
uint8_t mtltest_mtl_randomizer_and_authpath(void)
{
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	uint32_t index, added_index;
	static const SPX_PARAMS params;
	RANDOMIZER *mtl_rand;
	AUTHPATH *auth;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 32;

	assert(mtl_initns(&mtl_ctx, &sid) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, (void*)&params, 0,
					mtl_test_hash_leaf,
					mtl_test_hash_int, NULL) == MTL_OK);

	// Insert records for verification later
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %d\n", index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer), &added_index) == MTL_OK);
	}

	// Verify that authpaths and randomizers are avaialble
	for (index = 0; index < 16; index++) {
		assert(mtl_randomizer_and_authpath
		       (mtl_ctx, index, &mtl_rand, &auth) == MTL_OK);

		assert(mtl_rand->length == 32);
		assert(memcmp(mtl_rand->value, pk_seed.seed, pk_seed.length) ==
		       0);

		assert(auth->flags == 0);
		assert(auth->sid.length == sid.length);
		assert(memcmp(auth->sid.id, sid.id, sid.length) == 0);
		assert(auth->leaf_index == index);
		assert(auth->rung_left == 0);
		assert(auth->rung_right == 15);
		assert(auth->sibling_hash_count == 4);

		mtl_authpath_free(auth);
		mtl_randomizer_free(mtl_rand);
	}

	// Test NULL parameters
	assert(mtl_randomizer_and_authpath(NULL, index, &mtl_rand, &auth) == MTL_NULL_PTR);
	assert(mtl_randomizer_and_authpath(mtl_ctx, index, NULL, &auth) == MTL_NULL_PTR);
	assert(mtl_randomizer_and_authpath(mtl_ctx, index, &mtl_rand, NULL) == MTL_NULL_PTR);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}
*/

/**
 * Verify fetching the randomizer and authpath w/random
 */
uint8_t mtltest_mtl_randomizer_and_authpath_random(void)
{
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	MTL_INDEX index, added_index;
	RANDOMIZER *mtl_rand;
	AUTHPATH *auth;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 32;


	assert(mtl_initns(&mtl_ctx, &sid, MTL_PRIVATE_KEY) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	// Insert records for verification later
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %lu\n", (long unsigned int)index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer), NULL, 0, &added_index) == MTL_OK);
	}

	// Verify that authpaths and randomizers are avaialble
	for (index = 0; index < 16; index++) {
		assert(mtl_randomizer_and_authpath
		       (mtl_ctx, index, &mtl_rand, &auth) == MTL_OK);

		assert(mtl_rand->length == 16);
		assert(memcmp(mtl_rand->value, sid.id, sid.length) != 0);

		assert(auth->flags == 0);
		assert(auth->sid.length == sid.length);
		assert(memcmp(auth->sid.id, sid.id, sid.length) == 0);
		assert(auth->leaf_index == index);
		assert(auth->rung_left == 0);
		assert(auth->rung_right == 15);
		assert(auth->sibling_hash_count == 4);

		mtl_authpath_free(auth);
		mtl_randomizer_free(mtl_rand);
	}

	// Test NULL parameters
	assert(mtl_randomizer_and_authpath(NULL, index, &mtl_rand, &auth) == MTL_NULL_PTR);
	assert(mtl_randomizer_and_authpath(mtl_ctx, index, NULL, &auth)  == MTL_NULL_PTR);
	assert(mtl_randomizer_and_authpath(mtl_ctx, index, &mtl_rand, NULL) == MTL_NULL_PTR);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/** \todo Revisit this test once PRF randomization implemented
 * Verify message hashing and verification
 *
uint8_t mtltest_mtl_hash_and_verify(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	uint32_t index, added_index;
	static const SPX_PARAMS params;
	RANDOMIZER *mtl_rand;
	AUTHPATH *auth;
	LADDER *ladder;
	RUNG *rung;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;

	memset(&pk_seed, 0x22, sizeof(SEED));
	pk_seed.length = 32;
	memset(pk_seed.seed, 0x55, 32);

	assert(mtl_initns(&mtl_ctx, &pk_seed, &sid, NULL) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, (void*)&params, 0,
					mtl_test_hash_msg,
					mtl_test_hash_leaf,
					mtl_test_hash_int, NULL) == MTL_OK);

	// Insert records for verification later
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %d\n", index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer), &added_index) == MTL_OK);
		assert(added_index == index);
	}

	// Get ladder and rung
	ladder = mtl_ladder(mtl_ctx);

	// Verify that authpaths and randomizers are avaialble
	for (index = 0; index < 16; index++) {
		assert(mtl_randomizer_and_authpath
		       (mtl_ctx, index, &mtl_rand, &auth) == MTL_OK);

		sprintf(message_buffer, "Verification Msg %d\n", index);
		rung = mtl_rung(auth, ladder);
		assert(mtl_hash_and_verify
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer), mtl_rand, auth, rung) == MTL_OK);

		assert(mtl_authpath_free(auth) == MTL_OK);
		assert(mtl_randomizer_free(mtl_rand) == MTL_OK);
	}

	// Verify NULL parameters
	assert(mtl_hash_and_verify(NULL, (unsigned char *)message_buffer,
				   strlen(message_buffer), mtl_rand,
				   auth, rung) != MTL_OK);
	assert(mtl_hash_and_verify(mtl_ctx, NULL,
				   strlen(message_buffer), mtl_rand,
				   auth, rung) != MTL_OK);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   0, mtl_rand, auth, rung) != MTL_OK);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), NULL,
				   auth, rung) != MTL_OK);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), mtl_rand,
				   NULL, rung) != MTL_OK);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), mtl_rand,
				   auth, NULL) != MTL_OK);

	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}
*/

/**
 * Verify message hashing and verification w/randomization
 */
uint8_t mtltest_mtl_hash_and_verify_random(void)
{
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	MTL_INDEX index, added_index;
	RANDOMIZER *mtl_rand;
	AUTHPATH *auth;
	LADDER *ladder;
	RUNG *rung;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 32;


	assert(mtl_initns(&mtl_ctx, &sid, MTL_PRIVATE_KEY) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, 1,
					mtl_test_hash_leaf,
					mtl_test_hash_int) == MTL_OK);

	// Insert records for verification later
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %lu\n", (long unsigned int)index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer), NULL, 0, &added_index) == MTL_OK);
		assert(added_index == index);
	}

	// Get ladder and rung
	ladder = mtl_ladder(mtl_ctx);

	// Verify that authpaths and randomizers are avaialble
	for (index = 0; index < 16; index++) {
		assert(mtl_randomizer_and_authpath
		       (mtl_ctx, index, &mtl_rand, &auth) == MTL_OK);

		sprintf(message_buffer, "Verification Msg %lu\n", (long unsigned int)index);
		rung = mtl_rung(auth, ladder);
		assert(mtl_hash_and_verify
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer), NULL, 0, mtl_rand, auth, rung) == MTL_OK);

		assert(mtl_authpath_free(auth) == MTL_OK);
		assert(mtl_randomizer_free(mtl_rand) == MTL_OK);
	}

	// Verify NULL parameters
	assert(mtl_hash_and_verify(NULL, (unsigned char *)message_buffer,
				   strlen(message_buffer), NULL, 0, mtl_rand,
				   auth, rung) == MTL_NULL_PTR);
	assert(mtl_hash_and_verify(mtl_ctx, NULL,
				   strlen(message_buffer), NULL, 0, mtl_rand,
				   auth, rung) == MTL_NULL_PTR);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   0, NULL, 0, mtl_rand, auth, rung) == MTL_NULL_PTR);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), NULL, 0, NULL,
				   auth, rung) == MTL_NULL_PTR);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), NULL, 0, mtl_rand,
				   NULL, rung) == MTL_NULL_PTR);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), NULL, 0, mtl_rand,
				   auth, NULL) == MTL_NULL_PTR);

	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;

}
