/*
	Copyright (c) 2024, VeriSign, Inc.
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
#include <assert.h>
#include <string.h>

#include "mtltest.h"
#include "mtl_node_set.h"
#include "mtl_error.h"
#include "mtl.h"
#include "mtl_spx.h"
#include "mtltest_mock.h"

// Prototypes for testing functions
uint8_t mtltest_mtl_generate_randomizer(void);
uint8_t mtltest_mtl_get_scheme_separated_buffer(void);
uint8_t mtltest_mtl_hash_and_append(void);
uint8_t mtltest_mtl_hash_and_append_random(void);
uint8_t mtltest_mtl_hash_and_verify(void);
uint8_t mtltest_mtl_hash_and_verify_random(void);
uint8_t mtltest_mtl_randomizer_and_authpath(void);
uint8_t mtltest_mtl_randomizer_and_authpath_random(void);

uint8_t mtltest_mtl_abstract(void)
{
	NEW_TEST("MTL Abstract Functions");

	RUN_TEST(mtltest_mtl_generate_randomizer,
		 "Test MTL Randomizer Generation");
	RUN_TEST(mtltest_mtl_get_scheme_separated_buffer,
		 "Test MTL Separation Buffer");
	RUN_TEST(mtltest_mtl_hash_and_append, "Test MTL hash and append");
	RUN_TEST(mtltest_mtl_hash_and_append_random,
		 "Test MTL hash and append w/randomization");
	RUN_TEST(mtltest_mtl_hash_and_verify, "Test MTL hash and verify");
	RUN_TEST(mtltest_mtl_hash_and_verify_random,
		 "Test MTL hash and verify w/randomization");
	RUN_TEST(mtltest_mtl_randomizer_and_authpath,
		 "Test MTL get randomizer and authpath");
	RUN_TEST(mtltest_mtl_randomizer_and_authpath_random,
		 "Test MTL get randomizer and authpath w/randomization");

	return 0;
}

/**
 * Verify the MTL randomizer generator
 */
uint8_t mtltest_mtl_generate_randomizer(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	RANDOMIZER *randomizer;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;

	memset(&pk_seed, 0, sizeof(SEED));
	pk_seed.length = 32;
	memset(pk_seed.seed, 0x55, 32);

	assert(mtl_initns(&mtl_ctx, &pk_seed, &sid, NULL) == MTL_OK);

	// Check that the seed is used for the randomizer
	mtl_ctx->randomize = 0;
	assert(mtl_generate_randomizer(mtl_ctx, &randomizer) == 0);
	assert(randomizer->length == pk_seed.length);
	assert(memcmp(randomizer->value, pk_seed.seed, pk_seed.length) == 0);
	assert(mtl_randomizer_free(randomizer) == MTL_OK);

	// Check that randomizer is not the seed when configured
	mtl_ctx->randomize = 1;
	assert(mtl_generate_randomizer(mtl_ctx, &randomizer) == 0);
	assert(randomizer->length == pk_seed.length);
	assert(memcmp(randomizer->value, pk_seed.seed, pk_seed.length) != 0);
	assert(mtl_randomizer_free(randomizer) == MTL_OK);

	// Check NULL parameters
	mtl_ctx->randomize = 0;
	assert(mtl_generate_randomizer(NULL, &randomizer) == 1);
	assert(mtl_generate_randomizer(mtl_ctx, NULL) == 1);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Verify generation for the underlying signature buffer
 * with proper separation from the MTL scheme.
 */
uint8_t mtltest_mtl_get_scheme_separated_buffer(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	LADDER *ladder;
	uint8_t *buffer = NULL;
	uint8_t rung_data[] = { 0x0e, 0xea, 0xdb, 0x7e, 0x93, 0x86, 0xf7, 0xce,
		0x6a, 0x24, 0x70, 0x8f, 0xc1, 0x38, 0xfd, 0x72,
		0x6b, 0x0c, 0xef, 0xbf, 0x93, 0x49, 0xcb, 0xc8,
		0xb0, 0x40, 0xe3, 0xb5, 0x5a, 0xc2, 0xda, 0x91
	};
	uint8_t results[] = 
		{ 0x81, 0x00, 0x2b, 0xce, 0x0f, 0x06, 0x0a, 0x10,
		0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03, 0x0e, 0xea, 0xdb, 0x7e,
		0x93, 0x86, 0xf7, 0xce, 0x6a, 0x24, 0x70, 0x8f,
		0xc1, 0x38, 0xfd, 0x72, 0x6b, 0x0c, 0xef, 0xbf,
		0x93, 0x49, 0xcb, 0xc8, 0xb0, 0x40, 0xe3, 0xb5,
		0x5a, 0xc2, 0xda, 0x91
	};
	uint8_t oid[] = {0x2B, 0xCE, 0x0F, 0x06, 0x0A, 0x10 };

	memset(&sid, 0xAA, sizeof(SERIESID));
	sid.length = 8;

	memset(&pk_seed, 0, sizeof(SEED));
	pk_seed.length = 32;
	memset(pk_seed.seed, 0x55, 32);

	assert(mtl_initns(&mtl_ctx, &pk_seed, &sid, NULL) == MTL_OK);

	ladder = mtl_ladder(mtl_ctx);
	ladder->flags = 0;
	ladder->sid.length = sid.length;
	memcpy(ladder->sid.id, sid.id, sid.length);
	ladder->rung_count = 1;
	free(ladder->rungs);
	ladder->rungs = malloc(sizeof(RUNG));

	ladder->rungs->left_index = 0;
	ladder->rungs->right_index = 3;
	ladder->rungs->hash_length = 32;
	memcpy(ladder->rungs->hash, rung_data, 32);

	assert(mtl_get_scheme_separated_buffer(mtl_ctx, ladder, 32, &buffer, 
	    &oid[0], 6) == 60);		
	assert(memcmp(buffer, results, 60) == 0);
	assert(memcmp(buffer+2, oid, 6) == 0);

	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);
	free(buffer);
	return 0;
}

/**
 * Verify message hashing and appending.
 */
uint8_t mtltest_mtl_hash_and_append(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	uint16_t index;
	static const SPX_PARAMS params;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;

	memset(&pk_seed, 0, sizeof(SEED));
	pk_seed.length = 32;
	memset(pk_seed.seed, 0x55, 32);

	assert(mtl_initns(&mtl_ctx, &pk_seed, &sid, NULL) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, (void*)&params, 0,
					mtl_test_hash_msg,
					mtl_test_hash_leaf,
					mtl_test_hash_node, NULL) == MTL_OK);

	// Verify inserting records
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %d\n", index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer)) == index);
	}

	assert(mtl_ctx->nodes.leaf_count == 16);
	assert(mtl_ctx->nodes.hash_size == 32);
	assert(mtl_ctx->nodes.tree_pages[0] != NULL);
	assert(mtl_ctx->nodes.tree_pages[1] == NULL);

	// Verify NULL parameters
	assert(mtl_hash_and_append
	       (NULL, (unsigned char *)message_buffer,
		strlen(message_buffer)) == 0xffffffff);
	assert(mtl_hash_and_append(mtl_ctx, NULL, strlen(message_buffer)) ==
	       0xffffffff);
	assert(mtl_hash_and_append(mtl_ctx, (unsigned char *)message_buffer, 0)
	       == 0xffffffff);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Verify message hashing and appending w/random.
 */
uint8_t mtltest_mtl_hash_and_append_random(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	uint16_t index;
	static const SPX_PARAMS params;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;

	memset(&pk_seed, 0, sizeof(SEED));
	pk_seed.length = 32;
	memset(pk_seed.seed, 0x55, 32);

	assert(mtl_initns(&mtl_ctx, &pk_seed, &sid, NULL) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, (void*)&params, 1,
					mtl_test_hash_msg,
					mtl_test_hash_leaf,
					mtl_test_hash_node, NULL) == MTL_OK);

	// Verify inserting records
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %d\n", index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer)) == index);
	}

	assert(mtl_ctx->nodes.leaf_count == 16);
	assert(mtl_ctx->nodes.hash_size == 32);
	assert(mtl_ctx->nodes.tree_pages[0] != NULL);
	assert(mtl_ctx->nodes.tree_pages[1] == NULL);

	// Verify NULL parameters
	assert(mtl_hash_and_append
	       (NULL, (unsigned char *)message_buffer,
		strlen(message_buffer)) == 0xffffffff);
	assert(mtl_hash_and_append(mtl_ctx, NULL, strlen(message_buffer)) ==
	       0xffffffff);
	assert(mtl_hash_and_append(mtl_ctx, (unsigned char *)message_buffer, 0)
	       == 0xffffffff);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Verify fetching the randomizer and authpath
 */
uint8_t mtltest_mtl_randomizer_and_authpath(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	uint16_t index;
	static const SPX_PARAMS params;
	RANDOMIZER *mtl_rand;
	AUTHPATH *auth;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;

	memset(&pk_seed, 0x22, sizeof(SEED));
	pk_seed.length = 32;
	memset(pk_seed.seed, 0x55, 32);

	assert(mtl_initns(&mtl_ctx, &pk_seed, &sid, NULL) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, (void*)&params, 0,
					mtl_test_hash_msg,
					mtl_test_hash_leaf,
					mtl_test_hash_node, NULL) == MTL_OK);

	// Insert records for verification later
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %d\n", index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer)) == index);
	}

	// Verify that authpaths and randomizers are avaialble
	for (index = 0; index < 16; index++) {
		assert(mtl_randomizer_and_authpath
		       (mtl_ctx, index, &mtl_rand, &auth) == 0);

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
	assert(mtl_randomizer_and_authpath(NULL, index, &mtl_rand, &auth) != 0);
	assert(mtl_randomizer_and_authpath(mtl_ctx, index, NULL, &auth) != 0);
	assert(mtl_randomizer_and_authpath(mtl_ctx, index, &mtl_rand, NULL) !=
	       0);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Verify fetching the randomizer and authpath w/random
 */
uint8_t mtltest_mtl_randomizer_and_authpath_random(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	uint16_t index;
	static const SPX_PARAMS params;
	RANDOMIZER *mtl_rand;
	AUTHPATH *auth;

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;

	memset(&pk_seed, 0x22, sizeof(SEED));
	pk_seed.length = 32;
	memset(pk_seed.seed, 0x55, 32);

	assert(mtl_initns(&mtl_ctx, &pk_seed, &sid, NULL) == MTL_OK);
	assert(mtl_set_scheme_functions(mtl_ctx, (void*)&params, 1,
					mtl_test_hash_msg,
					mtl_test_hash_leaf,
					mtl_test_hash_node, NULL) == MTL_OK);

	// Insert records for verification later
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %d\n", index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer)) == index);
	}

	// Verify that authpaths and randomizers are avaialble
	for (index = 0; index < 16; index++) {
		assert(mtl_randomizer_and_authpath
		       (mtl_ctx, index, &mtl_rand, &auth) == 0);

		assert(mtl_rand->length == 32);
		assert(memcmp(mtl_rand->value, pk_seed.seed, pk_seed.length) !=
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
	assert(mtl_randomizer_and_authpath(NULL, index, &mtl_rand, &auth) != 0);
	assert(mtl_randomizer_and_authpath(mtl_ctx, index, NULL, &auth) != 0);
	assert(mtl_randomizer_and_authpath(mtl_ctx, index, &mtl_rand, NULL) !=
	       0);

	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Verify message hashing and verification
 */
uint8_t mtltest_mtl_hash_and_verify(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	uint16_t index;
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
					mtl_test_hash_node, NULL) == MTL_OK);

	// Insert records for verification later
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %d\n", index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer)) == index);
	}

	// Get ladder and rung
	ladder = mtl_ladder(mtl_ctx);

	// Verify that authpaths and randomizers are avaialble
	for (index = 0; index < 16; index++) {
		assert(mtl_randomizer_and_authpath
		       (mtl_ctx, index, &mtl_rand, &auth) == 0);

		sprintf(message_buffer, "Verification Msg %d\n", index);
		rung = mtl_rung(auth, ladder);
		assert(mtl_hash_and_verify
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer), mtl_rand, auth, rung) == 0);

		assert(mtl_authpath_free(auth) == MTL_OK);
		assert(mtl_randomizer_free(mtl_rand) == MTL_OK);
	}

	// Verify NULL parameters
	assert(mtl_hash_and_verify(NULL, (unsigned char *)message_buffer,
				   strlen(message_buffer), mtl_rand,
				   auth, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, NULL,
				   strlen(message_buffer), mtl_rand,
				   auth, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   0, mtl_rand, auth, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), NULL,
				   auth, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), mtl_rand,
				   NULL, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), mtl_rand,
				   auth, NULL) != 0);

	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;
}

/**
 * Verify message hashing and verification w/randomization
 */
uint8_t mtltest_mtl_hash_and_verify_random(void)
{
	SEED pk_seed;
	SERIESID sid;
	MTL_CTX *mtl_ctx = NULL;
	char message_buffer[32];
	uint16_t index;
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
	assert(mtl_set_scheme_functions(mtl_ctx, (void*)&params, 1,
					mtl_test_hash_msg,
					mtl_test_hash_leaf,
					mtl_test_hash_node, NULL) == MTL_OK);

	// Insert records for verification later
	for (index = 0; index < 16; index++) {
		sprintf(message_buffer, "Verification Msg %d\n", index);
		assert(mtl_hash_and_append
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer)) == index);
	}

	// Get ladder and rung
	ladder = mtl_ladder(mtl_ctx);

	// Verify that authpaths and randomizers are avaialble
	for (index = 0; index < 16; index++) {
		assert(mtl_randomizer_and_authpath
		       (mtl_ctx, index, &mtl_rand, &auth) == 0);

		sprintf(message_buffer, "Verification Msg %d\n", index);
		rung = mtl_rung(auth, ladder);
		assert(mtl_hash_and_verify
		       (mtl_ctx, (unsigned char *)message_buffer,
			strlen(message_buffer), mtl_rand, auth, rung) == 0);

		assert(mtl_authpath_free(auth) == MTL_OK);
		assert(mtl_randomizer_free(mtl_rand) == MTL_OK);
	}

	// Verify NULL parameters
	assert(mtl_hash_and_verify(NULL, (unsigned char *)message_buffer,
				   strlen(message_buffer), mtl_rand,
				   auth, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, NULL,
				   strlen(message_buffer), mtl_rand,
				   auth, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   0, mtl_rand, auth, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), NULL,
				   auth, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), mtl_rand,
				   NULL, rung) != 0);
	assert(mtl_hash_and_verify(mtl_ctx, (unsigned char *)message_buffer,
				   strlen(message_buffer), mtl_rand,
				   auth, NULL) != 0);

	assert(mtl_ladder_free(ladder) == MTL_OK);
	assert(mtl_free(mtl_ctx) == MTL_OK);

	return 0;

}
