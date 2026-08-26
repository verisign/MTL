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
#include "mtl.h"
#include "mtltest_test_vectors.h"

// Prototypes for testing functions
uint8_t mtltest_auth_path_from_buffer(void);
uint8_t mtltest_auth_path_to_buffer(void);
uint8_t mtltest_ladder_from_buffer(void);
uint8_t mtltest_ladder_to_buffer(void);

uint8_t mtltest_buffer(void)
{
	NEW_TEST("MTL Buffer Tests");

	RUN_TEST(mtltest_auth_path_from_buffer, "Verify auth_path from buffer");
	RUN_TEST(mtltest_auth_path_to_buffer, "Verify auth_path to buffer");
	RUN_TEST(mtltest_ladder_from_buffer, "Verify ladder from buffer");
	RUN_TEST(mtltest_ladder_to_buffer, "Verify ladder to buffer");

	return 0;
}

/**
 * Test the mtl auth path struct from byte buffer
 */
uint8_t mtltest_auth_path_from_buffer(void)
{
	AUTHPATH *auth = NULL;
	RANDOMIZER *mtl_rand = NULL;

	uint16_t hash_len = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	uint16_t flags = 0x0000;
	uint8_t sid_data[] = MTL_TEST_VECTOR_SID;
	const uint8_t randomizer[] = MTL_TEST_VECTOR_HASH_RANDOMIZER;
	MTL_INDEX leaf_index = 13;
	MTL_INDEX target_left = 0x00;
	MTL_INDEX target_right = 0x1f;
	uint16_t sibling_count = 5;
	uint8_t buffer[] = MTL_TEST_VECTOR_CONDENSED_SIG;
	uint16_t buffer_len = MTL_TEST_VECTOR_CONDENSED_SIG_LEN;

	// Randomizer
	assert(mtl_auth_path_from_buffer(buffer, buffer_len, hash_len, &mtl_rand, &auth)
	       == buffer_len);
	assert(auth->flags == flags);
	assert(auth->sid.length == 2*hash_len);
	assert(memcmp(auth->sid.id, sid_data, auth->sid.length) == 0);
	assert(auth->leaf_index == leaf_index);
	assert(auth->rung_left == target_left);
	assert(auth->rung_right == target_right);
	assert(auth->sibling_hash_count == sibling_count);
	size_t sib_hash_size = (size_t)sibling_count*(size_t)hash_len;
	assert(memcmp(auth->sibling_hash, 
		buffer+buffer_len-sib_hash_size, sib_hash_size) == 0);

	assert(memcmp(mtl_rand->value, randomizer, hash_len) == 0);
	assert(mtl_rand->length == hash_len);
	assert(mtl_authpath_free(auth) == MTL_OK);
	free(mtl_rand->value);
	free(mtl_rand);

	// NULL parameters
	assert(mtl_auth_path_from_buffer(NULL, 0, hash_len, &mtl_rand, &auth) ==
	       0);
	assert(mtl_auth_path_from_buffer(buffer, buffer_len, 0, &mtl_rand, &auth) == 0);
	assert(mtl_auth_path_from_buffer(buffer, buffer_len, hash_len, NULL, &auth) ==
	       0);
	assert(mtl_auth_path_from_buffer(buffer, buffer_len, hash_len, &mtl_rand, NULL)
	       == 0);

	return 0;
}

/**
 * Test the mtl auth path struct to byte buffer
 */
uint8_t mtltest_auth_path_to_buffer(void)
{
	AUTHPATH auth;
	RANDOMIZER mtl_rand;
	
	uint16_t hash_len = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	uint16_t flags = 0x0000;
	uint8_t sid_data[] = MTL_TEST_VECTOR_SID;
	const uint8_t randomizer[] = MTL_TEST_VECTOR_HASH_RANDOMIZER;
	MTL_INDEX leaf_index = 13;
	MTL_INDEX target_left = 0x00;
	MTL_INDEX target_right = 0x1f;
	uint16_t sibling_count = 5;
	uint16_t buffer_len = MTL_TEST_VECTOR_CONDENSED_SIG_LEN;
	uint8_t test_buffer[] = MTL_TEST_VECTOR_CONDENSED_SIG;
	uint8_t * buffer = NULL;

	auth.flags = flags;
	auth.sid.length = 2*hash_len;
	memcpy(auth.sid.id, sid_data, auth.sid.length);
	auth.leaf_index = leaf_index;
	auth.rung_left = target_left;
	auth.rung_right = target_right;
	auth.sibling_hash_count = 5;
	auth.sibling_hash = test_buffer + buffer_len-(sibling_count*hash_len);

	// Randomizer
	mtl_rand.value = (uint8_t *) & randomizer[0];
	mtl_rand.length = hash_len;
	assert(mtl_auth_path_to_buffer(&mtl_rand, &auth, hash_len, &buffer) ==
	       buffer_len);
	assert(memcmp(buffer, &test_buffer[0], buffer_len) == 0);
	free(buffer);

	// NULL parameters
	assert(mtl_auth_path_to_buffer(NULL, &auth, hash_len, &buffer) == 0);
	assert(mtl_auth_path_to_buffer(&mtl_rand, NULL, 0, &buffer) == 0);
	assert(mtl_auth_path_to_buffer(&mtl_rand, &auth, hash_len, NULL) == 0);
	assert(mtl_auth_path_to_buffer(&mtl_rand, &auth, hash_len, NULL) == 0);

	// NULL hash data    
	auth.sibling_hash = NULL;
	assert(mtl_auth_path_to_buffer(&mtl_rand, &auth, hash_len, &buffer) ==
	       0);

	return 0;
}

/**
 * Test the mtl ladder struct from byte buffer
 */
uint8_t mtltest_ladder_from_buffer(void)
{
	uint16_t hash_len = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	uint16_t flags = 0x00;
	uint8_t sid_data[] = MTL_TEST_VECTOR_SID;
	LADDER *ladder;
	uint16_t rung_count = 6;
	size_t ladder_buffer_len = MTL_TEST_VECTOR_UNSIGNED_LADDER_LEN;
	uint8_t ladder_buffer[] = MTL_TEST_VECTOR_UNSIGNED_LADDER;

	uint8_t * first_rung = ladder_buffer + sizeof(flags) + 2*hash_len + sizeof(ladder->rung_count) + 2*sizeof(MTL_INDEX);
	uint8_t * second_rung = first_rung + 2*sizeof(MTL_INDEX) + hash_len;

	assert(mtl_ladder_from_buffer(ladder_buffer, ladder_buffer_len, hash_len, &ladder) ==
	       ladder_buffer_len);
	assert(ladder->flags == flags);
	assert(ladder->sid.length == 2*hash_len);
	assert(memcmp(ladder->sid.id, sid_data, ladder->sid.length) == 0);
	assert(ladder->rung_count == rung_count);
	// Verify Rungs
	RUNG *rungs = ladder->rungs;
	assert(rungs[0].left_index == 0);
	assert(rungs[0].right_index == 31);
	assert(rungs[0].hash_length == hash_len);
	assert(memcmp(rungs[0].hash, first_rung, hash_len) == 0);
	assert(rungs[1].left_index == 32);
	assert(rungs[1].right_index == 47);
	assert(rungs[1].hash_length == hash_len);
	assert(memcmp(rungs[1].hash, second_rung, hash_len) == 0);
	assert(mtl_ladder_free(ladder) == MTL_OK);


	// NULL parameters
	assert(mtl_ladder_from_buffer(NULL, 0, hash_len, &ladder) == 0);
	assert(mtl_ladder_from_buffer(ladder_buffer, ladder_buffer_len, 0, &ladder) == 0);
	assert(mtl_ladder_from_buffer(ladder_buffer, ladder_buffer_len, hash_len, NULL) == 0);

	return 0;
}

/**
 * Test the mtl ladder struct to byte buffer
 */
uint8_t mtltest_ladder_to_buffer(void)
{
	uint16_t hash_len = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	uint16_t flags = 0x0000;
	uint8_t sid_data[] = MTL_TEST_VECTOR_SID;
	LADDER ladder;
	uint16_t rung_count = 6;
	RUNG rungs[rung_count];
	uint32_t expected_buffer_length = MTL_TEST_VECTOR_UNSIGNED_LADDER_LEN;
	uint8_t expected_buffer[] = MTL_TEST_VECTOR_UNSIGNED_LADDER;
	uint8_t i;
	size_t buffer_offset = 0;

	uint8_t *buffer = NULL;
	assert((buffer = malloc(expected_buffer_length)) != NULL);

	ladder.flags = flags;
	ladder.sid.length = 2*hash_len;
	memcpy(ladder.sid.id, sid_data, ladder.sid.length);
	ladder.rung_count = rung_count;
	ladder.rungs = rungs;

	for (i = 0; i < rung_count; i++) {
		buffer_offset = sizeof(ladder.flags) +
			ladder.sid.length +
			sizeof(ladder.rung_count) +
			i * (2 * sizeof(MTL_INDEX) + hash_len);
		rungs[i].left_index = expected_buffer[buffer_offset + sizeof(MTL_INDEX) - 1];
		rungs[i].right_index = expected_buffer[buffer_offset + 2 * sizeof(MTL_INDEX) - 1];
		rungs[i].hash_length = hash_len;
		memcpy(rungs[i].hash, expected_buffer + buffer_offset + 2*sizeof(MTL_INDEX), hash_len);
	}
	free(buffer);
	assert(mtl_ladder_to_buffer(&ladder, hash_len, &buffer) ==
	       expected_buffer_length);
	assert(memcmp(buffer, expected_buffer, expected_buffer_length) == 0);
	free(buffer);

	// NULL parameters
	assert(mtl_ladder_to_buffer(NULL, hash_len, &buffer) == 0);
	assert(mtl_ladder_to_buffer(&ladder, 0, &buffer) == 0);
	assert(mtl_ladder_to_buffer(&ladder, hash_len, NULL) == 0);

	return 0;
}
