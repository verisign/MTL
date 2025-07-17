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
#include <config.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "mtltest.h"
#include "mtl.h"

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
	uint16_t hash_len = 16;
	uint8_t sid_data[] = { 0x12, 0x9b, 0x46, 0x9b, 0x84, 0x22, 0xaf, 0x05 };
	const uint8_t randomizer[] =
	    { 0x49, 0xf6, 0x4a, 0xce, 0xea, 0xa3, 0xee, 0x0d,
		0x4c, 0x61, 0xe2, 0x79, 0x88, 0x08, 0x6b, 0x2d
	};
	uint8_t hash_data[] = { 0x6a, 0xc4, 0x8a, 0x61, 0x62, 0xf7, 0xd7, 0xeb,
		0xcc, 0x8d, 0x0c, 0x29, 0x6d, 0x66, 0x13, 0x29,
		0x47, 0x3a, 0x4e, 0xe2, 0x56, 0x49, 0x17, 0x19,
		0xba, 0x31, 0x8a, 0x6e, 0x87, 0xc1, 0xf1, 0x1a
	};
	char result[] = { 0x49, 0xf6, 0x4a, 0xce, 0xea, 0xa3, 0xee, 0x0d,
		0x4c, 0x61, 0xe2, 0x79, 0x88, 0x08, 0x6b, 0x2d,
		0x00, 0x55, 0x12, 0x9b, 0x46, 0x9b, 0x84, 0x22,
		0xaf, 0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02,
		0x6a, 0xc4, 0x8a, 0x61, 0x62, 0xf7, 0xd7, 0xeb,
		0xcc, 0x8d, 0x0c, 0x29, 0x6d, 0x66, 0x13, 0x29,
		0x47, 0x3a, 0x4e, 0xe2, 0x56, 0x49, 0x17, 0x19,
		0xba, 0x31, 0x8a, 0x6e, 0x87, 0xc1, 0xf1, 0x1a
	};
	uint16_t result_len = 72;

	// Randomizer
	assert(mtl_auth_path_from_buffer(result, result_len, hash_len, 8, &mtl_rand, &auth)
	       == result_len);
	assert(auth->flags == 0x55);
	assert(auth->sid.length == 8);
	assert(memcmp(auth->sid.id, sid_data, 8) == 0);
	assert(auth->leaf_index == 2);
	assert(auth->rung_left == 0);
	assert(auth->rung_right == 3);
	assert(auth->sibling_hash_count == 2);
	assert(memcmp(auth->sibling_hash, hash_data, 32) == 0);

	assert(memcmp(mtl_rand->value, randomizer, 16) == 0);
	assert(mtl_rand->length == 16);
	assert(mtl_authpath_free(auth) == MTL_OK);
	free(mtl_rand->value);
	free(mtl_rand);

	// NULL parameters
	assert(mtl_auth_path_from_buffer(NULL, 0, hash_len, 8, &mtl_rand, &auth) ==
	       0);
	assert(mtl_auth_path_from_buffer(result, result_len, 0, 8, &mtl_rand, &auth) == 0);
	assert(mtl_auth_path_from_buffer(result, result_len, hash_len, 0, &mtl_rand, &auth)
	       == 0);
	assert(mtl_auth_path_from_buffer(result, result_len, hash_len, 8, NULL, &auth) ==
	       0);
	assert(mtl_auth_path_from_buffer(result, result_len, hash_len, 8, &mtl_rand, NULL)
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
	uint16_t hash_len = 16;
	uint8_t sid_data[] = { 0x12, 0x9b, 0x46, 0x9b, 0x84, 0x22, 0xaf, 0x05 };
	const uint8_t randomizer[] =
	    { 0x49, 0xf6, 0x4a, 0xce, 0xea, 0xa3, 0xee, 0x0d,
		0x4c, 0x61, 0xe2, 0x79, 0x88, 0x08, 0x6b, 0x2d
	};
	uint8_t hash_data[] = { 0x6a, 0xc4, 0x8a, 0x61, 0x62, 0xf7, 0xd7, 0xeb,
		0xcc, 0x8d, 0x0c, 0x29, 0x6d, 0x66, 0x13, 0x29,
		0x47, 0x3a, 0x4e, 0xe2, 0x56, 0x49, 0x17, 0x19,
		0xba, 0x31, 0x8a, 0x6e, 0x87, 0xc1, 0xf1, 0x1a
	};
	uint8_t *buffer;
	uint8_t result[] = { 0x49, 0xf6, 0x4a, 0xce, 0xea, 0xa3, 0xee, 0x0d,
		0x4c, 0x61, 0xe2, 0x79, 0x88, 0x08, 0x6b, 0x2d,
		0x00, 0x55, 0x12, 0x9b, 0x46, 0x9b, 0x84, 0x22,
		0xaf, 0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02,
		0x6a, 0xc4, 0x8a, 0x61, 0x62, 0xf7, 0xd7, 0xeb,
		0xcc, 0x8d, 0x0c, 0x29, 0x6d, 0x66, 0x13, 0x29,
		0x47, 0x3a, 0x4e, 0xe2, 0x56, 0x49, 0x17, 0x19,
		0xba, 0x31, 0x8a, 0x6e, 0x87, 0xc1, 0xf1, 0x1a
	};
	uint16_t result_len = 72;

	auth.flags = 0x55;
	auth.sid.length = 8;
	memcpy(auth.sid.id, sid_data, 8);
	auth.leaf_index = 2;
	auth.rung_left = 0;
	auth.rung_right = 3;
	auth.sibling_hash_count = 2;
	auth.sibling_hash = &hash_data[0];

	// Randomizer
	mtl_rand.value = (uint8_t *) & randomizer[0];
	mtl_rand.length = hash_len;
	assert(mtl_auth_path_to_buffer(&mtl_rand, &auth, hash_len, &buffer) ==
	       result_len);
	assert(memcmp(buffer, result, result_len) == 0);
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
	uint16_t hash_len = 16;
	uint8_t sid_data[] = { 0xe4, 0xd8, 0xb7, 0xee, 0x9c, 0xc8, 0x05, 0x72 };
	char ladder_buffer[] = { 0x00, 0x55, 0xe4, 0xd8, 0xb7, 0xee, 0x9c, 0xc8,
		0x05, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03, 0x74, 0xac, 0x79, 0x8c,
		0xc7, 0x75, 0x5b, 0x33, 0x19, 0x99, 0xf1, 0x4b,
		0xa8, 0x0c, 0x94, 0x95
	};
	uint32_t ladder_buffer_len = 36;
	LADDER *ladder;
	uint8_t rung_data[] = { 0x74, 0xac, 0x79, 0x8c, 0xc7, 0x75, 0x5b, 0x33,
		0x19, 0x99, 0xf1, 0x4b, 0xa8, 0x0c, 0x94, 0x95
	};

	assert(mtl_ladder_from_buffer(ladder_buffer, ladder_buffer_len, hash_len, 8, &ladder) ==
	       ladder_buffer_len);
	assert(ladder->flags == 0x55);
	assert(ladder->sid.length == 8);
	assert(memcmp(ladder->sid.id, sid_data, 8) == 0);
	assert(ladder->rung_count == 1);
	// Verify Rungs
	RUNG *rung = ladder->rungs;
	assert(rung->left_index == 0);
	assert(rung->right_index == 3);
	assert(rung->hash_length == 16);
	assert(memcmp(rung->hash, rung_data, hash_len) == 0);
	assert(mtl_ladder_free(ladder) == MTL_OK);


	// NULL parameters
	assert(mtl_ladder_from_buffer(NULL, 0, hash_len, 8, &ladder) == 0);
	assert(mtl_ladder_from_buffer(ladder_buffer, ladder_buffer_len, 0, 8, &ladder) == 0);
	assert(mtl_ladder_from_buffer(ladder_buffer, ladder_buffer_len, hash_len, 0, &ladder) ==
	       0);
	assert(mtl_ladder_from_buffer(ladder_buffer, ladder_buffer_len, hash_len, 8, NULL) == 0);

	return 0;
}

/**
 * Test the mtl ladder struct to byte buffer
 */
uint8_t mtltest_ladder_to_buffer(void)
{
	uint16_t hash_len = 16;
	uint8_t sid_data[] = { 0xe4, 0xd8, 0xb7, 0xee, 0x9c, 0xc8, 0x05, 0x72 };
	char ladder_buffer[] = { 0x00, 0x55, 0xe4, 0xd8, 0xb7, 0xee, 0x9c, 0xc8,
		0x05, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03, 0x74, 0xac, 0x79, 0x8c,
		0xc7, 0x75, 0x5b, 0x33, 0x19, 0x99, 0xf1, 0x4b,
		0xa8, 0x0c, 0x94, 0x95
	};
	uint32_t ladder_buffer_len = 36;
	LADDER ladder;
	RUNG rung;
	uint8_t *buffer;
	uint8_t rung_data[] = { 0x74, 0xac, 0x79, 0x8c, 0xc7, 0x75, 0x5b, 0x33,
		0x19, 0x99, 0xf1, 0x4b, 0xa8, 0x0c, 0x94, 0x95
	};

	ladder.flags = 0x55;
	ladder.sid.length = 8;
	memcpy(ladder.sid.id, sid_data, 8);
	ladder.rung_count = 1;
	ladder.rungs = &rung;

	rung.left_index = 0;
	rung.right_index = 3;
	rung.hash_length = 16;
	memcpy(&rung.hash, &rung_data, hash_len);

	assert(mtl_ladder_to_buffer(&ladder, hash_len, &buffer) ==
	       ladder_buffer_len);
	assert(memcmp(buffer, ladder_buffer, ladder_buffer_len) == 0);
	free(buffer);

	// NULL parameters
	assert(mtl_ladder_to_buffer(NULL, hash_len, &buffer) == 0);
	assert(mtl_ladder_to_buffer(&ladder, 0, &buffer) == 0);
	assert(mtl_ladder_to_buffer(&ladder, hash_len, NULL) == 0);

	return 0;
}
