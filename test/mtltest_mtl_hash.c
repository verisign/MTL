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
#include "mtl_hash.h"
#include <assert.h>
#include <string.h>

#include "mtltest.h"
#include "mtltest_test_vectors.h"

// Prototypes for testing functions
uint8_t mtltest_hash_sha2(void);
uint8_t mtltest_hash_shake(void);
uint8_t mtltest_node_set_hash_leaf(void);
uint8_t mtltest_node_set_hash_leaf_sha2(void);
uint8_t mtltest_node_set_hash_leaf_shake(void);
uint8_t mtltest_node_set_hash_int(void);
uint8_t mtltest_node_set_hash_int_sha2(void);
uint8_t mtltest_node_set_hash_int_shake(void);

uint8_t mtltest_mtl_hash(void)
{
	NEW_TEST("MTL Hash Internal Function Tests");

	RUN_TEST(mtltest_hash_sha2,
		 "Verify the SHA2 implementation for tree hashing");
	RUN_TEST(mtltest_hash_shake,
		 "Verify the SHAKE implementation for tree hashing");
	RUN_TEST(mtltest_node_set_hash_leaf,
		 "Verify the leaf hashing wrapper");
	RUN_TEST(mtltest_node_set_hash_int,
		 "Verify the internal node hashing wrapper");
	
	return 0;
}

/**
 * Verify the mtl_hash_sha2 hashing function
 */
uint8_t mtltest_hash_sha2(void)
{
	uint8_t data[] = "Test Message";
	uint8_t data_len = 12;
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint32_t hash_len = 0;
	uint8_t output_sha256[] = {
		0xd7, 0x79, 0x73, 0xb0, 0x05, 0xca, 0x7f, 0xd9, 
		0x86, 0x13, 0xbb, 0xae, 0x85, 0xf0, 0xed, 0xca, 
		0x68, 0x2b, 0xd0, 0x4f, 0x20, 0x16, 0x73, 0x81, 
		0x41, 0xc0, 0xdc, 0x23, 0xd7, 0x5e, 0xdb, 0x4b
	};
	uint8_t output_sha512[] = {
		0x77, 0x12, 0xfc, 0xcc, 0xea, 0xbf, 0xae, 0x97, 
		0xec, 0x6c, 0x3e, 0x11, 0x2e, 0xa7, 0xe2, 0xb7, 
		0xc0, 0xa8, 0xe9, 0xea, 0xd3, 0x75, 0x75, 0xfa, 
		0x85, 0xe2, 0x10, 0x46, 0x95, 0xb5, 0xb0, 0xd8, 
		0x1b, 0xa7, 0x53, 0x4b, 0xda, 0x78, 0xac, 0x22, 
		0xeb, 0x0a, 0xf8, 0x43, 0x3f, 0xfe, 0x79, 0x37, 
		0x3f, 0x87, 0x34, 0xc6, 0xd8, 0xd9, 0x19, 0x15, 
		0x52, 0x45, 0xd6, 0x09, 0x7f, 0x54, 0xbb, 0xfe 
	};

	// Test a hash of length 32 bytes (256 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 32;
	assert(mtl_hash_sha2(hash, data, data_len, hash_len) == MTL_OK);
	assert(memcmp(hash, output_sha512, hash_len) == 0);

	// Test a hash of length 16 bytes (128 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 16;
	assert(mtl_hash_sha2(hash, data, data_len, hash_len) == MTL_OK);
	assert(memcmp(hash, output_sha256, hash_len) == 0);

	// Test a hash of length 24 bytes (192 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 24;
	assert(mtl_hash_sha2(hash, data, data_len, hash_len) == MTL_OK);
	assert(memcmp(hash, output_sha512, hash_len) == 0);

	// Re-test a hash of length 32 bytes (256 bits) to ensure no residuals
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 32;
	assert(mtl_hash_sha2(hash, data, data_len, hash_len) == MTL_OK);
	assert(memcmp(hash, output_sha512, hash_len) == 0);

	return 0;
}

/**
 * Verify the mtl_hash_shake hashing function
 */
uint8_t mtltest_hash_shake(void)
{
	uint8_t data[] = "Test Message";
	uint8_t data_len = 12;
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint32_t hash_len = 0;
	// Temporarily using SHAKE outputs; update when cSHAKE support implemented
	uint8_t output_shake128[] = {
		0x50, 0xd9, 0xcc, 0xcf, 0x84, 0x1a, 0x65, 0x95, 
		0xee, 0xc0, 0xb2, 0x46, 0x06, 0xd9, 0x7c, 0x02, 

	};
	uint8_t output_shake256[] = {
		0x5b, 0xf6, 0x7a, 0xa3, 0x16, 0xf0, 0xe4, 0x62, 
		0x6f, 0xe1, 0x3c, 0xda, 0x7f, 0xce, 0x45, 0xbb, 
		0xbc, 0x37, 0xda, 0x61, 0x6f, 0x34, 0x26, 0x48, 
		0xe4, 0x65, 0xdd, 0x77, 0x89, 0xb8, 0xd8, 0x58, 
	};

	// Test a hash of length 32 bytes (256 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 32;
	assert(mtl_hash_shake(hash, data, data_len, hash_len) == MTL_OK);
	assert(memcmp(hash, output_shake256, hash_len) == 0);

	// Test a hash of length 16 bytes (128 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 16;
	assert(mtl_hash_shake(hash, data, data_len, hash_len) == MTL_OK);
	assert(memcmp(hash, output_shake128, hash_len) == 0);

	// Test a hash of length 24 bytes (192 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 24;
	assert(mtl_hash_shake(hash, data, data_len, hash_len) == MTL_OK);
	assert(memcmp(hash, output_shake256, hash_len) == 0);

	// Re-test a hash of length 32 bytes (256 bits) to ensure no residuals
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 32;
	assert(mtl_hash_shake(hash, data, data_len, hash_len) == MTL_OK);
	assert(memcmp(hash, output_shake256, hash_len) == 0);

	return 0;
}

/**
 * Verify a single instance of node set leaf hashing function
 */
uint8_t mtltest_node_set_hash_leaf_single(
	SERIESID sid, uint32_t node_index,
	uint8_t * msg_buffer, uint32_t msg_len,
	uint8_t * ctx, uint32_t ctx_len,
	uint8_t * randomizer,
	H_LEAF * h_leaf,
	uint8_t * target_hash, size_t hash_len)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	memset(hash, 0, EVP_MAX_MD_SIZE);

	sid.length=2*hash_len;
	assert((*h_leaf)(&sid, node_index, 
		msg_buffer, msg_len, ctx, ctx_len,
		randomizer, hash_len, hash, hash_len) == MTL_OK);
	assert(memcmp(hash, target_hash, hash_len) == 0);

	return 0;
}

/**
 * Verify the node set leaf hashing sha2 wrapper
 */
uint8_t mtltest_node_set_hash_leaf(void)
{
	SERIESID sid;
	uint8_t sid_id[] = MTL_TEST_VECTOR_SID;
	memcpy(sid.id, sid_id, 64);
	uint32_t node_index = 0xfedcba98;

	uint8_t randomizer[] = MTL_TEST_VECTOR_HASH_RANDOMIZER;
	uint8_t msg_buffer[] = "Test Message";
	uint32_t msg_len = 12;
	uint8_t ctx[] = "Context String";
	uint32_t ctx_len = 14;

	uint8_t sha2_16_output[] = MTL_TEST_VECTOR_HASH_SHA2_16_LEAF;
	uint8_t sha2_24_output[] = MTL_TEST_VECTOR_HASH_SHA2_24_LEAF;
	uint8_t sha2_32_output[] = MTL_TEST_VECTOR_HASH_SHA2_32_LEAF;
	uint8_t shake_16_output[] = MTL_TEST_VECTOR_HASH_SHAKE_16_LEAF;
	uint8_t shake_24_output[] = MTL_TEST_VECTOR_HASH_SHAKE_24_LEAF;
	uint8_t shake_32_output[] = MTL_TEST_VECTOR_HASH_SHAKE_32_LEAF;

	// SHA2 tests
	mtltest_node_set_hash_leaf_single(sid, node_index, 
										msg_buffer, msg_len, 
										ctx, ctx_len, randomizer, 
										mtl_node_set_hash_leaf_sha2, sha2_16_output, 16);
	mtltest_node_set_hash_leaf_single(sid, node_index, 
										msg_buffer, msg_len, 
										ctx, ctx_len, randomizer, 
										mtl_node_set_hash_leaf_sha2, sha2_24_output, 24);
	mtltest_node_set_hash_leaf_single(sid, node_index, 
										msg_buffer, msg_len, 
										ctx, ctx_len, randomizer, 
										mtl_node_set_hash_leaf_sha2, sha2_32_output, 32);

	// SHAKE tests
	mtltest_node_set_hash_leaf_single(sid, node_index, 
										msg_buffer, msg_len, 
										ctx, ctx_len, randomizer, 
										mtl_node_set_hash_leaf_shake, shake_16_output, 16);
	mtltest_node_set_hash_leaf_single(sid, node_index, 
										msg_buffer, msg_len, 
										ctx, ctx_len, randomizer, 
										mtl_node_set_hash_leaf_shake, shake_24_output, 24);
	mtltest_node_set_hash_leaf_single(sid, node_index, 
										msg_buffer, msg_len, 
										ctx, ctx_len, randomizer, 
										mtl_node_set_hash_leaf_shake, shake_32_output, 32);
	
	return 0;
}

/**
 * Verify a single instance of node set internal hashing function
 */
uint8_t mtltest_node_set_hash_int_single(
	SERIESID sid, MTL_INDEX adrs_left, MTL_INDEX adrs_right,
	uint8_t * child_left, uint8_t * child_right,
	H_INT * h_int,
	uint8_t * target_hash, size_t hash_len)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	memset(hash, 0, EVP_MAX_MD_SIZE);

	sid.length=2*hash_len;
	assert((*h_int)(&sid, adrs_left, adrs_right, 
		child_left, child_right, 
		hash, hash_len) == MTL_OK);
	assert(memcmp(hash, target_hash, hash_len) == 0);

	return 0;
}

/**
 * Verify the node set internal hashing function
 */
uint8_t mtltest_node_set_hash_int(void)
{

	SERIESID sid;
	uint8_t sid_id[] = MTL_TEST_VECTOR_SID;
	memcpy(sid.id, sid_id, 64);
	MTL_INDEX adrs_left =  0xabcd4000;
	MTL_INDEX adrs_right = 0xabcd8000;
	uint8_t child_left[] = MTL_TEST_VECTOR_HASH_CHILD_LEFT;
	uint8_t child_right[] = MTL_TEST_VECTOR_HASH_CHILD_RIGHT;

	uint8_t sha2_16_output[] = MTL_TEST_VECTOR_HASH_SHA2_16_INT;
	uint8_t sha2_24_output[] = MTL_TEST_VECTOR_HASH_SHA2_24_INT;
	uint8_t sha2_32_output[] = MTL_TEST_VECTOR_HASH_SHA2_32_INT;
	uint8_t shake_16_output[] = MTL_TEST_VECTOR_HASH_SHAKE_16_INT;
	uint8_t shake_24_output[] = MTL_TEST_VECTOR_HASH_SHAKE_24_INT;
	uint8_t shake_32_output[] = MTL_TEST_VECTOR_HASH_SHAKE_32_INT;

	// SHA2 tests
	mtltest_node_set_hash_int_single(sid, adrs_left, adrs_right,
										child_left, child_right,
										mtl_node_set_hash_int_sha2,
										sha2_16_output, 16);
	mtltest_node_set_hash_int_single(sid, adrs_left, adrs_right,
										child_left, child_right,
										mtl_node_set_hash_int_sha2,
										sha2_24_output, 24);
	mtltest_node_set_hash_int_single(sid, adrs_left, adrs_right,
										child_left, child_right,
										mtl_node_set_hash_int_sha2,
										sha2_32_output, 32);
	
	// SHAKE tests
	mtltest_node_set_hash_int_single(sid, adrs_left, adrs_right,
										child_left, child_right,
										mtl_node_set_hash_int_shake,
										shake_16_output, 16);
	mtltest_node_set_hash_int_single(sid, adrs_left, adrs_right,
										child_left, child_right,
										mtl_node_set_hash_int_shake,
										shake_24_output, 24);
	mtltest_node_set_hash_int_single(sid, adrs_left, adrs_right,
										child_left, child_right,
										mtl_node_set_hash_int_shake,
										shake_32_output, 32);


	return 0;
}