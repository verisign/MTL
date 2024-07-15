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
#include "mtl_spx.h"
#include "spx_funcs.h"
#include <assert.h>
#include <string.h>

#include "mtltest.h"
#include "mtltest_spx.h"

// Prototypes for testing functionsß
uint8_t test_SPX_mtlns_adrs_compressed(void);
uint8_t test_SPX_mtlns_adrs_full(void);
uint8_t test_SPX_spx_sha2(void);
uint8_t test_SPX_spx_shake(void);
uint8_t test_SPX_mtl_node_set_hash_message(void);
uint8_t test_SPX_mtl_node_set_hash_message_sha2(void);
uint8_t test_SPX_mtl_node_set_hash_message_shake(void);
uint8_t test_SPX_mtl_node_set_hash_leaf(void);
uint8_t test_SPX_mtl_node_set_hash_leaf_robust(void);
uint8_t test_SPX_mtl_node_set_hash_leaf_sha2(void);
uint8_t test_SPX_mtl_node_set_hash_leaf_shake(void);
uint8_t test_SPX_mtl_node_set_hash_int(void);
uint8_t test_SPX_mtl_node_set_hash_int_robust(void);
uint8_t test_SPX_mtl_node_set_hash_int_sha2(void);
uint8_t test_SPX_mtl_node_set_hash_int_shake(void);
uint8_t test_SPX_spx_mtl_prf_sha2(void);
uint8_t test_SPX_spx_mtl_prf_shake(void);

uint8_t mtltest_spx(void)
{
	NEW_TEST("MTL SPX Internal Function Tests");

	RUN_TEST(test_SPX_mtlns_adrs_compressed,
		 "Test the Compressed Address Functions");
	RUN_TEST(test_SPX_mtlns_adrs_full, "Test the Full Address Functions");
	RUN_TEST(test_SPX_spx_sha2,
		 "Verify the SHA2 implementation for tree hashing");
	RUN_TEST(test_SPX_spx_shake,
		 "Verify the SHAKE implementation for tree hashing");
	RUN_TEST(test_SPX_mtl_node_set_hash_message,
		 "Verify the SPX message hash functions");
	RUN_TEST(test_SPX_mtl_node_set_hash_message_sha2,
		 "Verify the SPX SHA2 message hash wrapper");
	RUN_TEST(test_SPX_mtl_node_set_hash_message_shake,
		 "Verify the SPX SHAKE message hash wrapper");
	RUN_TEST(test_SPX_mtl_node_set_hash_leaf,
		 "Verify the SPX leaf hashing function");
	RUN_TEST(test_SPX_mtl_node_set_hash_leaf_robust,
		 "Verify the SPX leaf hashing function w/robust");
	RUN_TEST(test_SPX_mtl_node_set_hash_leaf_sha2,
		 "Verify the SPX SHA2 leaf hashing wrapper");
	RUN_TEST(test_SPX_mtl_node_set_hash_leaf_shake,
		 "Verify the SPX SHAKE leaf hashing wrapper");
	RUN_TEST(test_SPX_mtl_node_set_hash_int,
		 "Verify the SPX int hashing function");
	RUN_TEST(test_SPX_mtl_node_set_hash_int_robust,
		 "Verify the SPX int hashing function w/robust");
	RUN_TEST(test_SPX_mtl_node_set_hash_int_sha2,
		 "Verify the SPX SHA2 int hashing wrapper");
	RUN_TEST(test_SPX_mtl_node_set_hash_int_shake,
		 "Verify the SPX SHAKE int hashing wrapper");
	RUN_TEST(test_SPX_spx_mtl_prf_sha2,
		 "Verify the SPX SHA2 PRF message function");
	RUN_TEST(test_SPX_spx_mtl_prf_shake,
		 "Verify the SPX SHAKE PRF message function");
	return 0;
}

/**
 * Verify the compressed MTL ADRS function
 */
uint8_t test_SPX_mtlns_adrs_compressed(void)
{
	uint8_t mtl_adrs[32];
	SERIESID sid;

	memset(mtl_adrs, 0, 32);
	sid.length = 64;
	memset(&sid.id, 0x55, 64);
	// Verify a compressed address is created correctly
	assert(mtlns_adrs_compressed
	       ((uint8_t *) & mtl_adrs, SPX_ADRS_MTL_DATA, &sid, 0,
		9) == ADRS_ADDR_SIZE_C);	
	assert(memcmp(mtl_adrs, adrs_compress, 32) == 0);

	// Verify that an invalid ADRS does not match
	assert(memcmp(mtl_adrs, adrs_comporess_invalid, 32) != 0);

	return 0;
}

/**
 * Verify the compressed MTL ADRS function
 */
uint8_t test_SPX_mtlns_adrs_full(void)
{
	uint8_t mtl_adrs[32];
	SERIESID sid;

	memset(mtl_adrs, 0, 32);
	sid.length = 8;
	memset(&sid.id, 0x55, 8);
	// Verify a compressed address is created correctly
	assert(mtlns_adrs_full
	       ((uint8_t *) & mtl_adrs, SPX_ADRS_MTL_DATA, &sid, 0,
		9) == ADRS_ADDR_SIZE);
	assert(memcmp(mtl_adrs, adrs_full, 32) == 0);
	// Verify that an invalid ADRS does not match
	assert(memcmp(mtl_adrs, adrs_full_invalid, 32) != 0);

	return 0;
}

/**
 * Verify the spx_sha2 hashing function
 */
uint8_t test_SPX_spx_sha2(void)
{
	uint8_t data[] = "Test Message";
	uint8_t seed[64] = { 0x55 };
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint32_t hash_len = 0;
	uint8_t response_32[] =
	    { 0x4b, 0x72, 0xe2, 0x10, 0xbd, 0x4c, 0x47, 0xb6,
		0x69, 0x14, 0x82, 0xb4, 0x68, 0x18, 0xea, 0x12,
		0x09, 0x90, 0x79, 0x72, 0xd1, 0xae, 0x8f, 0xd4,
		0xf0, 0x3f, 0x28, 0xad, 0x77, 0xaa, 0xb9, 0x8c
	};
	uint8_t response_16[] =
	    { 0xdf, 0x8a, 0x44, 0x11, 0x01, 0x8e, 0x9c, 0xf7,
		0xe3, 0x7b, 0x59, 0xc8, 0xb5, 0x38, 0xb4, 0x09
	};
	uint8_t response_64[] =
	    { 0x4b, 0x72, 0xe2, 0x10, 0xbd, 0x4c, 0x47, 0xb6,
		0x69, 0x14, 0x82, 0xb4, 0x68, 0x18, 0xea, 0x12,
		0x09, 0x90, 0x79, 0x72, 0xd1, 0xae, 0x8f, 0xd4,
		0xf0, 0x3f, 0x28, 0xad, 0x77, 0xaa, 0xb9, 0x8c,
		0x5f, 0x52, 0xe1, 0x9c, 0x60, 0x7c, 0x6a, 0x3e,
		0xbb, 0x7d, 0x6f, 0x15, 0x73, 0x4d, 0xad, 0x18,
		0x8c, 0x44, 0xfc, 0x5f, 0x7e, 0x1f, 0x1c, 0xb2,
		0x76, 0x10, 0x32, 0x53, 0x71, 0x59, 0xce, 0x3a
	};

	// Test a hash of length 32 bytes (256 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 32;
	assert(spx_sha2
	       (&seed[0], hash_len, (uint8_t *) & adrs_compress[0], 22, data,
		13, &hash[0], hash_len) == 0);	
	assert(memcmp(hash, response_32, 32) == 0);

	// Test a hash of length 16 bytes (128 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 16;
	assert(spx_sha2
	       (&seed[0], hash_len, (uint8_t *) & adrs_compress[0], 22, data,
		13, &hash[0], hash_len) == 0);
	assert(memcmp(hash, response_16, 16) == 0);

	// Test a hash of length 64 bytes (512 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 64;
	assert(spx_sha2
	       (&seed[0], hash_len, (uint8_t *) & adrs_compress[0], 22, data,
		13, &hash[0], hash_len) == 0);
	assert(memcmp(hash, response_64, 64) == 0);

	// Re-test a hash of length 32 bytes (256 bits) to ensure no residuals
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 32;
	assert(spx_sha2
	       (&seed[0], hash_len, (uint8_t *) & adrs_compress[0], 22, data,
		13, &hash[0], hash_len) == 0);
	assert(memcmp(hash, response_32, 32) == 0);

	return 0;
}

/**
 * Verify the spx_shake hashing function
 */
uint8_t test_SPX_spx_shake(void)
{
	uint8_t data[] = "Test Message";
	uint8_t seed[64] = { 0x55 };
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint32_t hash_len = 0;
	uint8_t response_32[] =
	    { 0x8e, 0x08, 0xac, 0xa0, 0x97, 0xd8, 0x0a, 0x3c,
		0x6a, 0x77, 0x01, 0x9c, 0x8c, 0x31, 0xbb, 0x59,
		0x18, 0x02, 0x43, 0x0b, 0x8c, 0x38, 0x13, 0xf2,
		0x2c, 0x45, 0x07, 0x0f, 0x40, 0xba, 0xf6, 0xbe
	};
	uint8_t response_16[] =
	    { 0x49, 0x30, 0xc9, 0xbd, 0xa4, 0xb5, 0xd7, 0x2e,
		0x0c, 0x69, 0x41, 0x0c, 0x5a, 0x84, 0xb1, 0x69
	};

	// Test a hash of length 32 bytes (256 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 32;
	assert(spx_shake
	       (&seed[0], hash_len, (uint8_t *) & adrs_compress[0], 22, data,
		13, &hash[0], hash_len) == 0);	
	assert(memcmp(hash, response_32, 32) == 0);

	// Test a hash of length 16 bytes (128 bits)
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 16;
	assert(spx_shake
	       (&seed[0], hash_len, (uint8_t *) & adrs_compress[0], 22, data,
		13, &hash[0], hash_len) == 0);
	assert(memcmp(hash, response_16, 16) == 0);

	// Re-test a hash of length 32 bytes (256 bits) to ensure no residuals
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 32;
	assert(spx_shake
	       (&seed[0], hash_len, (uint8_t *) & adrs_compress[0], 22, data,
		13, &hash[0], hash_len) == 0);
	assert(memcmp(hash, response_32, 32) == 0);

	// Verify different adrs results in different hash
	memset(hash, 0, EVP_MAX_MD_SIZE);
	hash_len = 32;
	assert(spx_shake
	       (&seed[0], hash_len, (uint8_t *) & adrs_compress_alt[0], 22,
		data, 13, &hash[0], hash_len) == 0);
	assert(memcmp(hash, response_32, 32) != 0);

	return 0;
}

/**
 * Verify the node set message hashing function
 */
uint8_t test_SPX_mtl_node_set_hash_message(void)
{
	uint8_t msg_buffer[] = "test_SPX_mtl_node_set_hash_message";
	uint8_t msg_buffer2[] = "alt1_SPX_mtl_node_set_hash_message";
	uint16_t msg_len = 34;
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_len = 32;
	SERIESID sid;
	char* context_str = "MTL_TEST_STR";
	uint8_t rmtl[EVP_MAX_MD_SIZE];
	uint8_t* rmtl_ptr = &rmtl[0];
	uint32_t rmtl_len=0;
	uint8_t sha2_1[] = { 0x23, 0x96, 0x7b, 0x83, 0xd4, 0x92, 0xb3, 0x8e,
		0x01, 0x34, 0xd7, 0x71, 0x6c, 0x96, 0x1c, 0x21,
		0xe7, 0x2e, 0xf7, 0xcb, 0xf6, 0x37, 0x44, 0xf9,
		0x27, 0x9c, 0x82, 0x96, 0x7c, 0xcb, 0x2e, 0xa0

	};
	uint8_t shake1[] = { 0x87, 0x2e, 0x33, 0xf9, 0xe2, 0xe3, 0x46, 0x62,
		0x94, 0x97, 0x2b, 0xb9, 0x91, 0x71, 0x24, 0x75,
		0xbc, 0xb8, 0xd9, 0x77, 0xee, 0x97, 0x3a, 0x47,
		0xc3, 0x44, 0x82, 0xdb, 0x30, 0x8c, 0xe3, 0x2e
	};
	uint8_t sha2_2[] = { 0xdb, 0xf5, 0xe7, 0xc8, 0xb4, 0x38, 0xd1, 0xd3,
		0xa1, 0xe7, 0xf4, 0xe0, 0x58, 0x3b, 0x01, 0x37
	};
	uint8_t prf[] = { 0x3b, 0x70, 0x6b, 0xde, 0x28, 0xe4, 0xf9, 0x93,
		0xbe, 0x88, 0x2d, 0xff, 0xf6, 0xda, 0x04, 0x71,
		0x20, 0x39, 0xdf, 0xd9, 0x42, 0x45, 0xda, 0x64,
		0x3e, 0xd3, 0x84, 0xe7, 0x7b, 0xc6, 0x5e, 0x83
	};

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memset(params, 0, sizeof(SPX_PARAMS()));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	params->robust = 0;
	memcpy(&params->prf.data, prf, 32);
	params->prf.length = 32;
	memset(hash, 0, EVP_MAX_MD_SIZE);

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify different algorithm combinations - SHA256, SHA512, SHAKE
	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, NULL, &rmtl_ptr, &rmtl_len,
		SPX_MTL_SHA2) == 0);	
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;	
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, NULL, &rmtl_ptr, &rmtl_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], 16,
		&msg_buffer[0], msg_len, &hash[0], 16, NULL, &rmtl_ptr, &rmtl_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) == 0);

	// Verify that the different parameters provide uinque outputs
	// Vary randomizer
	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer_alt[0],
		randomizer_len, &msg_buffer[0], msg_len, &hash[0], hash_len, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer_alt[0],
		randomizer_len, &msg_buffer[0], msg_len, &hash[0], hash_len, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHAKE) == 0);		
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer_alt[0], 16,
		&msg_buffer[0], msg_len, &hash[0], 16, NULL, 
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	// Vary message  msg_buffer2
	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer2[0], msg_len, &hash[0], hash_len, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);	
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer2[0], msg_len, &hash[0], hash_len, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHAKE) == 0);	
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], 16,
		&msg_buffer2[0], msg_len, &hash[0], 16, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	// Vary seed
	memcpy(&params->pk_seed.seed, &seed_alt[0], 32);
	params->pk_seed.length = 32;
	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;	
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], 16,
		&msg_buffer[0], msg_len, &hash[0], 16, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	// Vary public key
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey_alt[0], 32);
	params->pk_root.length = 32;

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], 16,
		&msg_buffer[0], msg_len, &hash[0], 16, NULL,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	// Verify the context impact
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, context_str,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, context_str,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message
	       (params, &sid, 0, (uint8_t *) & randomizer[0], 16,
		&msg_buffer[0], msg_len, &hash[0], 16, context_str,
		&rmtl_ptr, &rmtl_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);
	free(rmtl_ptr);

	free(params);
	return 0;
}

/**
 * Verify the node set message hashing function SHA2 wrapper
 */
uint8_t test_SPX_mtl_node_set_hash_message_sha2(void)
{
	uint8_t msg_buffer[] = "test_SPX_mtl_node_set_hash_message";
	uint16_t msg_len = 34;
	uint8_t hash[EVP_MAX_MD_SIZE];
	SERIESID sid;
	uint16_t hash_len = 32;
	uint8_t rmtl[EVP_MAX_MD_SIZE];
	uint8_t* rmtl_ptr = &rmtl[0];
	uint32_t rmtl_len;
	uint8_t sha2_1[] = { 0x23, 0x96, 0x7b, 0x83, 0xd4, 0x92, 0xb3, 0x8e,
		0x01, 0x34, 0xd7, 0x71, 0x6c, 0x96, 0x1c, 0x21,
		0xe7, 0x2e, 0xf7, 0xcb, 0xf6, 0x37, 0x44, 0xf9,
		0x27, 0x9c, 0x82, 0x96, 0x7c, 0xcb, 0x2e, 0xa0

	};
	uint8_t sha2_2[] = { 0xdb, 0xf5, 0xe7, 0xc8, 0xb4, 0x38, 0xd1, 0xd3,
		0xa1, 0xe7, 0xf4, 0xe0, 0x58, 0x3b, 0x01, 0x37
	};
	uint8_t prf[] = { 0x3b, 0x70, 0x6b, 0xde, 0x28, 0xe4, 0xf9, 0x93,
		0xbe, 0x88, 0x2d, 0xff, 0xf6, 0xda, 0x04, 0x71,
		0x20, 0x39, 0xdf, 0xd9, 0x42, 0x45, 0xda, 0x64,
		0x3e, 0xd3, 0x84, 0xe7, 0x7b, 0xc6, 0x5e, 0x83
	};

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	memcpy(&params->prf.data, prf, 32);
	params->prf.length = 32;
	params->robust = 0;
	memset(hash, 0, EVP_MAX_MD_SIZE);

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify wrapper functions result in same output as base function
	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	rmtl_ptr = NULL;	
	assert(spx_mtl_node_set_hash_message_sha2
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, NULL, &rmtl_ptr, &rmtl_len) == 0);			
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_len = 0;
	free(rmtl_ptr);
	rmtl_ptr = NULL;
	assert(spx_mtl_node_set_hash_message_sha2
	       (params, &sid, 0, (uint8_t *) & randomizer[0], 16,
		&msg_buffer[0], msg_len, &hash[0], 16, NULL, &rmtl_ptr, &rmtl_len) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) == 0);
	free(rmtl_ptr);

	free(params);
	return 0;
}

/**
 * Verify the node set message hashing function Shake wrapper
 */
uint8_t test_SPX_mtl_node_set_hash_message_shake(void)
{
	uint8_t msg_buffer[] = "test_SPX_mtl_node_set_hash_message";
	uint16_t msg_len = 34;
	uint8_t hash[EVP_MAX_MD_SIZE];
	SERIESID sid;
	uint16_t hash_len = 32;
	uint8_t rmtl[EVP_MAX_MD_SIZE];
	uint8_t* rmtl_ptr = &rmtl[0];	
	uint32_t rmtl_len = 0;	
	uint8_t shake1[] = { 0x87, 0x2e, 0x33, 0xf9, 0xe2, 0xe3, 0x46, 0x62,
		0x94, 0x97, 0x2b, 0xb9, 0x91, 0x71, 0x24, 0x75,
		0xbc, 0xb8, 0xd9, 0x77, 0xee, 0x97, 0x3a, 0x47,
		0xc3, 0x44, 0x82, 0xdb, 0x30, 0x8c, 0xe3, 0x2e
	};
	uint8_t prf[] = { 0x3b, 0x70, 0x6b, 0xde, 0x28, 0xe4, 0xf9, 0x93,
		0xbe, 0x88, 0x2d, 0xff, 0xf6, 0xda, 0x04, 0x71,
		0x20, 0x39, 0xdf, 0xd9, 0x42, 0x45, 0xda, 0x64,
		0x3e, 0xd3, 0x84, 0xe7, 0x7b, 0xc6, 0x5e, 0x83
	};

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	memcpy(&params->prf.data, prf, 32);
	params->prf.length = 32;
	params->robust = 0;
	memset(hash, 0, EVP_MAX_MD_SIZE);

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify wrapper functions result in same output as base function
	memset(hash, 0, EVP_MAX_MD_SIZE);
	rmtl_ptr = NULL;
	rmtl_len = 0;
	assert(spx_mtl_node_set_hash_message_shake
	       (params, &sid, 0, (uint8_t *) & randomizer[0], randomizer_len,
		&msg_buffer[0], msg_len, &hash[0], hash_len, NULL, &rmtl_ptr, &rmtl_len) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);
	free(rmtl_ptr);

	free(params);
	return 0;
}

/**
 * Verify the node set leaf hashing function
 */
uint8_t test_SPX_mtl_node_set_hash_leaf(void)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_len = 32;
	SERIESID sid;
	uint8_t seed_alt[] = { 0x55, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
		0x06, 0xb5, 0x59, 0x89, 0x75, 0x08, 0xe7, 0x2c,
		0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
		0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
	};
	uint8_t msg_buffer[] = { 0x8a, 0x44, 0x26, 0x42, 0xad, 0x4a, 0x96, 0x1f,
		0xb4, 0x47, 0x52, 0x3b, 0x26, 0x42, 0xe7, 0x9b,
		0x65, 0xf4, 0x46, 0x49, 0xf1, 0xbd, 0x62, 0xa6,
		0xc4, 0x19, 0xd8, 0x82, 0xdf, 0x2d, 0x9a, 0xd0
	};
	uint8_t msg_buffer2[] =
	    { 0x8a, 0x44, 0x26, 0x42, 0xad, 0x4a, 0x96, 0x1f,
		0xb4, 0x47, 0x52, 0x3b, 0x26, 0x42, 0x7e, 0x9b,
		0x65, 0xf4, 0x46, 0x49, 0xf1, 0xbd, 0x62, 0xa6,
		0xc4, 0x19, 0xd8, 0x82, 0xdf, 0x2d, 0x9a, 0xd0
	};
	uint8_t sha2_1[] = { 0xb8, 0xe2, 0x70, 0xec, 0x86, 0x6d, 0x21, 0xb8,
		0x19, 0x19, 0x08, 0x04, 0xcf, 0x37, 0xbf, 0xab,
		0x63, 0xb6, 0xbf, 0x2c, 0x9f, 0x69, 0x36, 0x4e,
		0x47, 0x28, 0xf4, 0xb9, 0x40, 0xe0, 0x4e, 0x2f
	};
	uint8_t sha2_2[] = { 0x00, 0x15, 0x7c, 0x7a, 0xfd, 0x3b, 0xe2, 0x51,
		0x17, 0xbf, 0x2f, 0x28, 0x5a, 0x8e, 0xc0, 0xd5,
		0x6a, 0xcf, 0xc9, 0x42, 0x5a, 0x15, 0x68, 0xe4,
		0x8f, 0x10, 0x4f, 0x15, 0x26, 0x70, 0xa9, 0x81
	};
	uint8_t shake1[] = { 0x63, 0xe0, 0xe5, 0x0d, 0xf3, 0xc4, 0x4a, 0xe1,
		0x78, 0x73, 0xd4, 0x2e, 0x21, 0xc9, 0xc5, 0x3c,
		0x13, 0xec, 0xb7, 0x1a, 0x5a, 0xd5, 0x72, 0xa9,
		0x83, 0x90, 0x86, 0xc3, 0xe4, 0x88, 0x68, 0x38
	};
	uint8_t prf[] = { 0x3b, 0x70, 0x6b, 0xde, 0x28, 0xe4, 0xf9, 0x93,
		0xbe, 0x88, 0x2d, 0xff, 0xf6, 0xda, 0x04, 0x71,
		0x20, 0x39, 0xdf, 0xd9, 0x42, 0x45, 0xda, 0x64,
		0x3e, 0xd3, 0x84, 0xe7, 0x7b, 0xc6, 0x5e, 0x83
	};
	uint16_t msg_len = 32;
	uint32_t node_id = 11;

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	memcpy(&params->prf.data, prf, 32);
	params->prf.length = 32;
	params->robust = 0;

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify different algorithm combinations - SHA256, SHA512, SHAKE
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);	  
	assert(memcmp(&hash[0], sha2_2, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	// Test other parameters
	// Adjusted Msg Buffer
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf
	       (params, &sid, node_id, &msg_buffer2[0], msg_len, &hash[0],
		hash_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf
	       (params, &sid, node_id, &msg_buffer2[0], msg_len, &hash[0],
		hash_len, SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf
	       (params, &sid, node_id, &msg_buffer2[0], msg_len, &hash[0], 16,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf
	       (params, &sid, node_id, &msg_buffer2[0], msg_len, &hash[0],
		hash_len, SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// Adjusted Node ID
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, 0, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, 0, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, 0, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, 0, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// Adjusted SID
	memcpy(sid.id, sid_val_alt, 8);
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);
	memcpy(sid.id, sid_val, 8);

	// Adjusted SEED
	memcpy(&params->pk_seed.seed, &seed_alt[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// Adjusted PK
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey_alt[0], 32);
	params->pk_root.length = 32;
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	free(params);
	return 0;
}

/**
 * Verify the node set leaf hashing function w/robust
 */
uint8_t test_SPX_mtl_node_set_hash_leaf_robust(void)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_len = 32;
	SERIESID sid;
	uint8_t seed_alt[] = { 0x55, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
		0x06, 0xb5, 0x59, 0x89, 0x75, 0x08, 0xe7, 0x2c,
		0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
		0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
	};
	uint8_t msg_buffer[] = { 0x8a, 0x44, 0x26, 0x42, 0xad, 0x4a, 0x96, 0x1f,
		0xb4, 0x47, 0x52, 0x3b, 0x26, 0x42, 0xe7, 0x9b,
		0x65, 0xf4, 0x46, 0x49, 0xf1, 0xbd, 0x62, 0xa6,
		0xc4, 0x19, 0xd8, 0x82, 0xdf, 0x2d, 0x9a, 0xd0
	};
	uint8_t msg_buffer2[] =
	    { 0x8a, 0x44, 0x26, 0x42, 0xad, 0x4a, 0x96, 0x1f,
		0xb4, 0x47, 0x52, 0x3b, 0x26, 0x42, 0x7e, 0x9b,
		0x65, 0xf4, 0x46, 0x49, 0xf1, 0xbd, 0x62, 0xa6,
		0xc4, 0x19, 0xd8, 0x82, 0xdf, 0x2d, 0x9a, 0xd0
	};
	uint8_t sha2_1[] = { 0x13, 0x24, 0xeb, 0x9c, 0x1a, 0x30, 0x79, 0xd1,
		0x78, 0x4b, 0x50, 0xd0, 0x58, 0xf1, 0xb4, 0x37,
		0x06, 0x74, 0xa7, 0x93, 0x1c, 0xc4, 0xea, 0x0d,
		0x9f, 0x1a, 0x00, 0x27, 0x70, 0x53, 0x01, 0x5d
	};
	uint8_t sha2_2[] = { 0xc1, 0x11, 0x62, 0x34, 0x38, 0x51, 0x8b, 0x19,
		0xb7, 0xe1, 0x86, 0x7d, 0xb8, 0x87, 0x88, 0x73,
		0xf0, 0xd7, 0xfe, 0x9e, 0x02, 0xb0, 0xe5, 0xe5,
		0x79, 0x2c, 0xba, 0x92, 0x85, 0xad, 0x6e, 0xcf
	};
	uint8_t shake1[] = { 0x02, 0x2a, 0x36, 0x62, 0xd7, 0x1b, 0xbe, 0xcc,
		0x74, 0xf9, 0x29, 0x76, 0x2d, 0x97, 0x5f, 0x0e,
		0xe3, 0x5b, 0x5a, 0x5f, 0xd8, 0x0e, 0x85, 0xe0,
		0x60, 0x5a, 0xc9, 0x20, 0xe3, 0x41, 0x25, 0xee
	};
	uint8_t prf[] = { 0x3b, 0x70, 0x6b, 0xde, 0x28, 0xe4, 0xf9, 0x93,
		0xbe, 0x88, 0x2d, 0xff, 0xf6, 0xda, 0x04, 0x71,
		0x20, 0x39, 0xdf, 0xd9, 0x42, 0x45, 0xda, 0x64,
		0x3e, 0xd3, 0x84, 0xe7, 0x7b, 0xc6, 0x5e, 0x83
	};
	uint16_t msg_len = 32;
	uint32_t node_id = 11;

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	memcpy(&params->prf.data, prf, 32);
	params->prf.length = 32;
	params->robust = 1;

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify different algorithm combinations - SHA256, SHA512, SHAKE
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);					  
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);						  
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);			  
	assert(memcmp(&hash[0], sha2_2, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	// Test other parameters
	// Adjusted Msg Buffer
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf
	       (params, &sid, node_id, &msg_buffer2[0], msg_len, &hash[0],
		hash_len, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf
	       (params, &sid, node_id, &msg_buffer2[0], msg_len, &hash[0],
		hash_len, SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf
	       (params, &sid, node_id, &msg_buffer2[0], msg_len, &hash[0], 16,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf
	       (params, &sid, node_id, &msg_buffer2[0], msg_len, &hash[0],
		hash_len, SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// Adjusted Node ID
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, 0, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, 0, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, 0, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, 0, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// Adjusted SID
	memcpy(sid.id, sid_val_alt, 8);
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);
	memcpy(sid.id, sid_val, 8);

	// Adjusted SEED
	memcpy(&params->pk_seed.seed, &seed_alt[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// Adjusted PK
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey_alt[0], 32);
	params->pk_root.length = 32;
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], 16,
					  SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf(params, &sid, node_id, &msg_buffer[0],
					  msg_len, &hash[0], hash_len,
					  SPX_MTL_SHA2) == 0);

	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	free(params);
	return 0;
}

/**
 * Verify the node set leaf hashing sha2 wrapper
 */
uint8_t test_SPX_mtl_node_set_hash_leaf_sha2(void)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_len = 32;
	uint8_t msg_buffer[] = { 0x8a, 0x44, 0x26, 0x42, 0xad, 0x4a, 0x96, 0x1f,
		0xb4, 0x47, 0x52, 0x3b, 0x26, 0x42, 0xe7, 0x9b,
		0x65, 0xf4, 0x46, 0x49, 0xf1, 0xbd, 0x62, 0xa6,
		0xc4, 0x19, 0xd8, 0x82, 0xdf, 0x2d, 0x9a, 0xd0
	};
	uint8_t sha2_1[] = { 0xb8, 0xe2, 0x70, 0xec, 0x86, 0x6d, 0x21, 0xb8,
		0x19, 0x19, 0x08, 0x04, 0xcf, 0x37, 0xbf, 0xab,
		0x63, 0xb6, 0xbf, 0x2c, 0x9f, 0x69, 0x36, 0x4e,
		0x47, 0x28, 0xf4, 0xb9, 0x40, 0xe0, 0x4e, 0x2f
	};
	uint8_t sha2_2[] = { 0x00, 0x15, 0x7c, 0x7a, 0xfd, 0x3b, 0xe2, 0x51,
		0x17, 0xbf, 0x2f, 0x28, 0x5a, 0x8e, 0xc0, 0xd5,
		0x6a, 0xcf, 0xc9, 0x42, 0x5a, 0x15, 0x68, 0xe4,
		0x8f, 0x10, 0x4f, 0x15, 0x26, 0x70, 0xa9, 0x81
	};
	uint16_t msg_len = 32;
	uint32_t node_id = 11;
	SERIESID sid;

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	params->robust = 0;

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify different algorithm combinations - SHA256, SHA512, SHAKE
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf_sha2
	       (params, &sid, node_id, &msg_buffer[0], msg_len, &hash[0],
		hash_len) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf_sha2
	       (params, &sid, node_id, &msg_buffer[0], msg_len, &hash[0],
		16) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) == 0);

	// Test other parameters

	free(params);
	return 0;
}

/**
 * Verify the node set leaf hashing shake wrapper
 */
uint8_t test_SPX_mtl_node_set_hash_leaf_shake(void)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_len = 32;
	SERIESID sid;
	uint8_t msg_buffer[] = { 0x8a, 0x44, 0x26, 0x42, 0xad, 0x4a, 0x96, 0x1f,
		0xb4, 0x47, 0x52, 0x3b, 0x26, 0x42, 0xe7, 0x9b,
		0x65, 0xf4, 0x46, 0x49, 0xf1, 0xbd, 0x62, 0xa6,
		0xc4, 0x19, 0xd8, 0x82, 0xdf, 0x2d, 0x9a, 0xd0
	};
	uint8_t shake1[] = { 0x63, 0xe0, 0xe5, 0x0d, 0xf3, 0xc4, 0x4a, 0xe1,
		0x78, 0x73, 0xd4, 0x2e, 0x21, 0xc9, 0xc5, 0x3c,
		0x13, 0xec, 0xb7, 0x1a, 0x5a, 0xd5, 0x72, 0xa9,
		0x83, 0x90, 0x86, 0xc3, 0xe4, 0x88, 0x68, 0x38
	};
	uint16_t msg_len = 32;
	uint32_t node_id = 11;

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	params->robust = 0;

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_leaf_shake
	       (params, &sid, node_id, &msg_buffer[0], msg_len, &hash[0],
		hash_len) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	free(params);
	return 0;
}

/**
 * Verify the node set internal hashing function
 */
uint8_t test_SPX_mtl_node_set_hash_int(void)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_len = 32;
	SERIESID sid;
	uint8_t sha2_1[] = { 0x35, 0x52, 0x06, 0x12, 0xab, 0xb3, 0xfd, 0xeb,
		0xd3, 0xd4, 0x44, 0x92, 0xca, 0xb6, 0x63, 0x89,
		0xfa, 0xe6, 0x06, 0x9a, 0x85, 0x56, 0x2f, 0x3c,
		0x8d, 0x18, 0xaf, 0xf6, 0x8e, 0xa8, 0x28, 0x18
	};
	uint8_t sha2_2[] = { 0xd7, 0x15, 0x44, 0x8d, 0x1d, 0xe9, 0xbe, 0x86,
		0xda, 0xf6, 0xe4, 0x09, 0x69, 0x5e, 0x58, 0xf0,
		0xe5, 0xf1, 0xa6, 0xe9, 0x2d, 0x2e, 0x09, 0xea,
		0x5d, 0xf4, 0xc5, 0x30, 0x0a, 0xff, 0xdd, 0xc3
	};
	uint8_t shake1[] = { 0xfb, 0x72, 0x40, 0xdb, 0x2b, 0x7b, 0x04, 0x0c,
		0xa1, 0xb2, 0x55, 0x3f, 0xdb, 0xff, 0xe5, 0x59,
		0x54, 0x80, 0x28, 0x49, 0x60, 0xb8, 0xe4, 0x4d,
		0x32, 0x65, 0xbc, 0x5e, 0x29, 0x29, 0x64, 0x73
	};

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	params->robust = 0;

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify different algorithm combinations - SHA256, SHA512, SHAKE
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);	
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);	
	assert(memcmp(&hash[0], sha2_2, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	// seed
	memcpy(&params->pk_seed.seed, &seed_alt[0], 32);
	params->pk_seed.length = 32;
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;

	// public key
	memcpy(&params->pk_root.key, &pubkey_alt[0], 32);
	params->pk_root.length = 32;
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;

	// sid
	memcpy(sid.id, sid_val_alt, 8);
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);
	memcpy(sid.id, sid_val, 8);

	// left
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 0, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 0, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 0, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 0, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// right
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 11, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 11, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 11, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 11, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// hash_left
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left_alt[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left_alt[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left_alt[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left_alt[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// hash_right
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right_alt[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right_alt[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right_alt[0], &hash[0], 16,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right_alt[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	free(params);
	return 0;
}

/**
 * Verify the node set internal hashing function w/robust
 */
uint8_t test_SPX_mtl_node_set_hash_int_robust(void)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_len = 32;
	SERIESID sid;
	uint8_t sha2_1[] = { 0xc2, 0x99, 0x02, 0x42, 0x29, 0x27, 0xf9, 0x86,
		0xe5, 0x6f, 0x70, 0x5e, 0xdd, 0x90, 0xb3, 0x63,
		0x57, 0xaa, 0x9e, 0xce, 0xed, 0xf5, 0x79, 0xa2,
		0x67, 0x6e, 0xea, 0x86, 0xdb, 0x9a, 0x2c, 0xef
	};
	uint8_t sha2_2[] = { 0xe4, 0x92, 0x05, 0x6a, 0x78, 0x84, 0xd7, 0x85,
		0xfa, 0x3c, 0x1f, 0x03, 0x20, 0x5d, 0x81, 0x64,
		0x7c, 0x7b, 0x2d, 0x50, 0xd1, 0x8a, 0x91, 0x17,
		0x93, 0xc0, 0x80, 0x45, 0x2e, 0xc8, 0x4f, 0xb2
	};
	uint8_t shake1[] = { 0x49, 0xed, 0x02, 0x20, 0x9a, 0xbb, 0x4e, 0x58,
		0x8a, 0x92, 0x85, 0xa2, 0x51, 0xc9, 0x48, 0xdc,
		0xf9, 0x0b, 0x0f, 0x73, 0x38, 0x7e, 0x11, 0x32,
		0x85, 0xc1, 0x6c, 0x82, 0x90, 0xd4, 0x21, 0x90
	};
	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	params->robust = 1;

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify different algorithm combinations - SHA256, SHA512, SHAKE
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);	
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);		
	assert(memcmp(&hash[0], sha2_2, 16) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	// seed
	memcpy(&params->pk_seed.seed, &seed_alt[0], 32);
	params->pk_seed.length = 32;
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;

	// public key
	memcpy(&params->pk_root.key, &pubkey_alt[0], 32);
	params->pk_root.length = 32;
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, 16) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;

	// sid
	memcpy(sid.id, sid_val_alt, 8);
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);
	memcpy(sid.id, sid_val, 8);

	// left
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 0, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 0, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 0, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 0, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// right
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 11, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 11, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 11, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 11, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// hash_left
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left_alt[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left_alt[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left_alt[0],
		(uint8_t *) & hash_right[0], &hash[0], 16, SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left_alt[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	// hash_right
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right_alt[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right_alt[0], &hash[0], hash_len,
		SPX_MTL_SHAKE) == 0);
	assert(memcmp(&hash[0], shake1, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right_alt[0], &hash[0], 16,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) != 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right_alt[0], &hash[0], hash_len,
		SPX_MTL_SHA2) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) != 0);

	free(params);
	return 0;
}

/**
 * Verify the node set internal sha2 wrapper
 */
uint8_t test_SPX_mtl_node_set_hash_int_sha2(void)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_len = 32;
	SERIESID sid;
	uint8_t sha2_1[] = { 0x35, 0x52, 0x06, 0x12, 0xab, 0xb3, 0xfd, 0xeb,
		0xd3, 0xd4, 0x44, 0x92, 0xca, 0xb6, 0x63, 0x89,
		0xfa, 0xe6, 0x06, 0x9a, 0x85, 0x56, 0x2f, 0x3c,
		0x8d, 0x18, 0xaf, 0xf6, 0x8e, 0xa8, 0x28, 0x18
	};
	uint8_t sha2_2[] = { 0xd7, 0x15, 0x44, 0x8d, 0x1d, 0xe9, 0xbe, 0x86,
		0xda, 0xf6, 0xe4, 0x09, 0x69, 0x5e, 0x58, 0xf0,
		0xe5, 0xf1, 0xa6, 0xe9, 0x2d, 0x2e, 0x09, 0xea,
		0x5d, 0xf4, 0xc5, 0x30, 0x0a, 0xff, 0xdd, 0xc3
	};

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	params->robust = 0;

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify different algorithm combinations - SHA256, SHA512, SHAKE
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int_sha2
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len) == 0);
	assert(memcmp(&hash[0], sha2_1, hash_len) == 0);

	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int_sha2
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], 16) == 0);
	assert(memcmp(&hash[0], sha2_2, hash_len) == 0);

	free(params);
	return 0;
}

/**
 * Verify the node set internal shake wrapper
 */
uint8_t test_SPX_mtl_node_set_hash_int_shake(void)
{
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint16_t hash_len = 32;
	SERIESID sid;
	uint8_t shake1[] = { 0xfb, 0x72, 0x40, 0xdb, 0x2b, 0x7b, 0x04, 0x0c,
		0xa1, 0xb2, 0x55, 0x3f, 0xdb, 0xff, 0xe5, 0x59,
		0x54, 0x80, 0x28, 0x49, 0x60, 0xb8, 0xe4, 0x4d,
		0x32, 0x65, 0xbc, 0x5e, 0x29, 0x29, 0x64, 0x73
	};

	SPX_PARAMS *params = malloc(sizeof(SPX_PARAMS));
	memcpy(&params->pk_seed.seed, &seed[0], 32);
	params->pk_seed.length = 32;
	memcpy(&params->pk_root.key, &pubkey[0], 32);
	params->pk_root.length = 32;
	params->robust = 0;

	sid.length = 8;
	memcpy(sid.id, sid_val, 8);

	// Verify different algorithm combinations - SHA256, SHA512, SHAKE
	memset(hash, 0, EVP_MAX_MD_SIZE);
	assert(spx_mtl_node_set_hash_int_shake
	       (params, &sid, 8, 9, (uint8_t *) & hash_left[0],
		(uint8_t *) & hash_right[0], &hash[0], hash_len) == 0);

	assert(memcmp(&hash[0], shake1, hash_len) == 0);

	free(params);
	return 0;
}

/**
 * Verify the spx_sha2 message prf function
 */
uint8_t test_SPX_spx_mtl_prf_sha2(void)
{
	uint8_t skprf[] = { 0xde, 0x08, 0xc3, 0xf1, 0xc8, 0x43, 0x80, 0x94,
		0x2f, 0x7d, 0x38, 0x8e, 0x09, 0xe3, 0x4a, 0xc7,
		0x78, 0x87, 0x11, 0xe1, 0xbe, 0x39, 0x84, 0xbd,
		0x2d, 0x08, 0x45, 0xc2, 0x13, 0xd0, 0x20, 0x54,
		0xd2, 0xad, 0xc3, 0xdd, 0x92, 0xad, 0xad, 0x0d,
		0x79, 0x67, 0xd6, 0x02, 0xcf, 0x22, 0xa3, 0xd8,
		0x8c, 0x99, 0xe4, 0x29, 0x70, 0x4e, 0x6f, 0x45,
		0x14, 0xb1, 0xfb, 0xdf, 0xb9, 0x6e, 0x71, 0xd6
	};
	const char *message = "PRF Test Message Buffer";
	uint32_t message_len = 23;
	uint8_t rmtl[EVP_MAX_MD_SIZE];
	uint8_t rmtl_1[] = { 0xc7, 0x9f, 0x93, 0xdd, 0xec, 0x31, 0xc6, 0xd6,
		0x12, 0xe4, 0x44, 0xbb, 0x86, 0x2a, 0x7d, 0x8d
	};
	uint8_t rmtl_2[] = { 0x02, 0xa6, 0x8b, 0x3c, 0x80, 0x61, 0x78, 0x25,
		0xfd, 0x42, 0xbb, 0x7d, 0x1f, 0x52, 0x6c, 0xf8,
		0xfe, 0x2e, 0xfc, 0x9d, 0xe5, 0x15, 0x94, 0x97
	};
	uint8_t rmtl_3[] = { 0xe3, 0x79, 0xc1, 0x27, 0x32, 0x12, 0x20, 0x2c,
		0xcc, 0x78, 0x88, 0xbc, 0xc2, 0xa4, 0x5c, 0x06,
		0xf0, 0xb8, 0x1b, 0xf6, 0xd9, 0x42, 0xc4, 0x5d,
		0x67, 0x37, 0x40, 0xff, 0xf7, 0x52, 0x1b, 0x19
	};
	uint8_t rmtl_4[] = { 0x1d, 0xa0, 0x58, 0x95, 0x57, 0xef, 0x2e, 0xfc,
		0x9f, 0x89, 0xc0, 0x56, 0xf2, 0xda, 0xf3, 0xa1,
		0x05, 0xcb, 0xa7, 0xe5, 0x3d, 0xc5, 0xc4, 0x33,
		0x78, 0xeb, 0xd3, 0xbe, 0x1c, 0x71, 0x42, 0x8d,
		0xea, 0x62, 0x7c, 0xd2, 0xa1, 0x8e, 0xc0, 0xbc,
		0x31, 0x9a, 0x5c, 0xdd, 0xda, 0x78, 0x3a, 0x46,
		0xb7, 0xc3, 0xd1, 0xbc, 0x02, 0x80, 0xf2, 0x9d,
		0xb0, 0xe6, 0xef, 0x7e, 0xbc, 0xe7, 0x08, 0x19
	};

	// Test with hash length 16
	assert(spx_mtl_node_set_prf_msg_sha2
	       (skprf, 16, (uint8_t *) randomizer, 16, (uint8_t *) message,
		message_len, (uint8_t *) & rmtl, 16) == 0);
	assert(memcmp(&rmtl, &rmtl_1, 16) == 0);

	// Test with hash length 24
	assert(spx_mtl_node_set_prf_msg_sha2
	       (skprf, 24, (uint8_t *) randomizer, 24, (uint8_t *) message,
		message_len, (uint8_t *) & rmtl, 24) == 0);
	assert(memcmp(&rmtl, &rmtl_2, 24) == 0);

	// Test with hash length 32
	assert(spx_mtl_node_set_prf_msg_sha2
	       (skprf, 32, (uint8_t *) randomizer, 32, (uint8_t *) message,
		message_len, (uint8_t *) & rmtl, 32) == 0);
	assert(memcmp(&rmtl, &rmtl_3, 32) == 0);

	// Test with hash length 64
	assert(spx_mtl_node_set_prf_msg_sha2
	       (skprf, 64, (uint8_t *) randomizer, 32, (uint8_t *) message,
		message_len, (uint8_t *) & rmtl, 64) == 0);
	assert(memcmp(&rmtl, &rmtl_4, 64) == 0);

	return 0;
}

/**
 * Verify the spx_sha2 message prf function
 */
uint8_t test_SPX_spx_mtl_prf_shake(void)
{
	uint8_t skprf[] = { 0xde, 0x08, 0xc3, 0xf1, 0xc8, 0x43, 0x80, 0x94,
		0x2f, 0x7d, 0x38, 0x8e, 0x09, 0xe3, 0x4a, 0xc7,
		0x78, 0x87, 0x11, 0xe1, 0xbe, 0x39, 0x84, 0xbd,
		0x2d, 0x08, 0x45, 0xc2, 0x13, 0xd0, 0x20, 0x54,
		0xd2, 0xad, 0xc3, 0xdd, 0x92, 0xad, 0xad, 0x0d,
		0x79, 0x67, 0xd6, 0x02, 0xcf, 0x22, 0xa3, 0xd8,
		0x8c, 0x99, 0xe4, 0x29, 0x70, 0x4e, 0x6f, 0x45,
		0x14, 0xb1, 0xfb, 0xdf, 0xb9, 0x6e, 0x71, 0xd6
	};
	const char *message = "PRF Test Message Buffer";
	uint32_t message_len = 23;
	uint8_t rmtl[EVP_MAX_MD_SIZE];
	uint8_t rmtl_1[] = { 0xc2, 0xd3, 0x27, 0xd6, 0xcd, 0x4f, 0x21, 0xdd,
		0x10, 0x45, 0x42, 0x02, 0xb2, 0x16, 0x82, 0xaa
	};
	uint8_t rmtl_2[] = { 0xa3, 0x64, 0x91, 0x21, 0xcf, 0xd3, 0xf7, 0xea,
		0x32, 0xb2, 0x29, 0xbc, 0xfa, 0xce, 0x91, 0xc6,
		0xc4, 0x8b, 0x42, 0x38, 0x2c, 0x9e, 0xb9, 0x95
	};
	uint8_t rmtl_3[] = { 0xda, 0x88, 0xb6, 0x8f, 0x99, 0xcc, 0x1c, 0x9f,
		0x87, 0xf8, 0xa2, 0x7f, 0x98, 0xb8, 0x9c, 0xbe,
		0xe5, 0xc7, 0xf0, 0xd7, 0x4f, 0x5d, 0x46, 0x05,
		0x9f, 0xfc, 0x9b, 0x50, 0x3c, 0x84, 0xb6, 0x75
	};
	uint8_t rmtl_4[] = { 0x97, 0xf2, 0xaa, 0x24, 0x23, 0xa6, 0x5b, 0x7c,
		0xb8, 0xf7, 0x26, 0xc3, 0x74, 0x8d, 0x13, 0x2d,
		0x8a, 0x3f, 0x90, 0x73, 0x24, 0x3f, 0x1e, 0x77,
		0xc8, 0xa6, 0x74, 0x32, 0xc9, 0x63, 0xff, 0x89,
		0x57, 0x6b, 0x45, 0x4a, 0xfd, 0x31, 0x61, 0xca,
		0xd6, 0x7e, 0xfd, 0xc0, 0xf7, 0x18, 0xd0, 0x05,
		0x30, 0x00, 0x75, 0xf2, 0x99, 0xae, 0x95, 0x4f,
		0x06, 0xf9, 0xf1, 0x70, 0x8c, 0xe2, 0x88, 0x92
	};

	// Test with hash length 16
	assert(spx_mtl_node_set_prf_msg_shake
	       (skprf, 16, (uint8_t *) randomizer, 16, (uint8_t *) message,
		message_len, (uint8_t *) & rmtl, 16) == 0);
	assert(memcmp(&rmtl, &rmtl_1, 16) == 0);

	// Test with hash length 24
	assert(spx_mtl_node_set_prf_msg_shake
	       (skprf, 24, (uint8_t *) randomizer, 24, (uint8_t *) message,
		message_len, (uint8_t *) & rmtl, 24) == 0);
	assert(memcmp(&rmtl, &rmtl_2, 24) == 0);

	// Test with hash length 32
	assert(spx_mtl_node_set_prf_msg_shake
	       (skprf, 32, (uint8_t *) randomizer, 32, (uint8_t *) message,
		message_len, (uint8_t *) & rmtl, 32) == 0);
	assert(memcmp(&rmtl, &rmtl_3, 32) == 0);

	// Test with hash length 64
	assert(spx_mtl_node_set_prf_msg_shake
	       (skprf, 64, (uint8_t *) randomizer, 32, (uint8_t *) message,
		message_len, (uint8_t *) & rmtl, 64) == 0);
	assert(memcmp(&rmtl, &rmtl_4, 64) == 0);

	return 0;

}
