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
#include "mtllib.h"
#include "mtltest_test_vectors.h"

// Prototypes for testing functions
uint8_t mtltest_mtllib_key_new(void);
uint8_t mtltest_mtllib_key_new_null(void);
uint8_t mtltest_mtllib_pubkey_to_buffer(void);
uint8_t mtltest_mtllib_pubkey_to_buffer_null(void);
uint8_t mtltest_mtllib_pubkey_from_buffer(void);
uint8_t mtltest_mtllib_pubkey_from_buffer_null(void);
uint8_t mtltest_mtllib_key_from_buffer(void);
uint8_t mtltest_mtllib_key_from_buffer_null(void);
uint8_t mtltest_mtllib_key_to_buffer(void);
uint8_t mtltest_mtllib_key_to_buffer_null(void);
uint8_t mtltest_mtllib_sign_append(void);
uint8_t mtltest_mtllib_sign_append_null(void);
uint8_t mtltest_mtllib_sign_free_handle_null(void);
uint8_t mtltest_mtllib_sign_get_condensed_sig(void);
uint8_t mtltest_mtllib_sign_get_condensed_sig_null(void);
uint8_t mtltest_mtllib_sign_get_signed_ladder(void);
uint8_t mtltest_mtllib_sign_get_signed_ladder_null(void);
uint8_t mtltest_mtllib_sign_get_full_sig(void);
uint8_t mtltest_mtllib_sign_get_full_sig_null(void);

uint8_t mtltest_mtllib_verify_condensed(void);
uint8_t mtltest_mtllib_verify_condensed_no_ladder(void);
uint8_t mtltest_mtllib_verify_full(void);
uint8_t mtltest_mtllib_verify_null(void);
uint8_t mtltest_mtllib_verify_unparseable(void);

uint8_t mtltest_mtllib_verify_signed_ladder(void);
uint8_t mtltest_mtllib_verify_signed_ladder_no_sig(void);
uint8_t mtltest_mtllib_verify_signed_ladder_corrupt(void);
uint8_t mtltest_mtllib_verify_signed_ladder_null(void);


uint8_t mtltest_mtllib(void)
{
	NEW_TEST("MTL Library Tests");

	RUN_TEST(mtltest_mtllib_key_new,
			 "Verify MTL library key generation function");
	RUN_TEST(mtltest_mtllib_key_new_null,
			 "Verify MTL library key generation function with NULL parameters");
	RUN_TEST(mtltest_mtllib_pubkey_to_buffer,
			 "Verify MTL library get public key from a key set");
	RUN_TEST(mtltest_mtllib_pubkey_to_buffer_null,
			 "Verify MTL library get public key from a key set");
	RUN_TEST(mtltest_mtllib_pubkey_from_buffer,
			 "Verify MTL library get public key function with NULL parameters");
	RUN_TEST(mtltest_mtllib_pubkey_from_buffer_null,
			 "Verify MTL library get public key from a parameter set with NULL parameters");
	RUN_TEST(mtltest_mtllib_key_from_buffer,
			 "Verify MTL library get a key from a byte buffer");
	RUN_TEST(mtltest_mtllib_key_from_buffer_null,
			 "Verify MTL library get a key from a byte buffer with NULL parameters");
	RUN_TEST(mtltest_mtllib_key_to_buffer,
			 "Verify MTL library write a key to a byte buffer");
	RUN_TEST(mtltest_mtllib_key_to_buffer_null,
			 "Verify MTL library write a key to a byte buffer with NULL parameters");
	RUN_TEST(mtltest_mtllib_sign_append,
			 "Verify MTL library signer append message");
	RUN_TEST(mtltest_mtllib_sign_append_null,
			 "Verify MTL library signer append message with NULL parameters");
	RUN_TEST(mtltest_mtllib_sign_free_handle_null,
			 "Verify MTL library signer free message handle with NULL parameters");
	RUN_TEST(mtltest_mtllib_sign_get_condensed_sig,
			 "Verify MTL library signer get condensed signature");
	RUN_TEST(mtltest_mtllib_sign_get_condensed_sig_null,
			 "Verify MTL library signer get condensed signature with NULL parameters");
	RUN_TEST(mtltest_mtllib_sign_get_signed_ladder,
			 "Verify MTL library signer get signed ladder");
	RUN_TEST(mtltest_mtllib_sign_get_signed_ladder_null,
			 "Verify MTL library signer get signed ladder with NULL parameters");
	RUN_TEST(mtltest_mtllib_sign_get_full_sig,
			 "Verify MTL library signer get full signature");
	RUN_TEST(mtltest_mtllib_sign_get_full_sig_null,
			 "Verify MTL library signer get full signature with NULL parameters");
	RUN_TEST(mtltest_mtllib_verify_condensed,
			 "Verify MTL library verify a condensed signature");
	RUN_TEST(mtltest_mtllib_verify_condensed_no_ladder,
			 "Verify MTL library verify a condensed signature with no ladder");
	RUN_TEST(mtltest_mtllib_verify_full,
			 "Verify MTL library verify a full signature");
	RUN_TEST(mtltest_mtllib_verify_null,
			 "Verify MTL library verify a signature with NULL parameters");
	RUN_TEST(mtltest_mtllib_verify_unparseable,
			 "Verify MTL library verify a signature with unparseable parameters");
	RUN_TEST(mtltest_mtllib_verify_signed_ladder,
			 "Verify MTL library verify a signed ladder");
	RUN_TEST(mtltest_mtllib_verify_signed_ladder_no_sig,
			 "Verify MTL library verify a signed ladder missing the signature");
	RUN_TEST(mtltest_mtllib_verify_signed_ladder_corrupt,
			 "Verify MTL library verify a signed ladder that is corrupt");			 			 
	RUN_TEST(mtltest_mtllib_verify_signed_ladder_null,
			 "Verify MTL library verify a signed ladder with NULL parameters");			 

	return 0;
}

extern MTL_ALGORITHM_PROPS sig_algos[];

/**
 * Test the mtl initialization routines
 */
uint8_t mtltest_mtllib_key_new(void)
{
	size_t algo = 0;
	MTLLIB_CTX *ctx = NULL;

	// Test creating key
	algo = 0;
	while (sig_algos[algo].name != NULL)
	{
		ctx = NULL;
		assert(mtllib_key_new(sig_algos[algo].name, &ctx) == MTLLIB_OK);
		assert(ctx->algo_params == &sig_algos[algo]);
		assert(ctx->signature != NULL);
		assert(ctx->secret_key != NULL);
		assert(ctx->secret_key_len > 0);
		assert(ctx->public_key != NULL);
		assert(ctx->public_key_len > 0);
		assert(ctx->mtl != NULL);
		mtllib_key_free(ctx);
		algo++;
	}

	return 0;
}

/**
 * Test the mtl initialization routines with NULL parameters
 */
uint8_t mtltest_mtllib_key_new_null(void)
{
	MTLLIB_CTX *ctx = NULL;

	assert(mtllib_key_new(NULL, &ctx) == MTLLIB_NULL_PARAMS);
	assert(mtllib_key_new(MTL_TEST_VECTOR_SCHEME_NAME, NULL) == MTLLIB_NULL_PARAMS);

	return 0;
}

uint8_t mtltest_mtllib_pubkey_to_buffer(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTLLIB_BUFFER *public_key = NULL;
	size_t key_len = 0;

	assert(mtllib_key_new(MTL_TEST_VECTOR_SCHEME_NAME, &ctx) == MTLLIB_OK);
	key_len = mtllib_pubkey_to_buffer_length(ctx);
	assert(key_len == MTL_TEST_VECTOR_SCHEME_PK_LEN);
	assert(mtllib_buffer_initialize(&public_key, key_len, NULL) == MTLLIB_OK);
	assert(public_key->buffer_length == key_len);
	assert(public_key->buffer_position == 0);
	assert(mtllib_pubkey_to_buffer(ctx, public_key) == MTLLIB_OK);
	assert(public_key->buffer_length == key_len);
	assert(public_key->buffer_position == key_len);
	assert(memcmp(public_key->buffer_data, ctx->public_key, key_len) == 0);
	mtllib_key_free(ctx);
	mtllib_buffer_free(public_key);

	return 0;
}

uint8_t mtltest_mtllib_pubkey_to_buffer_null(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTLLIB_BUFFER *public_key = NULL;

	assert(mtllib_key_new(MTL_TEST_VECTOR_SCHEME_NAME, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&public_key, mtllib_pubkey_to_buffer_length(ctx), NULL) == MTLLIB_OK);
	assert(mtllib_pubkey_to_buffer(NULL, public_key) == MTLLIB_NULL_PARAMS);
	assert(public_key->buffer_position == 0);
	assert(mtllib_pubkey_to_buffer(ctx, NULL) == MTLLIB_NULL_PARAMS);
	assert(public_key->buffer_position == 0);
	mtllib_buffer_free(public_key);
	assert(mtllib_buffer_initialize(&public_key, 1, NULL) == MTLLIB_OK);
	assert(mtllib_pubkey_to_buffer(ctx, public_key) == MTLLIB_BUFFER_ISSUE);
	mtllib_buffer_free(public_key);
	mtllib_key_free(ctx);

	return 0;
}

uint8_t mtltest_mtllib_pubkey_from_buffer(void)
{
	size_t algo = 0;
	MTLLIB_CTX *ctx = NULL;
	uint8_t *pubkey = NULL;
	size_t pubkey_len[] = {
        OQS_SIG_sphincs_shake_128s_simple_length_public_key,
        OQS_SIG_sphincs_shake_128f_simple_length_public_key,
        OQS_SIG_sphincs_shake_192s_simple_length_public_key,
        OQS_SIG_sphincs_shake_192f_simple_length_public_key,
        OQS_SIG_sphincs_shake_256s_simple_length_public_key,
        OQS_SIG_sphincs_shake_256f_simple_length_public_key,
        OQS_SIG_sphincs_sha2_128s_simple_length_public_key,
        OQS_SIG_sphincs_sha2_128f_simple_length_public_key,
        OQS_SIG_sphincs_sha2_192s_simple_length_public_key,
        OQS_SIG_sphincs_sha2_192f_simple_length_public_key,
        OQS_SIG_sphincs_sha2_256s_simple_length_public_key,
        OQS_SIG_sphincs_sha2_256f_simple_length_public_key,
        OQS_SIG_ml_dsa_44_length_public_key,
        OQS_SIG_ml_dsa_65_length_public_key,
        OQS_SIG_ml_dsa_87_length_public_key,
//        OQS_SIG_falcon_512_length_public_key,
        OQS_SIG_falcon_padded_512_length_public_key,
//        OQS_SIG_falcon_1024_length_public_key,
        OQS_SIG_falcon_padded_1024_length_public_key,
        OQS_SIG_mayo_1_length_public_key,
        OQS_SIG_mayo_2_length_public_key,
        OQS_SIG_mayo_3_length_public_key,
        OQS_SIG_mayo_5_length_public_key,
        OQS_SIG_cross_rsdp_128_balanced_length_public_key,
        OQS_SIG_cross_rsdp_128_fast_length_public_key,
        OQS_SIG_cross_rsdp_128_small_length_public_key,
        OQS_SIG_cross_rsdp_192_balanced_length_public_key,
        OQS_SIG_cross_rsdp_192_fast_length_public_key,
        OQS_SIG_cross_rsdp_192_small_length_public_key,
        OQS_SIG_cross_rsdp_256_balanced_length_public_key,
        OQS_SIG_cross_rsdp_256_fast_length_public_key,
        OQS_SIG_cross_rsdp_256_small_length_public_key,
        OQS_SIG_cross_rsdpg_128_balanced_length_public_key,
        OQS_SIG_cross_rsdpg_128_fast_length_public_key,
        OQS_SIG_cross_rsdpg_128_small_length_public_key,
        OQS_SIG_cross_rsdpg_192_balanced_length_public_key,
        OQS_SIG_cross_rsdpg_192_fast_length_public_key,
        OQS_SIG_cross_rsdpg_192_small_length_public_key,
        OQS_SIG_cross_rsdpg_256_balanced_length_public_key,
        OQS_SIG_cross_rsdpg_256_fast_length_public_key,
        OQS_SIG_cross_rsdpg_256_small_length_public_key,
        OQS_SIG_uov_ov_Is_length_public_key,
        OQS_SIG_uov_ov_Ip_length_public_key,
        OQS_SIG_uov_ov_III_length_public_key,
        OQS_SIG_uov_ov_V_length_public_key,
        OQS_SIG_uov_ov_Is_pkc_length_public_key,
        OQS_SIG_uov_ov_Ip_pkc_length_public_key,
        OQS_SIG_uov_ov_III_pkc_length_public_key,
        OQS_SIG_uov_ov_V_pkc_length_public_key,
        OQS_SIG_uov_ov_Is_pkc_skc_length_public_key,
        OQS_SIG_uov_ov_Ip_pkc_skc_length_public_key,
        OQS_SIG_uov_ov_III_pkc_skc_length_public_key,
        OQS_SIG_uov_ov_V_pkc_skc_length_public_key,
        OQS_SIG_snova_SNOVA_24_5_4_length_public_key,
        OQS_SIG_snova_SNOVA_24_5_4_SHAKE_length_public_key,
        OQS_SIG_snova_SNOVA_24_5_4_esk_length_public_key,
        OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_length_public_key,
        OQS_SIG_snova_SNOVA_37_17_2_length_public_key,
        OQS_SIG_snova_SNOVA_25_8_3_length_public_key,
        OQS_SIG_snova_SNOVA_56_25_2_length_public_key,
        OQS_SIG_snova_SNOVA_49_11_3_length_public_key,
        OQS_SIG_snova_SNOVA_37_8_4_length_public_key,
        OQS_SIG_snova_SNOVA_24_5_5_length_public_key,
        OQS_SIG_snova_SNOVA_60_10_4_length_public_key,
        OQS_SIG_snova_SNOVA_29_6_5_length_public_key
	};
	uint8_t sid[32];
	FILE *fd = NULL;
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	
	// OV Keys are very large so it is best to allocate heap space not stack space for test.
	pubkey = calloc(1, OQS_SIG_uov_ov_V_length_public_key);
	assert(pubkey != NULL);
	memset(&sid[0], 0x55, 32);
	memset(pubkey, 0xaf, 4096);
	// Setup to get random data for the test pubkey
	if ((fd = fopen("/dev/random", "r")) == NULL) {
		free(pubkey);
		return 1;
	}

	// Test creating key with no context string
	algo = 0;
	while (sig_algos[algo].name != NULL)
	{
		fread(pubkey, 128, 1, fd);
		ctx = NULL;
		assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len[algo], pubkey) == MTLLIB_OK);
		assert(mtllib_pubkey_from_buffer(sig_algos[algo].name, &ctx, pubkey_buffer, sid) == MTLLIB_OK);
		assert(ctx->algo_params == &sig_algos[algo]);
		assert(ctx->signature != NULL);
		assert(ctx->secret_key != NULL);
		assert(ctx->secret_key_len == 0);
		assert(ctx->public_key != NULL);
		assert(memcmp(ctx->public_key, pubkey, pubkey_len[algo]) == 0);
		assert(ctx->public_key_len == pubkey_len[algo]);
		assert(ctx->mtl != NULL);
		mtllib_key_free(ctx);
		algo++;
		mtllib_buffer_free(pubkey_buffer);
	}
	fclose(fd);	
	free(pubkey);

	return 0;
}

uint8_t mtltest_mtllib_pubkey_from_buffer_null(void)
{
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[8];
	uint8_t pubkey[32];

	memset(&sid[0],0x55, 8);
	memset(&pubkey[0], 0xaa, 32);
	MTLLIB_BUFFER *pubkey_buffer = NULL;

	assert(mtllib_buffer_initialize(&pubkey_buffer, 32, pubkey) == MTLLIB_OK);
	assert(mtllib_pubkey_from_buffer(NULL, &ctx, pubkey_buffer, &sid[0]) == MTLLIB_NULL_PARAMS);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, NULL, pubkey_buffer, &sid[0]) == MTLLIB_NULL_PARAMS);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, NULL, &sid[0]) == MTLLIB_NULL_PARAMS);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, NULL) == MTLLIB_NULL_PARAMS);

	mtllib_buffer_free(pubkey_buffer);
	return 0;
}

uint8_t mtltest_mtllib_key_from_buffer(void)
{
	MTLLIB_CTX *ctx = NULL;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	char scheme_str[] = MTL_TEST_VECTOR_SCHEME_UNDERLYING;
	size_t sk_len = MTL_TEST_VECTOR_SCHEME_SK_LEN;
	size_t pk_len = MTL_TEST_VECTOR_SCHEME_PK_LEN;
	MTLLIB_BUFFER *key_buffer = NULL;
	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);

	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(strcmp(ctx->algo_params->scheme_str,scheme_str) == 0);
	assert(ctx->signature != NULL);
	assert(ctx->secret_key != NULL);
	assert(ctx->secret_key_len == sk_len);
	assert(ctx->public_key != NULL);
	assert(ctx->public_key_len == pk_len);
	assert(ctx->mtl != NULL);
	mtllib_key_free(ctx);

	mtllib_buffer_free(key_buffer);

	return 0;
}

uint8_t mtltest_mtllib_key_from_buffer_null(void)
{
	MTLLIB_CTX *ctx = NULL;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	MTLLIB_BUFFER *key_buffer = NULL;
	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);

	assert(mtllib_key_from_buffer(NULL, &ctx) == MTLLIB_NULL_PARAMS);

	mtllib_buffer_free(key_buffer);
	assert(mtllib_buffer_initialize(&key_buffer, 0, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_BAD_VALUE);
	mtllib_buffer_free(key_buffer);
	assert(mtllib_buffer_initialize(&key_buffer, 1, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_BAD_VALUE);
	mtllib_buffer_free(key_buffer);

	return 0;
}

uint8_t mtltest_mtllib_key_to_buffer(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTLLIB_BUFFER *buffer = NULL;
	size_t sk_len = MTL_TEST_VECTOR_SCHEME_SK_LEN;
	size_t pk_len = MTL_TEST_VECTOR_SCHEME_PK_LEN;
	size_t secparam = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	uint8_t sk_len_bytes[4];
	uint8_t pk_len_bytes[4];
	uint32_to_bytes(sk_len_bytes, sk_len);
	uint32_to_bytes(pk_len_bytes, pk_len);
	MTL_INDEX ZERO = 0;

	char alg_str[] = MTL_TEST_VECTOR_SCHEME_NAME;
	uint8_t identifier[64];
	identifier[0] = 0; identifier[1] = 0; identifier[2] = 0;
	identifier[3] = strlen(alg_str);
	memcpy(identifier+4, alg_str, strlen(alg_str));
	size_t identifier_len = 4 + strlen(alg_str);

	size_t offsets[] = {
		identifier_len,
		identifier_len+4+sk_len,
		identifier_len+4+sk_len+4+pk_len,
		identifier_len+4+sk_len+4+pk_len+2,
		identifier_len+4+sk_len+4+pk_len+2+4+2*secparam,
		identifier_len+4+sk_len+4+pk_len+2+4+2*secparam+sizeof(MTL_INDEX),
	};

	assert(mtllib_buffer_initialize(&buffer, MTL_TEST_VECTOR_KEYBUFFER_LEN, NULL) == MTLLIB_OK);

	assert(mtllib_key_new(alg_str, &ctx) == MTLLIB_OK);
	assert(mtllib_key_to_buffer_length(ctx) == MTL_TEST_VECTOR_KEYBUFFER_LEN);
	assert(mtllib_key_to_buffer(ctx, buffer) == MTLLIB_OK);
	assert(buffer->buffer_position == MTL_TEST_VECTOR_KEYBUFFER_LEN);
	assert(buffer != NULL);
	// Idenfifier String
	assert(memcmp(buffer->buffer_data, &identifier[0], identifier_len) == 0);
	// SK Length
	assert(memcmp(buffer->buffer_data+offsets[0], sk_len_bytes, 4) == 0);
	// PK Length
	assert(memcmp(buffer->buffer_data+offsets[1], pk_len_bytes, 4) == 0);
	// Randomizer
	assert(memcmp(buffer->buffer_data+offsets[2], (uint8_t []){0,1}, 2) == 0);
	// SID
	assert(memcmp(buffer->buffer_data+offsets[3], (uint8_t []){0,0,0,2*secparam}, 4) == 0);
	// Leaf Count
	assert(memcmp(buffer->buffer_data+offsets[4], &ZERO, sizeof(MTL_INDEX)) == 0);
	// Hash Size
	assert(memcmp(buffer->buffer_data+offsets[5], (uint8_t []){0,MTL_TEST_VECTOR_SCHEME_SECPARAM}, 2) == 0);
	mtllib_buffer_free(buffer);
	mtllib_key_free(ctx);

	return 0;
}

uint8_t mtltest_mtllib_key_to_buffer_null(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTLLIB_BUFFER *buffer = NULL;

	assert(mtllib_buffer_initialize(&buffer, MTL_TEST_VECTOR_KEYBUFFER_LEN, NULL) == MTLLIB_OK);
	assert(mtllib_key_new(MTL_TEST_VECTOR_SCHEME_NAME, &ctx) == MTLLIB_OK);
	assert(mtllib_key_to_buffer(NULL, buffer) == MTLLIB_NULL_PARAMS);
	assert(mtllib_key_to_buffer(ctx, NULL) == MTLLIB_NULL_PARAMS);
	assert(mtllib_buffer_free(buffer) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&buffer, 1, NULL) == MTLLIB_OK);
	assert(mtllib_key_to_buffer(ctx, buffer) == MTLLIB_BUFFER_ISSUE);
	assert(mtllib_buffer_free(buffer) == MTLLIB_OK);

	mtllib_key_free(ctx);
	return 0;
}

uint8_t mtltest_mtllib_sign_append(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTL_HANDLE *handle;

	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	uint8_t msg[] = MTL_TEST_VECTOR_MSG;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	uint8_t ctx_str[] = MTL_TEST_VECTOR_CTX;
	size_t ctx_str_len = MTL_TEST_VECTOR_CTX_LEN;
	size_t secparam = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	size_t index = 0;
	MTLLIB_BUFFER *key_buffer = NULL;
	MTLLIB_BUFFER *msg_buffer = NULL;
	MTLLIB_BUFFER *ctx_str_buffer = NULL;
	
	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_free(key_buffer) == MTLLIB_OK);	
	assert(mtllib_buffer_initialize(&msg_buffer, msg_len, msg) == MTLLIB_OK);

	for (index = 0; index < 15; index++)
	{
		assert(mtllib_sign_append(ctx, msg_buffer, &handle) == MTLLIB_OK);
		assert(&handle != NULL);
		assert(handle->leaf_index == index);
		assert(handle->sid_len == 2*secparam);
		assert(memcmp(handle->sid, &sid[0], 2*secparam) == 0);
		mtllib_sign_free_handle(&handle);
		assert(handle == NULL);
	}
	mtllib_buffer_free(msg_buffer);
	mtllib_key_free(ctx);

	// Re-test with ctx_str
	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_free(key_buffer) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&msg_buffer, msg_len, msg) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&ctx_str_buffer, ctx_str_len, ctx_str) == MTLLIB_OK);

	for (index = 0; index < 15; index++)
	{
		assert(mtllib_sign_append_with_ctx_str(ctx, msg_buffer, ctx_str_buffer, &handle) == MTLLIB_OK);
		assert(&handle != NULL);
		assert(handle->leaf_index == index);
		assert(handle->sid_len == 2*secparam);
		assert(memcmp(handle->sid, &sid[0], 2*secparam) == 0);
		mtllib_sign_free_handle(&handle);
		assert(handle == NULL);
	}
	mtllib_buffer_free(msg_buffer);
	mtllib_buffer_free(ctx_str_buffer);
	mtllib_key_free(ctx);

	return 0;
}
uint8_t mtltest_mtllib_sign_append_null(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTL_HANDLE *handle;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	uint8_t msg[] = MTL_TEST_VECTOR_MSG;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	MTLLIB_BUFFER *key_buffer = NULL;
	MTLLIB_BUFFER *msg_buffer = NULL;

	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&msg_buffer, msg_len, msg) == MTLLIB_OK);

	assert(mtllib_sign_append(NULL, msg_buffer, &handle) == MTLLIB_NULL_PARAMS);
	assert(handle == NULL);
	mtllib_sign_free_handle(&handle);
	assert(handle == NULL);
	assert(mtllib_sign_append(ctx, NULL, &handle) == MTLLIB_NULL_PARAMS);
	assert(mtllib_sign_append(ctx, msg_buffer, NULL) == MTLLIB_NULL_PARAMS);
	mtllib_buffer_free(key_buffer);

	mtllib_buffer_free(msg_buffer);
	mtllib_key_free(ctx);
	return 0;
}

uint8_t mtltest_mtllib_sign_free_handle_null(void)
{
	// Run free on NULL to make sure this doesn't crash
	mtllib_sign_free_handle(NULL);

	return 0;
}
uint8_t mtltest_mtllib_sign_get_condensed_sig(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTL_HANDLE *handle = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	uint8_t msg[] = MTL_TEST_VECTOR_MSG;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	size_t secparam = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	size_t index = 0;
	MTLLIB_BUFFER *key_buffer = NULL;
	MTLLIB_BUFFER *sig = NULL;
	MTLLIB_BUFFER *msg_buffer = NULL;
	size_t sig_len;
	size_t hashes[] = {3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 1, 1, 0};
	size_t constant_overhead = 4 + 3*secparam + (3*sizeof(MTL_INDEX)); // randomizer + flags + SID + (index+left_rung+right_rung) + sibling_count

	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_free(key_buffer) == MTLLIB_OK);	
	assert(mtllib_buffer_initialize(&msg_buffer, msg_len, msg) == MTLLIB_OK);

	for (index = 0; index < 15; index++)
	{
		if (handle != NULL)
		{
			mtllib_sign_free_handle(&handle);
			assert(handle == NULL);
		}
		assert(mtllib_sign_append(ctx, msg_buffer,  &handle) == MTLLIB_OK);
		assert(&handle != NULL);
		assert(handle->leaf_index == index);
		assert(handle->sid_len == 2*secparam);
		assert(memcmp(handle->sid, &sid[0], 2*secparam) == 0);
	}

	for (index = 0; index < 15; index++)
	{
		handle->leaf_index = index;
		sig_len = mtllib_sign_get_condensed_sig_length(ctx, handle);
		assert(sig_len == constant_overhead + (hashes[index] * secparam));
		assert(mtllib_buffer_initialize(&sig, sig_len, NULL) == MTLLIB_OK);
		assert(mtllib_sign_get_condensed_sig(ctx, handle, sig) == MTLLIB_OK);
		assert(sig->buffer_position == sig_len);
		assert(mtllib_buffer_free(sig) == MTLLIB_OK);
	}

	mtllib_buffer_free(msg_buffer);
	mtllib_sign_free_handle(&handle);
	mtllib_key_free(ctx);

	return 0;
}
uint8_t mtltest_mtllib_sign_get_condensed_sig_null(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTL_HANDLE *handle = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	uint8_t msg[] = MTL_TEST_VECTOR_MSG;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	size_t secparam = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	size_t index = 0;
	MTLLIB_BUFFER *key_buffer = NULL;
	MTLLIB_BUFFER *sig = NULL;
	MTLLIB_BUFFER *msg_buffer = NULL;

	assert(mtllib_buffer_initialize(&sig, MTL_TEST_VECTOR_CONDENSED_SIG_LEN, NULL) == MTLLIB_OK);;
	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);;
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_free(key_buffer) == MTLLIB_OK);	
	assert(mtllib_buffer_initialize(&msg_buffer, msg_len, msg) == MTLLIB_OK);

	assert(mtllib_sign_append(ctx, msg_buffer, &handle) == MTLLIB_OK);
	assert(&handle != NULL);
	assert(handle->leaf_index == index);
	assert(handle->sid_len == 2*secparam);
	assert(memcmp(handle->sid, &sid[0], 2*secparam) == 0);

	assert(mtllib_sign_get_condensed_sig(NULL, handle, sig) == MTLLIB_NULL_PARAMS);
	assert(sig->buffer_position == 0);
	assert(mtllib_sign_get_condensed_sig(ctx, NULL, sig) == MTLLIB_NULL_PARAMS);
	assert(sig->buffer_position == 0);
	assert(mtllib_sign_get_condensed_sig(ctx, handle, NULL) == MTLLIB_NULL_PARAMS);
	assert(sig->buffer_position == 0);
	assert(mtllib_buffer_free(sig) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&sig, 1, NULL) == MTLLIB_OK);
	assert(mtllib_sign_get_condensed_sig(ctx, handle, sig) == MTLLIB_BUFFER_ISSUE);
	assert(sig->buffer_position == 0);

	mtllib_buffer_free(sig);
	mtllib_buffer_free(msg_buffer);
	mtllib_sign_free_handle(&handle);
	mtllib_key_free(ctx);
	
	return 0;
}
uint8_t mtltest_mtllib_sign_get_signed_ladder(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTL_HANDLE *handle = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	uint8_t msg[] = MTL_TEST_VECTOR_MSG;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	size_t secparam = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	size_t num_messages = MTL_TEST_VECTOR_NUM_MESSAGES;
	size_t index = 0;
	MTLLIB_BUFFER *key_buffer = NULL;
	MTLLIB_BUFFER *ladder = NULL;
	MTLLIB_BUFFER *msg_buffer = NULL;
	size_t expected_ladder_len = 
		MTL_TEST_VECTOR_FULL_SIG_LEN
		- MTL_TEST_VECTOR_CONDENSED_SIG_LEN;
	size_t computed_ladder_len;

	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_free(key_buffer) == MTLLIB_OK);	
	assert(mtllib_buffer_initialize(&msg_buffer, msg_len, msg) == MTLLIB_OK);	

	for (index = 0; index < num_messages; index++)
	{
		if (handle != NULL)
		{
			mtllib_sign_free_handle(&handle);
			assert(handle == NULL);
		}
		assert(mtllib_sign_append(ctx, msg_buffer, &handle) == MTLLIB_OK);
		assert(&handle != NULL);
		assert(handle->leaf_index == index);
		assert(handle->sid_len == 2*secparam);
		assert(memcmp(handle->sid, &sid[0], 2*secparam) == 0);
	}
	mtllib_sign_free_handle(&handle);

	computed_ladder_len = mtllib_sign_get_signed_ladder_length(ctx);
	assert(computed_ladder_len == expected_ladder_len);
	assert(mtllib_buffer_initialize(&ladder, computed_ladder_len, NULL) == MTLLIB_OK);
	// 4 Rungs
	assert(mtllib_sign_get_signed_ladder(ctx, ladder) == MTLLIB_OK);
	// Signed ladder should be 36 byte header (flags & sid & rung_count) 4 rungs of 24 bytes (address & hash) 4 bytes signature length and signatures
	assert(ladder->buffer_length == expected_ladder_len);
	assert(ladder->buffer_position == expected_ladder_len);

	mtllib_buffer_free(msg_buffer);
	mtllib_buffer_free(ladder);
	mtllib_key_free(ctx);
	
	return 0;
}
uint8_t mtltest_mtllib_sign_get_signed_ladder_null(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTL_HANDLE *handle = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	uint8_t msg[] = MTL_TEST_VECTOR_MSG;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	size_t secparam = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	size_t num_messages = MTL_TEST_VECTOR_NUM_MESSAGES;
	size_t index = 0;
	MTLLIB_BUFFER *key_buffer = NULL;
	MTLLIB_BUFFER *ladder = NULL;
	MTLLIB_BUFFER *msg_buffer = NULL;
	size_t signed_ladder_length = MTL_TEST_VECTOR_FULL_SIG_LEN - MTL_TEST_VECTOR_CONDENSED_SIG_LEN;

	assert(mtllib_buffer_initialize(&ladder, signed_ladder_length, NULL) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_free(key_buffer) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&msg_buffer, msg_len, msg) == MTLLIB_OK);

	for (index = 0; index < num_messages; index++)
	{
		if (handle != NULL)
		{
			mtllib_sign_free_handle(&handle);
			assert(handle == NULL);
		}
		assert(mtllib_sign_append(ctx, msg_buffer, &handle) == MTLLIB_OK);
		assert(&handle != NULL);
		assert(handle->leaf_index == index);
		assert(handle->sid_len == 2*secparam);
		assert(memcmp(handle->sid, &sid[0], 2*secparam) == 0);
	}
	mtllib_sign_free_handle(&handle);

	assert(mtllib_sign_get_signed_ladder(NULL, ladder) == MTLLIB_NULL_PARAMS);
	assert(ladder->buffer_position == 0); 
	assert(mtllib_sign_get_signed_ladder(ctx, NULL) == MTLLIB_NULL_PARAMS);
	assert(ladder->buffer_position == 0); 
	assert(mtllib_buffer_free(ladder) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&ladder, 1, NULL) == MTLLIB_OK);
	assert(mtllib_sign_get_signed_ladder(ctx, ladder) == MTLLIB_BUFFER_ISSUE);
	assert(ladder->buffer_position == 0); 

	mtllib_buffer_free(msg_buffer);
	mtllib_buffer_free(ladder);
	mtllib_key_free(ctx);
	
	return 0;
}
uint8_t mtltest_mtllib_sign_get_full_sig(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTL_HANDLE *handle = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	uint8_t msg[] = MTL_TEST_VECTOR_MSG;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	size_t secparam = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	size_t num_messages = MTL_TEST_VECTOR_NUM_MESSAGES;
	size_t index = 0;
	MTLLIB_BUFFER *key_buffer = NULL;
	MTLLIB_BUFFER *sig = NULL;
	MTLLIB_BUFFER *msg_buffer = NULL;
	size_t expected_siglen = MTL_TEST_VECTOR_FULL_SIG_LEN;
	size_t computed_siglen;

	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&msg_buffer, msg_len, msg) == MTLLIB_OK);

	for (index = 0; index < num_messages; index++)
	{
		if (handle != NULL)
		{
			mtllib_sign_free_handle(&handle);
			assert(handle == NULL);
		}
		assert(mtllib_sign_append(ctx, msg_buffer, &handle) == MTLLIB_OK);
		assert(&handle != NULL);
		assert(handle->leaf_index == index);
		assert(handle->sid_len == 2*secparam);
		assert(memcmp(handle->sid, &sid[0], 2*secparam) == 0);
	}

	handle->leaf_index = 13;

	computed_siglen = mtllib_sign_get_full_sig_length(ctx, handle);
	assert(computed_siglen == expected_siglen);
	assert(mtllib_buffer_initialize(&sig, computed_siglen, NULL) == MTLLIB_OK);
	assert(mtllib_sign_get_full_sig(ctx, handle, sig) == MTLLIB_OK);
	assert(sig->buffer_position == expected_siglen); 

	mtllib_buffer_free(msg_buffer);
	mtllib_buffer_free(sig);
	mtllib_buffer_free(key_buffer);
	mtllib_sign_free_handle(&handle);
	mtllib_key_free(ctx);
	return 0;
}
uint8_t mtltest_mtllib_sign_get_full_sig_null(void)
{
	MTLLIB_CTX *ctx = NULL;
	MTL_HANDLE *handle = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t key_buffer_len = MTL_TEST_VECTOR_KEYBUFFER_LEN;
	uint8_t key_buffer_bytes[] = MTL_TEST_VECTOR_KEYBUFFER;
	uint8_t msg[] = MTL_TEST_VECTOR_MSG;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	size_t secparam = MTL_TEST_VECTOR_SCHEME_SECPARAM;
	size_t index = 0;
	MTLLIB_BUFFER *key_buffer = NULL;
	MTLLIB_BUFFER *sig = NULL;
	MTLLIB_BUFFER *msg_buffer = NULL;
	size_t expected_siglen = MTL_TEST_VECTOR_FULL_SIG_LEN;
	
	assert(mtllib_buffer_initialize(&key_buffer, key_buffer_len, key_buffer_bytes) == MTLLIB_OK);
	assert(mtllib_key_from_buffer(key_buffer, &ctx) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&msg_buffer, msg_len, msg) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&sig, expected_siglen, NULL) == MTLLIB_OK);

	for (index = 0; index < 15; index++)
	{
		if (handle != NULL)
		{
			mtllib_sign_free_handle(&handle);
			assert(handle == NULL);
		}
		assert(mtllib_sign_append(ctx, msg_buffer, &handle) == MTLLIB_OK);
		assert(&handle != NULL);
		assert(handle->leaf_index == index);
		assert(handle->sid_len == 2*secparam);
		assert(memcmp(handle->sid, &sid[0], 2*secparam) == 0);
	}

	handle->leaf_index = 5;
	assert(mtllib_sign_get_full_sig(NULL, handle, sig) == MTLLIB_NULL_PARAMS);
	assert(sig->buffer_position == 0);
	assert(mtllib_sign_get_full_sig(ctx, NULL, sig) == MTLLIB_NULL_PARAMS);
	assert(sig->buffer_position == 0);
	assert(mtllib_sign_get_full_sig(ctx, handle, NULL) == MTLLIB_NULL_PARAMS);
	assert(sig->buffer_position == 0);
	mtllib_buffer_free(sig);
	assert(mtllib_buffer_initialize(&sig, 1, NULL) == MTLLIB_OK);
	assert(mtllib_sign_get_full_sig(ctx, handle, sig) == MTLLIB_BUFFER_ISSUE);
	assert(sig->buffer_position == 0);

	mtllib_buffer_free(msg_buffer);
	mtllib_buffer_free(sig);
	mtllib_buffer_free(key_buffer);
	mtllib_sign_free_handle(&handle);
	mtllib_key_free(ctx);
	
	return 0;
}

uint8_t mtltest_mtllib_verify_condensed(void) {
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	uint8_t pubkey[] = MTL_TEST_VECTOR_PUBKEY;
	size_t pubkey_len = MTL_TEST_VECTOR_PUBKEY_LEN;
	size_t authpath_len = MTL_TEST_VECTOR_CONDENSED_SIG_LEN;
	uint8_t authpath_raw[] = MTL_TEST_VECTOR_CONDENSED_SIG;
	uint8_t authpath_ctx_raw[] = MTL_TEST_VECTOR_CONDENSED_SIG_CTX;
	size_t unsigned_ladder_len = MTL_TEST_VECTOR_UNSIGNED_LADDER_LEN;
	uint8_t unsigned_ladder_raw[] = MTL_TEST_VECTOR_UNSIGNED_LADDER;
	uint8_t unsigned_ladder_ctx_raw[] = MTL_TEST_VECTOR_UNSIGNED_LADDER_CTX;

	size_t condensed_len = 0;
	uint8_t msg_raw[] = MTL_TEST_VECTOR_MSG;
	uint8_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	uint8_t ctx_raw[] = MTL_TEST_VECTOR_CTX;
	uint8_t ctx_len = MTL_TEST_VECTOR_CTX_LEN;

	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_BUFFER *msg = NULL;
	MTLLIB_BUFFER *ctx_str = NULL;
	MTLLIB_BUFFER *sig = NULL;
	MTLLIB_BUFFER *unsigned_ladder = NULL;
	assert(mtllib_buffer_initialize(&msg, msg_len, msg_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&sig, authpath_len, authpath_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&unsigned_ladder, unsigned_ladder_len, unsigned_ladder_raw) == MTLLIB_OK);

	assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len, pubkey) == MTLLIB_OK);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, sid) == MTLLIB_OK);
		
	assert(mtllib_verify(ctx, msg, sig, unsigned_ladder, &condensed_len) == MTLLIB_OK);
	assert(condensed_len == authpath_len);
	assert(mtllib_verify(ctx, msg, sig, unsigned_ladder, NULL) == MTLLIB_OK);

	mtllib_buffer_free(sig);
	mtllib_buffer_free(unsigned_ladder);

	// Re-test with ctx_str
	assert(mtllib_buffer_initialize(&ctx_str, ctx_len, ctx_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&sig, authpath_len, authpath_ctx_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&unsigned_ladder, unsigned_ladder_len, unsigned_ladder_ctx_raw) == MTLLIB_OK);

	assert(mtllib_verify_with_ctx_str(ctx, msg, ctx_str, sig, unsigned_ladder, &condensed_len) == MTLLIB_OK);
	assert(condensed_len == authpath_len);
	assert(mtllib_verify_with_ctx_str(ctx, msg, ctx_str, sig, unsigned_ladder, NULL) == MTLLIB_OK);

	/* Reject if no ctx_str */
	assert(mtllib_verify(ctx, msg, sig, unsigned_ladder, &condensed_len) == MTLLIB_NO_LADDER);
	assert(mtllib_verify(ctx, msg, sig, unsigned_ladder, NULL) == MTLLIB_NO_LADDER);
	/* Reject if wrong ctx_str */
	mtllib_buffer_data_ptr(ctx_str)[mtllib_buffer_in_use(ctx_str)/2]++;
	assert(mtllib_verify_with_ctx_str(ctx, msg, ctx_str, sig, unsigned_ladder, &condensed_len) == MTLLIB_NO_LADDER);
	assert(mtllib_verify_with_ctx_str(ctx, msg, ctx_str, sig, unsigned_ladder, NULL) == MTLLIB_NO_LADDER);

	mtllib_key_free(ctx);
	mtllib_buffer_free(pubkey_buffer);
	mtllib_buffer_free(msg);
	mtllib_buffer_free(sig);
	mtllib_buffer_free(ctx_str);
	mtllib_buffer_free(unsigned_ladder);
	return 0;
}

uint8_t mtltest_mtllib_verify_condensed_no_ladder(void) {
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	uint8_t pubkey[] = MTL_TEST_VECTOR_PUBKEY;
	size_t pubkey_len = MTL_TEST_VECTOR_PUBKEY_LEN;
	size_t authpath_len = MTL_TEST_VECTOR_CONDENSED_SIG_LEN;
	uint8_t authpath_raw[] = MTL_TEST_VECTOR_CONDENSED_SIG;

	uint8_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	uint8_t msg_raw[] = MTL_TEST_VECTOR_MSG;

	size_t condensed_len = 0;
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_BUFFER *msg = NULL;
	MTLLIB_BUFFER *sig = NULL;
	assert(mtllib_buffer_initialize(&msg, msg_len, msg_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&sig, authpath_len, authpath_raw) == MTLLIB_OK);

	assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len, pubkey) == MTLLIB_OK);
	memset(&sid[0], 0x55, 8);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, sid) == MTLLIB_OK);
		
	assert(mtllib_verify(ctx, msg, sig, NULL, NULL) == MTLLIB_NO_LADDER);
	assert(mtllib_verify(ctx, msg, sig, NULL, &condensed_len) == MTLLIB_NO_LADDER);
	assert(condensed_len == authpath_len);

	mtllib_key_free(ctx);
	mtllib_buffer_free(pubkey_buffer);
	mtllib_buffer_free(msg);
	mtllib_buffer_free(sig);
	return 0;
}

uint8_t mtltest_mtllib_verify_full(void) {
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t pubkey_len = MTL_TEST_VECTOR_PUBKEY_LEN;
	uint8_t pubkey[] = MTL_TEST_VECTOR_PUBKEY;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	uint8_t msg_raw[] = MTL_TEST_VECTOR_MSG;
	size_t ctx_str_len = MTL_TEST_VECTOR_CTX_LEN;
	uint8_t ctx_str_raw[] = MTL_TEST_VECTOR_CTX;

	size_t full_signature_len = MTL_TEST_VECTOR_FULL_SIG_LEN;
	uint8_t full_signature_raw[] = MTL_TEST_VECTOR_FULL_SIG;
	uint8_t full_signature_ctx_raw[] = MTL_TEST_VECTOR_FULL_SIG_CTX;
	size_t expected_condensed_len = MTL_TEST_VECTOR_CONDENSED_SIG_LEN;
	size_t condensed_len = 0;
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_BUFFER *msg = NULL;
	MTLLIB_BUFFER *sig = NULL;
	MTLLIB_BUFFER *ctx_str = NULL;

	size_t authpath_leaf_index_offset = 42;

	assert(mtllib_buffer_initialize(&msg, msg_len, msg_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&sig, full_signature_len, full_signature_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len, pubkey) == MTLLIB_OK);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, sid) == MTLLIB_OK);
		
	assert(mtllib_verify(ctx, msg, sig, NULL, NULL) == MTLLIB_OK_VALIDATED_LADDER);
	assert(mtllib_verify(ctx, msg, sig, NULL, &condensed_len) == MTLLIB_OK_VALIDATED_LADDER);
	assert(condensed_len == expected_condensed_len);

	/* underlying signature failure */
	mtllib_buffer_data_ptr(sig)[full_signature_len-1]++;
	assert(mtllib_verify(ctx, msg, sig, NULL, NULL) == MTLLIB_BOGUS_CRYPTO);
	mtllib_buffer_data_ptr(sig)[full_signature_len-1]--;

	/* bad reconstruction */
	memset(mtllib_buffer_data_ptr(sig)+authpath_leaf_index_offset, 0, 3*MTL_INDEX_LEN); // set leaf and target to node [0:0]
	assert(mtllib_verify(ctx, msg, sig, NULL, NULL) == MTLLIB_BOGUS_CRYPTO);


	// Re-test with ctx_str
	mtllib_buffer_free(sig);
	assert(mtllib_buffer_initialize(&ctx_str, ctx_str_len, ctx_str_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&sig, full_signature_len, full_signature_ctx_raw) == MTLLIB_OK);

	assert(mtllib_verify_with_ctx_str(ctx, msg, ctx_str, sig, NULL, NULL) == MTLLIB_OK_VALIDATED_LADDER);
	assert(mtllib_verify_with_ctx_str(ctx, msg, ctx_str, sig, NULL, &condensed_len) == MTLLIB_OK_VALIDATED_LADDER);
	assert(condensed_len == expected_condensed_len);

	/* Reject if no ctx_str */
	assert(mtllib_verify(ctx, msg, sig, NULL, NULL) == MTLLIB_BOGUS_CRYPTO);
	assert(mtllib_verify(ctx, msg, sig, NULL, &condensed_len) == MTLLIB_BOGUS_CRYPTO);
	/* Reject if wrong ctx_str */
	mtllib_buffer_data_ptr(ctx_str)[mtllib_buffer_in_use(ctx_str)/2]++;
	assert(mtllib_verify(ctx, msg, sig, NULL, NULL) == MTLLIB_BOGUS_CRYPTO);
	assert(mtllib_verify(ctx, msg, sig, NULL, &condensed_len) == MTLLIB_BOGUS_CRYPTO);
	mtllib_buffer_data_ptr(ctx_str)[mtllib_buffer_in_use(ctx_str)/2]--;

	/* underlying signature failure */
	mtllib_buffer_data_ptr(sig)[full_signature_len-1]++;
	assert(mtllib_verify(ctx, msg, sig, NULL, NULL) == MTLLIB_BOGUS_CRYPTO);
	mtllib_buffer_data_ptr(sig)[full_signature_len-1]--;

	/* bad reconstruction */
	memset(mtllib_buffer_data_ptr(sig)+authpath_leaf_index_offset, 0, 3*MTL_INDEX_LEN); // set leaf and target to node [0:0]
	assert(mtllib_verify(ctx, msg, sig, NULL, NULL) == MTLLIB_BOGUS_CRYPTO);

	mtllib_key_free(ctx);
	mtllib_buffer_free(pubkey_buffer);
	mtllib_buffer_free(msg);
	mtllib_buffer_free(sig);
	mtllib_buffer_free(ctx_str);
	return 0;
}

uint8_t mtltest_mtllib_verify_null(void) {
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t pubkey_len = MTL_TEST_VECTOR_PUBKEY_LEN;
	uint8_t pubkey[] = MTL_TEST_VECTOR_PUBKEY;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	uint8_t msg_raw[] = MTL_TEST_VECTOR_MSG;
	size_t unsigned_ladder_len = MTL_TEST_VECTOR_UNSIGNED_LADDER_LEN;
	uint8_t unsigned_ladder_raw[] = MTL_TEST_VECTOR_UNSIGNED_LADDER;
	size_t authpath_len = MTL_TEST_VECTOR_CONDENSED_SIG_LEN;
	uint8_t authpath_raw[] = MTL_TEST_VECTOR_CONDENSED_SIG;
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_BUFFER *msg = NULL;
	MTLLIB_BUFFER *authpath = NULL;
	MTLLIB_BUFFER *unsigned_ladder = NULL;


	assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len, pubkey) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&msg, msg_len, msg_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&authpath, authpath_len, authpath_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&unsigned_ladder, unsigned_ladder_len, unsigned_ladder_raw) == MTLLIB_OK);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, sid) == MTLLIB_OK);

	assert(mtllib_verify(NULL, msg, authpath, unsigned_ladder, NULL) == MTLLIB_NULL_PARAMS);
	assert(mtllib_verify(ctx, NULL, authpath, unsigned_ladder, NULL) == MTLLIB_NULL_PARAMS);
	assert(mtllib_verify(ctx, msg, NULL, unsigned_ladder, NULL) == MTLLIB_NULL_PARAMS);

	mtllib_buffer_free(pubkey_buffer);
	mtllib_buffer_free(msg);
	mtllib_buffer_free(authpath);
	mtllib_buffer_free(unsigned_ladder);
	mtllib_key_free(ctx);
	return 0;
}

uint8_t mtltest_mtllib_verify_unparseable(void) {
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t pubkey_len = MTL_TEST_VECTOR_PUBKEY_LEN;
	uint8_t pubkey[] = MTL_TEST_VECTOR_PUBKEY;
	size_t msg_len = MTL_TEST_VECTOR_MSG_LEN;
	uint8_t msg_raw[] = MTL_TEST_VECTOR_MSG;
	size_t unsigned_ladder_len = MTL_TEST_VECTOR_UNSIGNED_LADDER_LEN;
	uint8_t unsigned_ladder_raw[] = MTL_TEST_VECTOR_UNSIGNED_LADDER;
	size_t authpath_len = MTL_TEST_VECTOR_CONDENSED_SIG_LEN;
	uint8_t authpath_raw[] = MTL_TEST_VECTOR_CONDENSED_SIG;
	size_t full_signature_len = MTL_TEST_VECTOR_FULL_SIG_LEN;
	uint8_t full_signature_raw[] = MTL_TEST_VECTOR_FULL_SIG;
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_BUFFER *msg = NULL;
	MTLLIB_BUFFER *authpath = NULL;
	MTLLIB_BUFFER *unsigned_ladder = NULL;
	MTLLIB_BUFFER *full_sig = NULL;
	MTLLIB_BUFFER *bad_authpath = NULL;
	MTLLIB_BUFFER *bad_unsigned_ladder = NULL;
	MTLLIB_BUFFER *bad_full_sig = NULL;


	assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len, pubkey) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&msg, msg_len, msg_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&authpath, authpath_len, authpath_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&unsigned_ladder, unsigned_ladder_len, unsigned_ladder_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&full_sig, full_signature_len, full_signature_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&bad_authpath, authpath_len-1, authpath_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&bad_unsigned_ladder, unsigned_ladder_len-1, unsigned_ladder_raw) == MTLLIB_OK);
	assert(mtllib_buffer_initialize(&bad_full_sig, authpath_len + unsigned_ladder_len - 1, full_signature_raw) == MTLLIB_OK);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, sid) == MTLLIB_OK);

	// Unparseable condensed signature
	assert(mtllib_verify(ctx, msg, bad_authpath, unsigned_ladder, NULL) == MTLLIB_BAD_VALUE);
	assert(mtllib_verify(ctx, msg, bad_authpath, NULL, NULL) == MTLLIB_BAD_VALUE);
	assert(mtllib_verify(ctx, msg, bad_authpath, bad_unsigned_ladder, NULL) == MTLLIB_BAD_VALUE);

	// Unparseable cached ladder
	assert(mtllib_verify(ctx, msg, authpath, bad_unsigned_ladder, NULL) == MTLLIB_NO_LADDER);
	assert(mtllib_verify(ctx, msg, full_sig, bad_unsigned_ladder, NULL) == MTLLIB_OK_VALIDATED_LADDER);

	// Unparseable ladder in full signature
	assert(mtllib_verify(ctx, msg, bad_full_sig, NULL, NULL) == MTLLIB_BAD_VALUE);


	mtllib_buffer_free(pubkey_buffer);
	mtllib_buffer_free(msg);
	mtllib_buffer_free(authpath);
	mtllib_buffer_free(unsigned_ladder);
	mtllib_buffer_free(full_sig);
	mtllib_buffer_free(bad_authpath);
	mtllib_buffer_free(bad_unsigned_ladder);
	mtllib_buffer_free(bad_full_sig);
	mtllib_key_free(ctx);
	return 0;
}

uint8_t mtltest_mtllib_verify_signed_ladder(void) {
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t pubkey_len = MTL_TEST_VECTOR_PUBKEY_LEN;
	uint8_t pubkey[] = MTL_TEST_VECTOR_PUBKEY;
	size_t authpath_len = MTL_TEST_VECTOR_CONDENSED_SIG_LEN;

	size_t full_signature_len = MTL_TEST_VECTOR_FULL_SIG_LEN;
	uint8_t full_signature[] = MTL_TEST_VECTOR_FULL_SIG;

	size_t signed_ladder_len = full_signature_len - authpath_len;
	uint8_t* signed_ladder = full_signature + authpath_len;
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_BUFFER *signed_ladder_buffer = NULL;

	assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len, pubkey) == MTLLIB_OK);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, sid) == MTLLIB_OK);

	assert(mtllib_buffer_initialize(&signed_ladder_buffer, signed_ladder_len, signed_ladder) == MTLLIB_OK);		
	assert(mtllib_verify_signed_ladder(ctx, signed_ladder_buffer) == MTLLIB_OK);

	mtllib_key_free(ctx);
	mtllib_buffer_free(pubkey_buffer);
	mtllib_buffer_free(signed_ladder_buffer);
	return 0;
}

uint8_t mtltest_mtllib_verify_signed_ladder_no_sig(void) {
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t pubkey_len = MTL_TEST_VECTOR_PUBKEY_LEN;
	uint8_t pubkey[] = MTL_TEST_VECTOR_PUBKEY;

	size_t unsigned_ladder_len = MTL_TEST_VECTOR_UNSIGNED_LADDER_LEN;
	uint8_t unsigned_ladder[] = MTL_TEST_VECTOR_UNSIGNED_LADDER;
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_BUFFER *unsigned_ladder_buffer = NULL;

	assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len, pubkey) == MTLLIB_OK);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, sid) == MTLLIB_OK);

	assert(mtllib_buffer_initialize(&unsigned_ladder_buffer, unsigned_ladder_len, unsigned_ladder) == MTLLIB_OK);		
	assert(mtllib_verify_signed_ladder(ctx, unsigned_ladder_buffer) == MTLLIB_INDETERMINATE);

	mtllib_key_free(ctx);
	mtllib_buffer_free(pubkey_buffer);
	mtllib_buffer_free(unsigned_ladder_buffer);
	return 0;
}

uint8_t mtltest_mtllib_verify_signed_ladder_corrupt(void) {
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t pubkey_len = MTL_TEST_VECTOR_PUBKEY_LEN;
	uint8_t pubkey[] = MTL_TEST_VECTOR_PUBKEY;
	size_t authpath_len = MTL_TEST_VECTOR_CONDENSED_SIG_LEN;

	size_t full_signature_len = MTL_TEST_VECTOR_FULL_SIG_LEN;
	uint8_t full_signature[] = MTL_TEST_VECTOR_FULL_SIG;

	size_t signed_ladder_len = full_signature_len - authpath_len;
	uint8_t* signed_ladder = full_signature + authpath_len;
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_BUFFER *full_signature_buffer = NULL;

	assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len, pubkey) == MTLLIB_OK);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, sid) == MTLLIB_OK);

	signed_ladder[signed_ladder_len/2]++;
	assert(mtllib_buffer_initialize(&full_signature_buffer, full_signature_len, full_signature) == MTLLIB_OK);		
	assert(mtllib_verify_signed_ladder(ctx, full_signature_buffer) == MTLLIB_BOGUS_CRYPTO);

	mtllib_key_free(ctx);
	mtllib_buffer_free(pubkey_buffer);
	mtllib_buffer_free(full_signature_buffer);
	return 0;
}

uint8_t mtltest_mtllib_verify_signed_ladder_null(void) {
	MTLLIB_CTX *ctx = NULL;
	uint8_t sid[] = MTL_TEST_VECTOR_SID;
	size_t pubkey_len = MTL_TEST_VECTOR_PUBKEY_LEN;
	uint8_t pubkey[] = MTL_TEST_VECTOR_PUBKEY;

	size_t unsigned_ladder_len = MTL_TEST_VECTOR_UNSIGNED_LADDER_LEN;
	uint8_t unsigned_ladder[] = MTL_TEST_VECTOR_UNSIGNED_LADDER;
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_BUFFER *unsigned_ladder_buffer = NULL;

	assert(mtllib_buffer_initialize(&pubkey_buffer, pubkey_len, pubkey) == MTLLIB_OK);
	assert(mtllib_pubkey_from_buffer(MTL_TEST_VECTOR_SCHEME_NAME, &ctx, pubkey_buffer, sid) == MTLLIB_OK);
	
	assert(mtllib_buffer_initialize(&unsigned_ladder_buffer, unsigned_ladder_len, unsigned_ladder) == MTLLIB_OK);	
	assert(mtllib_verify_signed_ladder(NULL, unsigned_ladder_buffer) == MTLLIB_NULL_PARAMS);
	assert(mtllib_verify_signed_ladder(ctx, NULL) == MTLLIB_NULL_PARAMS);

	mtllib_key_free(ctx);
	mtllib_buffer_free(pubkey_buffer);
	mtllib_buffer_free(unsigned_ladder_buffer);
	return 0;
}

