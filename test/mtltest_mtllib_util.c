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
#include "mtllib_util.h"

// Prototypes for testing functions
uint8_t mtlltest_mtllib_util_get_algorithm_props_valid(void);
uint8_t mtlltest_mtllib_util_get_algorithm_props_invalid(void);
uint8_t mtlltest_mtllib_util_get_algorithm_props_null(void);
uint8_t mtlltest_mtllib_key_write_algorithms(void);
uint8_t mtlltest_mtllib_util_setup_sig_scheme(void);
uint8_t mtlltest_mtllib_util_setup_sig_scheme_bad_library(void);
uint8_t mtlltest_mtllib_util_setup_sig_scheme_null_context(void);
uint8_t mtlltest_mtllib_util_setup_sig_scheme_with_keys_provided(void);
uint8_t mtlltest_mtllib_util_setup_sig_scheme_with_keys_provided_mismatch(void);
uint8_t mtlltest_mtllib_util_buffer_read_bytes(void);
uint8_t mtlltest_mtllib_util_buffer_read_bytes_min_max(void);
uint8_t mtlltest_mtllib_util_buffer_read_bytes_null(void);
uint8_t mtlltest_mtllib_util_buffer_write_bytes(void);
uint8_t mtlltest_mtllib_util_buffer_write_bytes_min_max(void);
uint8_t mtlltest_mtllib_util_buffer_write_bytes_null(void);

uint8_t mtltest_mtllib_util(void)
{
    NEW_TEST("MTL Library Utility Tests");

    RUN_TEST(mtlltest_mtllib_util_get_algorithm_props_valid,
             "Verify MTL library get algorithm properties function");
    RUN_TEST(mtlltest_mtllib_key_write_algorithms,
             "Verify MTL library write all algorithms to *FP function");
    RUN_TEST(mtlltest_mtllib_util_setup_sig_scheme,
             "Verify MTL library setup the signature scheme");
    RUN_TEST(mtlltest_mtllib_util_setup_sig_scheme_bad_library,
             "Verify MTL library setup the signature scheme with bad library");
    RUN_TEST(mtlltest_mtllib_util_setup_sig_scheme_null_context,
             "Verify MTL library setup the signature scheme with null context");
    RUN_TEST(mtlltest_mtllib_util_setup_sig_scheme_with_keys_provided,
             "Verify MTL library setup the signature scheme with given keys");
    RUN_TEST(mtlltest_mtllib_util_setup_sig_scheme_with_keys_provided_mismatch,
             "Verify MTL library setup the signature scheme with given keys that do not match");
    RUN_TEST(mtlltest_mtllib_util_buffer_read_bytes,
             "Verify MTL library read key from buffer function");
    RUN_TEST(mtlltest_mtllib_util_buffer_read_bytes_min_max,
             "Verify MTL library read key from buffer function with min/max values");
    RUN_TEST(mtlltest_mtllib_util_buffer_read_bytes_null,
             "Verify MTL library read key from buffer function with null parameters");
    RUN_TEST(mtlltest_mtllib_util_buffer_write_bytes,
             "Verify MTL library write key to buffer function");
    RUN_TEST(mtlltest_mtllib_util_buffer_write_bytes_min_max,
             "Verify MTL library write key to buffer function with min/max values");
    RUN_TEST(mtlltest_mtllib_util_buffer_write_bytes_null,
             "Verify MTL library write key to buffer function with null parameters");

    return 0;
}

extern MTL_ALGORITHM_PROPS sig_algos[];

/**
 * Test the MTL library get algorithm properties function
 *    with valid algorithm strings.
 */
uint8_t mtlltest_mtllib_util_get_algorithm_props_valid(void)
{
	size_t algo = 0;

	while (sig_algos[algo].name != NULL)
	{
		assert(mtllib_util_get_algorithm_props(sig_algos[algo].name) == &sig_algos[algo]);
		algo++;
	}
	return 0;
}

/**
 * Test the MTL library get algorithm properties function
 *    with invalid algorithm strings.
 */
uint8_t mtlltest_mtllib_util_get_algorithm_props_invalid(void)
{
	assert(mtllib_util_get_algorithm_props("SPHINCS+") == NULL);
	assert(mtllib_util_get_algorithm_props("SLH-DSA-MTL-SHAKE-128R") == NULL);
	return 0;
}

/**
 * Test the MTL library get algorithm properties function
 *    with null algorithm strings.
 */
uint8_t mtlltest_mtllib_util_get_algorithm_props_null(void)
{
	assert(mtllib_util_get_algorithm_props(NULL) == NULL);
	return 0;
}

/**
 * Test the MTL library write algorithm names function.
 */
uint8_t mtlltest_mtllib_key_write_algorithms(void)
{
	char *algo_buffer = NULL;
	size_t algo_buffer_len = 0;
	FILE *test_file = NULL;
	char output[] = "\
      SLH-DSA-MTL-SHAKE-128S\n      SLH-DSA-MTL-SHAKE-128F\n\
      SLH-DSA-MTL-SHAKE-192S\n      SLH-DSA-MTL-SHAKE-192F\n\
      SLH-DSA-MTL-SHAKE-256S\n      SLH-DSA-MTL-SHAKE-256F\n\
      SLH-DSA-MTL-SHA2-128S\n      SLH-DSA-MTL-SHA2-128F\n\
      SLH-DSA-MTL-SHA2-192S\n      SLH-DSA-MTL-SHA2-192F\n\
      SLH-DSA-MTL-SHA2-256S\n      SLH-DSA-MTL-SHA2-256F\n";

	test_file = open_memstream(&algo_buffer, &algo_buffer_len);
	assert(test_file != NULL);
	assert(mtllib_key_write_algorithms(test_file) == MTLLIB_OK);
	fclose(test_file);

	assert(algo_buffer_len == strlen(output));
	assert(memcmp(output, algo_buffer, algo_buffer_len) == 0);

	free(algo_buffer);
	return 0;

}

/**
 * Test the MTL library write algorithm names function with
 *      null parameters.
 */
uint8_t mtlltest_mtllib_key_write_algorithms_null(void)
{
	assert(mtllib_key_write_algorithms(NULL) == MTLLIB_NULL_PARAMS);
	return 0;
}

/**
 * Test the MTL library signature setup scheme function
 */
uint8_t mtlltest_mtllib_util_setup_sig_scheme(void)
{
	MTLLIB_CTX *test_ctx = NULL;
	SEED seed;
	SERIESID sid;
	size_t index;
	uint32_t zero_count;

	// Setup variables
	test_ctx = calloc(1, sizeof(MTLLIB_CTX));
	test_ctx->algo_params = mtllib_util_get_algorithm_props("SLH-DSA-MTL-SHAKE-128S");

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;
	memset(&seed, 0xAA, sizeof(SEED));

	seed.length = 32;
	memset(seed.seed, 0xAA, 32);

	assert(test_ctx->signature == NULL);
	assert(test_ctx->secret_key == NULL);
	assert(test_ctx->secret_key_len == 0);
	assert(test_ctx->public_key == NULL);
	assert(test_ctx->public_key_len == 0);
	assert(test_ctx->mtl == NULL);

	// Test making a new key from scratch without a context string
	assert(mtllib_util_setup_sig_scheme(LIBOQS, test_ctx, NULL, 0, NULL, 0, NULL, NULL, NULL) == MTLLIB_OK);
	assert(test_ctx->signature != NULL);
	assert(test_ctx->secret_key != NULL);
	zero_count = 0;
	for (index = 0; index < test_ctx->secret_key_len; index++)
	{
		if (test_ctx->secret_key[index] != 0)
		{
			zero_count++;
		}
	}
	assert(zero_count > 16);
	assert(test_ctx->secret_key_len == 64);
	assert(test_ctx->public_key != NULL);
	assert(test_ctx->public_key_len == 32);
	zero_count = 0;
	for (index = 0; index < test_ctx->public_key_len; index++)
	{
		if (test_ctx->public_key[index] != 0)
		{
			zero_count++;
		}
	}
	assert(zero_count > 16);
	assert(test_ctx->mtl != NULL);
	assert(test_ctx->mtl->ctx_str == NULL);
	mtllib_key_free(test_ctx);

	test_ctx = calloc(1, sizeof(MTLLIB_CTX));
	test_ctx->algo_params = mtllib_util_get_algorithm_props("SLH-DSA-MTL-SHAKE-128F");
	assert(test_ctx->signature == NULL);
	assert(test_ctx->secret_key == NULL);
	assert(test_ctx->secret_key_len == 0);
	assert(test_ctx->public_key == NULL);
	assert(test_ctx->public_key_len == 0);
	assert(test_ctx->mtl == NULL);

	// Test making a new key from scratch with a context string
	assert(mtllib_util_setup_sig_scheme(LIBOQS, test_ctx, NULL, 0, NULL, 0, "Test", NULL, NULL) == MTLLIB_OK);
	assert(test_ctx->signature != NULL);
	assert(test_ctx->secret_key != NULL);
	assert(test_ctx->secret_key_len == 64);
	assert(test_ctx->public_key != NULL);
	assert(test_ctx->public_key_len == 32);
	assert(test_ctx->mtl != NULL);
	assert(test_ctx->mtl->ctx_str != NULL);
	mtllib_key_free(test_ctx);

	return 0;
}

/**
 * Test the MTL library signature setup scheme function with
 *         unsupported library providers.
 */
uint8_t mtlltest_mtllib_util_setup_sig_scheme_bad_library(void)
{
	MTLLIB_CTX *test_ctx = NULL;

	// Setup variables
	test_ctx = calloc(1, sizeof(MTLLIB_CTX));
	test_ctx->algo_params = mtllib_util_get_algorithm_props("SLH-DSA-MTL-SHAKE-128S");

	// Test making a new key from scratch without a context string with unsupported provider
	assert(mtllib_util_setup_sig_scheme(OPENSSL, test_ctx, NULL, 0, NULL, 0, NULL, NULL, NULL) == MTLLIB_UNSUPPORTED_FEATURE);
	assert(mtllib_util_setup_sig_scheme(NONE, test_ctx, NULL, 0, NULL, 0, NULL, NULL, NULL) == MTLLIB_BAD_ALGORITHM);

	mtllib_key_free(test_ctx);
	return 0;
}

/**
 * Test the MTL library signature setup scheme function with
 *         a null context.
 */
uint8_t mtlltest_mtllib_util_setup_sig_scheme_null_context(void)
{
	MTLLIB_CTX *test_ctx = NULL;

	// Setup variables
	test_ctx = calloc(1, sizeof(MTLLIB_CTX));
	test_ctx->algo_params = mtllib_util_get_algorithm_props("SLH-DSA-MTL-SHAKE-128S");

	// Test making a new key from scratch without a context string with unsupported provider
	assert(mtllib_util_setup_sig_scheme(LIBOQS, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL) == MTLLIB_NULL_PARAMS);

	mtllib_key_free(test_ctx);
	return 0;
}

/**
 * Test the MTL library signature setup scheme function with
 *         a set of provided keys.
 */
uint8_t mtlltest_mtllib_util_setup_sig_scheme_with_keys_provided(void)
{
	MTLLIB_CTX *test_ctx = NULL;
	SEED seed;
	SERIESID sid;
	size_t index;
	uint8_t secret_key[64];
	uint8_t public_key[32];

	// Setup variables
	test_ctx = calloc(1, sizeof(MTLLIB_CTX));
	test_ctx->algo_params = mtllib_util_get_algorithm_props("SLH-DSA-MTL-SHAKE-128S");

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;
	memset(&seed, 0xAA, sizeof(SEED));

	seed.length = 32;
	memset(seed.seed, 0xAA, 32);

	memset(&secret_key[0], 0xCC, 64);
	memset(&public_key[0], 0x55, 32);
	assert(test_ctx->signature == NULL);
	assert(test_ctx->secret_key == NULL);
	assert(test_ctx->secret_key_len == 0);
	assert(test_ctx->public_key == NULL);
	assert(test_ctx->public_key_len == 0);
	assert(test_ctx->mtl == NULL);

	// Test making a new key from scratch without a context string
	assert(mtllib_util_setup_sig_scheme(LIBOQS, test_ctx, &secret_key[0], 64, &public_key[0], 32, NULL, &seed, &sid) == MTLLIB_OK);
	assert(test_ctx->signature != NULL);
	assert(test_ctx->secret_key != NULL);
	for (index = 0; index < test_ctx->secret_key_len; index++)
	{
		assert(secret_key[index] == test_ctx->secret_key[index]);
	}
	assert(test_ctx->secret_key_len == 64);
	assert(test_ctx->public_key != NULL);
	assert(test_ctx->public_key_len == 32);
	for (index = 0; index < test_ctx->public_key_len; index++)
	{
		assert(public_key[index] == test_ctx->public_key[index]);
	}
	assert(test_ctx->mtl != NULL);
	assert(test_ctx->mtl->ctx_str == NULL);
	mtllib_key_free(test_ctx);

	return 0;
}

/**
 * Test the MTL library signature setup scheme function with
 *         a set of provided keys that mismatch.
 */
uint8_t mtlltest_mtllib_util_setup_sig_scheme_with_keys_provided_mismatch(void)
{
	MTLLIB_CTX *test_ctx = NULL;
	SEED seed;
	SERIESID sid;
	uint8_t secret_key[64];
	uint8_t public_key[32];

	// Setup variables
	test_ctx = calloc(1, sizeof(MTLLIB_CTX));
	test_ctx->algo_params = mtllib_util_get_algorithm_props("SLH-DSA-MTL-SHAKE-128S");

	memset(&sid, 0, sizeof(SERIESID));
	sid.length = 8;
	memset(&seed, 0xAA, sizeof(SEED));

	seed.length = 32;
	memset(seed.seed, 0xAA, 32);

	memset(&secret_key[0], 0xCC, 64);
	memset(&public_key[0], 0x55, 32);
	assert(test_ctx->signature == NULL);
	assert(test_ctx->secret_key == NULL);
	assert(test_ctx->secret_key_len == 0);
	assert(test_ctx->public_key == NULL);
	assert(test_ctx->public_key_len == 0);
	assert(test_ctx->mtl == NULL);

	// Test making a new key from scratch without a context string
	assert(mtllib_util_setup_sig_scheme(LIBOQS, test_ctx, &secret_key[0], 32, &public_key[0], 16, NULL, &seed, &sid) == MTLLIB_MEMORY_ERROR);
	mtllib_key_free(test_ctx);

	return 0;
}

/**
 * Test the MTL library signature read buffer function
 */
uint8_t mtlltest_mtllib_util_buffer_read_bytes(void)
{
	uint8_t buffer[] = {0x00, 0x00, 0x00, 0x10, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xaf, 0xff};
	size_t buffer_len = 20;
	uint8_t *dest_ptr = NULL;
	size_t dest_len = 0;
	size_t index = 0;
	uint8_t *buffer_ptr = &buffer[0];

	assert(mtllib_util_buffer_read_bytes(&buffer_ptr, &buffer_len, &dest_ptr, &dest_len, 32, 0) == MTLLIB_OK);
	assert(dest_len == 20);
	assert(buffer_len == 0);
	assert(buffer_ptr == &buffer[20]);
	for(index=0; index<16; index++) {
		assert(dest_ptr[index] == buffer[index+4]);
	}
	free(dest_ptr);

	return 0;
}

/**
 * Test the MTL library signature read buffer function
 *         with boundary conditions
 */
uint8_t mtlltest_mtllib_util_buffer_read_bytes_min_max(void)
{
	uint8_t buffer_max[] = {0x00, 0x00, 0x00, 0x10, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xaf, 0xff};
	size_t buffer_len_max = 20;
	uint8_t buffer_min[] = {0x00, 0x00, 0x00, 0x02, 0xa0, 0xa1};
	size_t buffer_len_min = 6;	
	uint8_t *dest_ptr = NULL;
	size_t dest_len = 0;
	uint8_t *buffer_ptr = NULL;

	// Test max is bigger than buffer max
	buffer_ptr = &buffer_max[0];
	assert(mtllib_util_buffer_read_bytes(&buffer_ptr, &buffer_len_max, &dest_ptr, &dest_len, 8, 0) == MTLLIB_BAD_VALUE);
	assert(dest_len == 0);
	assert(buffer_len_max == 20);
	assert(buffer_ptr == &buffer_max[0]);
	assert(dest_ptr == NULL);

	// Test max is bigger min
	buffer_ptr = &buffer_max[0];	
	assert(mtllib_util_buffer_read_bytes(&buffer_ptr, &buffer_len_max, &dest_ptr, &dest_len, 8, 32) == MTLLIB_BAD_VALUE);
	assert(dest_len == 0);
	assert(buffer_len_max == 20);
	assert(buffer_ptr == &buffer_max[0]);
	assert(dest_ptr == NULL);

	// Test min is more than the buffer size
	buffer_ptr = &buffer_min[0];	
	assert(mtllib_util_buffer_read_bytes(&buffer_ptr, &buffer_len_min, &dest_ptr, &dest_len, 32, 8) == MTLLIB_BAD_VALUE);
	assert(dest_len == 0);
	assert(buffer_len_max == 20);
	assert(buffer_ptr == &buffer_min[0]);
	assert(dest_ptr == NULL);

	return 0;
}

/**
 * Test the MTL library signature read buffer function
 *         with null pointers
 */
uint8_t mtlltest_mtllib_util_buffer_read_bytes_null(void)
{
	uint8_t buffer[] = {0x00, 0x00, 0x00, 0x10, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xaf, 0xff};
	size_t buffer_len = 20;
	uint8_t *dest_ptr = NULL;
	size_t dest_len = 0;
	uint8_t *buffer_ptr = &buffer[0];

	assert(mtllib_util_buffer_read_bytes(NULL, &buffer_len, &dest_ptr, &dest_len, 32, 0) == MTLLIB_NULL_PARAMS);
	assert(dest_len == 0);
	assert(buffer_len == 20);
	assert(buffer_ptr == &buffer[0]);
	assert(dest_ptr == NULL);

	assert(mtllib_util_buffer_read_bytes(&buffer_ptr, NULL, &dest_ptr, &dest_len, 32, 0) == MTLLIB_NULL_PARAMS);
	assert(dest_len == 0);
	assert(buffer_len == 20);
	assert(buffer_ptr == &buffer[0]);
	assert(dest_ptr == NULL);

	assert(mtllib_util_buffer_read_bytes(&buffer_ptr, &buffer_len, NULL, &dest_len, 32, 0) == MTLLIB_NULL_PARAMS);
	assert(dest_len == 0);
	assert(buffer_len == 20);
	assert(buffer_ptr == &buffer[0]);
	assert(dest_ptr == NULL);

	assert(mtllib_util_buffer_read_bytes(&buffer_ptr, &buffer_len, &dest_ptr, NULL, 32, 0) == MTLLIB_NULL_PARAMS);
	assert(dest_len == 0);
	assert(buffer_len == 20);
	assert(buffer_ptr == &buffer[0]);
	assert(dest_ptr == NULL);

	return 0;
}

/**
 * Test the MTL library signature write buffer function
 *         with null pointers
 */
uint8_t mtlltest_mtllib_util_buffer_write_bytes(void)
{
	uint8_t source[] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xaf, 0xff};
	size_t source_len = 16;
	uint8_t buffer[256];
	size_t buffer_len = 256;
	size_t index = 0;
	uint8_t *buffer_ptr = &buffer[0];
	memset(buffer_ptr, 0, 256);

	assert(mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, &source[0], source_len, 32, 0) == MTLLIB_OK);
	assert(source_len == 16);
	assert(buffer_len == 236);
	assert(buffer_ptr == &buffer[20]);
	assert(buffer[0] == 0x00);
	assert(buffer[1] == 0x00);
	assert(buffer[2] == 0x00);
	assert(buffer[3] == 0x10);
	for(index=0; index<16; index++) {
		assert(source[index] == buffer[index+4]);
	}

	return 0;
}

/**
 * Test the MTL library signature write buffer function
 *         with min/max values
 */
uint8_t mtlltest_mtllib_util_buffer_write_bytes_min_max(void)
{
	uint8_t source[] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xaf, 0xff};
	size_t source_len = 16;
	uint8_t buffer[256];
	size_t buffer_len = 256;
	size_t index = 0;
	uint8_t *buffer_ptr = &buffer[0];
	memset(buffer_ptr, 0, 256);

	// Test max is bigger than buffer max
	assert(mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, &source[0], source_len, 8, 0) == MTLLIB_BAD_VALUE);
	assert(source_len == 16);
	assert(buffer_len == 256);
	assert(buffer_ptr == &buffer[0]);
	for(index=0; index<256; index++) {
		assert(buffer[index] == 0);
	}

	// Test max is bigger min
	assert(mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, &source[0], source_len, 8, 32) == MTLLIB_BAD_VALUE);
	assert(source_len == 16);
	assert(buffer_len == 256);
	assert(buffer_ptr == &buffer[0]);
	for(index=0; index<256; index++) {
		assert(buffer[index] == 0);
	}

	// Test min is more than the buffer size
	assert(mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, &source[0], source_len, 32, 20) == MTLLIB_BAD_VALUE);
	assert(source_len == 16);
	assert(buffer_len == 256);
	assert(buffer_ptr == &buffer[0]);
	for(index=0; index<256; index++) {
		assert(buffer[index] == 0);
	}	

	return 0;
}

/**
 * Test the MTL library signature write buffer function
 *         with null pointers
 */
uint8_t mtlltest_mtllib_util_buffer_write_bytes_null(void)
{
	uint8_t source[] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xaf, 0xff};
	size_t source_len = 16;
	uint8_t buffer[256];
	size_t buffer_len = 256;
	size_t index = 0;
	uint8_t *buffer_ptr = &buffer[0];
	memset(buffer_ptr, 0, 256);

	// Test max is bigger than buffer max
	assert(mtllib_util_buffer_write_bytes(NULL, &buffer_len, &source[0], source_len, 32, 0) == MTLLIB_NULL_PARAMS);
	assert(source_len == 16);
	assert(buffer_len == 256);
	assert(buffer_ptr == &buffer[0]);
	for(index=0; index<256; index++) {
		assert(buffer[index] == 0);
	}

	assert(mtllib_util_buffer_write_bytes(&buffer_ptr, NULL, &source[0], source_len, 32, 0) == MTLLIB_NULL_PARAMS);
	assert(source_len == 16);
	assert(buffer_len == 256);
	assert(buffer_ptr == &buffer[0]);
	for(index=0; index<256; index++) {
		assert(buffer[index] == 0);
	}

	assert(mtllib_util_buffer_write_bytes(&buffer_ptr, &buffer_len, NULL, source_len, 32, 0) == MTLLIB_NULL_PARAMS);
	assert(source_len == 16);
	assert(buffer_len == 256);
	assert(buffer_ptr == &buffer[0]);
	for(index=0; index<256; index++) {
		assert(buffer[index] == 0);
	}

	return 0;
}