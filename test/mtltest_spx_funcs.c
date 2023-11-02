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

// Prototypes for testing functions
uint8_t mtltest_spx_funcs_block_pad(void);
uint8_t mtltest_spx_funcs_mgf1_256(void);
uint8_t mtltest_spx_funcs_mgf1_512(void);
uint8_t mtltest_spx_funcs_sha256(void);
uint8_t mtltest_spx_funcs_sha512(void);
uint8_t mtltest_spx_funcs_shake256(void);

uint8_t mtltest_spx_funcs(void)
{
	NEW_TEST("MTL SPX Function Tests");

	RUN_TEST(mtltest_spx_funcs_block_pad, "Verify SHA2 block padding");
	RUN_TEST(mtltest_spx_funcs_mgf1_256, "Verify MGF1 256 bit function");
	RUN_TEST(mtltest_spx_funcs_mgf1_512, "Verify MGF1 512 bit function");
	RUN_TEST(mtltest_spx_funcs_sha256, "Verify SHA256 function");
	RUN_TEST(mtltest_spx_funcs_sha512, "Verify SHA512 function");
	RUN_TEST(mtltest_spx_funcs_shake256, "Verify SHAKE256 function");

	return 0;
}

/**
 * Test the MTL buffer set flags functions
 */
uint8_t mtltest_spx_funcs_block_pad(void)
{
	uint8_t data[] = { 0xaa, 0x55, 0xaa, 0x55,
		0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
		0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
		0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
		0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
		0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
		0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
		0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
		0xaa, 0x55, 0xaa, 0x55
	};
	uint8_t empty[64] = { 0x00 };
	uint8_t *buffer_ptr = NULL;

	// Test if there is one full block
	assert(block_pad(data, 32, 32, &buffer_ptr) == 32);
	assert(memcmp(buffer_ptr, &data[0], 32) == 0);
	free(buffer_ptr);

	// Ensure overflow block works correctly
	assert(block_pad(data, 35, 32, &buffer_ptr) == 64);
	assert(memcmp(buffer_ptr, &data[0], 35) == 0);
	assert(memcmp(buffer_ptr + 35, &empty[0], 29) == 0);
	free(buffer_ptr);

	// Test if there is less than one full block
	assert(block_pad(data, 16, 32, &buffer_ptr) == 32);
	assert(memcmp(buffer_ptr, &data[0], 16) == 0);
	assert(memcmp(buffer_ptr + 16, &empty[0], 16) == 0);
	free(buffer_ptr);

	// Test different block size
	assert(block_pad(data, 34, 8, &buffer_ptr) == 40);
	assert(memcmp(buffer_ptr, &data[0], 34) == 0);
	assert(memcmp(buffer_ptr + 34, &empty[0], 6) == 0);
	free(buffer_ptr);

	return 0;
}

/**
 * Test the MTL buffer set flags functions
 */
uint8_t mtltest_spx_funcs_mgf1_256(void)
{
	char *buffer = "Test Hash Message 123456";
	uint32_t buffer_len = 24;
	uint8_t out_buffer[1024];
	uint8_t result_16[] = { 0x5e, 0x23, 0x9d, 0x0f, 0x1a, 0x23, 0x28, 0xbb,
		0x0d, 0xab, 0x44, 0x3a, 0x0d, 0x84, 0x49, 0xf7
	};
	uint8_t result_32[] = { 0x5e, 0x23, 0x9d, 0x0f, 0x1a, 0x23, 0x28, 0xbb,
		0x0d, 0xab, 0x44, 0x3a, 0x0d, 0x84, 0x49, 0xf7,
		0x95, 0x48, 0x45, 0x43, 0x69, 0x8a, 0xd2, 0xb3,
		0x90, 0xcb, 0x40, 0x56, 0x4c, 0x73, 0x0d, 0xd1
	};
	uint8_t result_48[] = { 0x5e, 0x23, 0x9d, 0x0f, 0x1a, 0x23, 0x28, 0xbb,
		0x0d, 0xab, 0x44, 0x3a, 0x0d, 0x84, 0x49, 0xf7,
		0x95, 0x48, 0x45, 0x43, 0x69, 0x8a, 0xd2, 0xb3,
		0x90, 0xcb, 0x40, 0x56, 0x4c, 0x73, 0x0d, 0xd1,
		0x7b, 0xfc, 0x11, 0x83, 0xcb, 0x07, 0x17, 0x40,
		0xe3, 0xf5, 0xce, 0xe5, 0xfb, 0xc7, 0x64, 0xe4
	};
	uint8_t empty[EVP_MAX_MD_SIZE];
	memset(empty, 0, EVP_MAX_MD_SIZE);

	mgf1_256(&out_buffer[0], 16, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer[0], result_16, 16) == 0);

	mgf1_256(&out_buffer[0], 32, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer[0], result_32, 32) == 0);

	mgf1_256(&out_buffer[0], 48, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer[0], result_48, 48) == 0);

	// API is to follow SPHINCS so no return on these
	// just calling to make sure no core dumps or other issues
	memset(&out_buffer[0], 0, EVP_MAX_MD_SIZE);
	mgf1_256(NULL, 48, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	mgf1_256(&out_buffer[0], 0, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	mgf1_256(&out_buffer[0], 48, NULL, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	mgf1_256(&out_buffer[0], 48, (unsigned char *)buffer, 0);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);

	return 0;
}

/**
 * Test the MTL buffer set flags functions
 */
uint8_t mtltest_spx_funcs_mgf1_512(void)
{
	char *buffer = "Test Hash Message 123456";
	uint32_t buffer_len = 24;
	uint8_t out_buffer[1024];
	uint8_t result_32[] = { 0x60, 0x5e, 0x2b, 0x0b, 0x04, 0xfc, 0x16, 0xeb,
		0x4a, 0x1d, 0xd5, 0x6e, 0xb0, 0x8d, 0x40, 0xba,
		0x2a, 0xb9, 0xfd, 0xf9, 0x4d, 0xe3, 0x4d, 0xd3,
		0x61, 0x71, 0xbf, 0xd1, 0xd6, 0x51, 0xf7, 0x41
	};
	uint8_t result_48[] = { 0x60, 0x5e, 0x2b, 0x0b, 0x04, 0xfc, 0x16, 0xeb,
		0x4a, 0x1d, 0xd5, 0x6e, 0xb0, 0x8d, 0x40, 0xba,
		0x2a, 0xb9, 0xfd, 0xf9, 0x4d, 0xe3, 0x4d, 0xd3,
		0x61, 0x71, 0xbf, 0xd1, 0xd6, 0x51, 0xf7, 0x41,
		0x3a, 0x1a, 0xa7, 0x3e, 0x41, 0x20, 0x1b, 0xe7,
		0xe3, 0x80, 0xeb, 0x16, 0x4e, 0x74, 0x94, 0xed
	};
	uint8_t result_64[] = { 0x60, 0x5e, 0x2b, 0x0b, 0x04, 0xfc, 0x16, 0xeb,
		0x4a, 0x1d, 0xd5, 0x6e, 0xb0, 0x8d, 0x40, 0xba,
		0x2a, 0xb9, 0xfd, 0xf9, 0x4d, 0xe3, 0x4d, 0xd3,
		0x61, 0x71, 0xbf, 0xd1, 0xd6, 0x51, 0xf7, 0x41,
		0x3a, 0x1a, 0xa7, 0x3e, 0x41, 0x20, 0x1b, 0xe7,
		0xe3, 0x80, 0xeb, 0x16, 0x4e, 0x74, 0x94, 0xed,
		0xb0, 0x2b, 0x72, 0xb1, 0x6f, 0x62, 0x3d, 0x53,
		0x56, 0x9d, 0x41, 0x6f, 0xf7, 0x4f, 0x46, 0xd5
	};
	uint8_t result_96[] = { 0x60, 0x5e, 0x2b, 0x0b, 0x04, 0xfc, 0x16, 0xeb,
		0x4a, 0x1d, 0xd5, 0x6e, 0xb0, 0x8d, 0x40, 0xba,
		0x2a, 0xb9, 0xfd, 0xf9, 0x4d, 0xe3, 0x4d, 0xd3,
		0x61, 0x71, 0xbf, 0xd1, 0xd6, 0x51, 0xf7, 0x41,
		0x3a, 0x1a, 0xa7, 0x3e, 0x41, 0x20, 0x1b, 0xe7,
		0xe3, 0x80, 0xeb, 0x16, 0x4e, 0x74, 0x94, 0xed,
		0xb0, 0x2b, 0x72, 0xb1, 0x6f, 0x62, 0x3d, 0x53,
		0x56, 0x9d, 0x41, 0x6f, 0xf7, 0x4f, 0x46, 0xd5,
		0x08, 0x5e, 0xda, 0xda, 0xff, 0x2f, 0x6d, 0x19,
		0x20, 0x14, 0x72, 0x07, 0xe7, 0xd9, 0x64, 0x29,
		0x06, 0xdd, 0x93, 0xa7, 0xac, 0xa2, 0x5a, 0x7f,
		0xbd, 0x85, 0x0e, 0xfd, 0xf6, 0xb3, 0x72, 0xdd
	};
	uint8_t empty[256];
	memset(empty, 0, 256);

	mgf1_512(&out_buffer[0], 32, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer[0], result_32, 32) == 0);

	mgf1_512(&out_buffer[0], 48, (unsigned char *)buffer, buffer_len);

	assert(memcmp(&out_buffer[0], result_48, 48) == 0);

	mgf1_512(&out_buffer[0], 64, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer[0], result_64, 64) == 0);

	mgf1_512(&out_buffer[0], 96, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer[0], result_96, 96) == 0);

	// API is to follow SPHINCS so no return on these
	// just calling to make sure no core dumps or other issues
	memset(&out_buffer[0], 0, 900);
	mgf1_512(NULL, EVP_MAX_MD_SIZE, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	mgf1_512(&out_buffer[0], 0, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	mgf1_512(&out_buffer[0], EVP_MAX_MD_SIZE, NULL, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	mgf1_512(&out_buffer[0], EVP_MAX_MD_SIZE, (unsigned char *)buffer, 0);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);

	return 0;
}

/**
 * Test the MTL buffer set flags functions
 */
uint8_t mtltest_spx_funcs_sha256(void)
{
	char *buffer = "Test Hash Message 123456";
	uint32_t buffer_len = 24;
	uint8_t out_buffer[EVP_MAX_MD_SIZE];
	uint8_t result[] = { 0x52, 0x2a, 0x01, 0x49, 0xb1, 0xc3, 0x51, 0x78,
		0x34, 0xe2, 0x15, 0x27, 0x9b, 0xbb, 0xde, 0xcf,
		0x22, 0xec, 0x23, 0x97, 0xb0, 0xd9, 0x1d, 0x4a,
		0xa1, 0xf0, 0xed, 0x36, 0x99, 0xeb, 0x3f, 0x96
	};
	uint8_t empty[EVP_MAX_MD_SIZE];
	memset(empty, 0, EVP_MAX_MD_SIZE);

	sha256(&out_buffer[0], (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer, result, 32) == 0);

	// API is to follow SPHINCS so no return on these
	// just calling to make sure no core dumps or other issues
	memset(&out_buffer[0], 0, EVP_MAX_MD_SIZE);
	sha256(NULL, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	sha256(&out_buffer[0], NULL, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	sha256(&out_buffer[0], (unsigned char *)buffer, 0);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);

	return 0;
}

/**
 * Test the MTL buffer set flags functions
 */
uint8_t mtltest_spx_funcs_sha512(void)
{
	char *buffer = "Test Hash Message 123456";
	uint32_t buffer_len = 24;
	uint8_t out_buffer[EVP_MAX_MD_SIZE];
	uint8_t result[] = { 0xdb, 0x7e, 0x56, 0xdc, 0x0e, 0x7c, 0xb4, 0x1c,
		0x78, 0xc0, 0xb1, 0x13, 0x10, 0x3a, 0x84, 0x9d,
		0x5a, 0x60, 0xf7, 0x71, 0xf1, 0xf9, 0xc9, 0x72,
		0xba, 0xb2, 0x90, 0x69, 0xda, 0x3b, 0x7c, 0x68,
		0x85, 0x39, 0x4c, 0x84, 0x10, 0x82, 0xaf, 0x05,
		0x6b, 0x87, 0x29, 0x39, 0xe6, 0xf5, 0xa0, 0xf2,
		0x9a, 0x0c, 0xf8, 0xa5, 0xe7, 0xf4, 0x35, 0xdf,
		0xeb, 0x81, 0x97, 0xfb, 0x11, 0x9f, 0x7a, 0xdd
	};
	uint8_t empty[EVP_MAX_MD_SIZE];
	memset(empty, 0, EVP_MAX_MD_SIZE);

	sha512(&out_buffer[0], (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer, result, 64) == 0);

	// API is to follow SPHINCS so no return on these
	// just calling to make sure no core dumps or other issues
	memset(&out_buffer[0], 0, EVP_MAX_MD_SIZE);
	sha512(NULL, (unsigned char *)buffer, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	sha512(&out_buffer[0], NULL, buffer_len);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	sha512(&out_buffer[0], (unsigned char *)buffer, 0);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);

	return 0;
}

/**
 * Test the MTL buffer set flags functions
 */
uint8_t mtltest_spx_funcs_shake256(void)
{
	char *buffer = "Test Hash Message 123456";
	uint32_t buffer_len = 24;
	uint8_t out_buffer[EVP_MAX_MD_SIZE];
	uint8_t result[] = { 0x5a, 0x5a, 0x30, 0x70, 0x50, 0x25, 0x9d, 0xc1,
		0x2a, 0x9e, 0xcd, 0xf1, 0xb3, 0x74, 0x7c, 0xb1,
		0x66, 0xf7, 0x07, 0x7d, 0x42, 0xcd, 0xb0, 0x40,
		0xf3, 0x0a, 0x9a, 0xe3, 0x25, 0x9e, 0x41, 0x45
	};
	uint8_t empty[EVP_MAX_MD_SIZE];
	memset(empty, 0, EVP_MAX_MD_SIZE);

	shake256(&out_buffer[0], (unsigned char *)buffer, buffer_len, 32);
	assert(memcmp(&out_buffer, result, 32) == 0);

	// API is to follow SPHINCS so no return on these
	// just calling to make sure no core dumps or other issues
	memset(&out_buffer[0], 0, EVP_MAX_MD_SIZE);
	shake256(NULL, (unsigned char *)buffer, buffer_len, 32);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	shake256(&out_buffer[0], NULL, buffer_len, 32);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);
	shake256(&out_buffer[0], (unsigned char *)buffer, 0, 32);
	assert(memcmp(&out_buffer, &empty, EVP_MAX_MD_SIZE) == 0);

	return 0;
}
