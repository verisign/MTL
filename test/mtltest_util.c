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
#include "mtl_util.h"

// Prototypes for testing functions
uint8_t mtltest_uint32_to_bytes(void);
uint8_t mtltest_uint16_to_bytes(void);
uint8_t mtltest_bytes_to_uint32(void);
uint8_t mtltest_bytes_to_uint16(void);

uint8_t mtltest_util(void)
{
	NEW_TEST("MTL Utilities Tests");

	RUN_TEST(mtltest_uint32_to_bytes,
		 "Verify converting 32 bit uint to bytes");
	RUN_TEST(mtltest_uint16_to_bytes,
		 "Verify converting 16 bit uint to bytes");
	RUN_TEST(mtltest_bytes_to_uint32,
		 "Verify converting bytes to 32 bit uint");
	RUN_TEST(mtltest_bytes_to_uint16,
		 "Verify converting bytes to 16 bit uint");

	return 0;
}

/**
 * Test converting 32 bit uint to bytes
 */
uint8_t mtltest_uint32_to_bytes(void)
{
	uint32_t test_value_1 = 0x97481620;
	uint32_t test_value_2 = 0x7531;
	uint32_t test_value_3 = 0x1;
	uint8_t buffer[4];
	uint8_t results_1[] = { 0x97, 0x48, 0x16, 0x20 };
	uint8_t results_2[] = { 0x00, 0x00, 0x75, 0x31 };
	uint8_t results_3[] = { 0x00, 0x00, 0x00, 0x01 };

	assert(uint32_to_bytes(&buffer[0], test_value_1) == 4);
	assert(memcmp(buffer, results_1, 4) == 0);
	assert(uint32_to_bytes(&buffer[0], test_value_2) == 4);
	assert(memcmp(buffer, results_2, 4) == 0);
	assert(uint32_to_bytes(&buffer[0], test_value_3) == 4);
	assert(memcmp(buffer, results_3, 4) == 0);
	assert(uint32_to_bytes(NULL, test_value_3) == 0);

	return 0;
}

/**
 * Test converting 16 bit uint to bytes
 */
uint8_t mtltest_uint16_to_bytes(void)
{
	uint16_t test_value_1 = 0x7531;
	uint16_t test_value_2 = 0x44;
	uint8_t buffer[2];
	uint8_t results_1[] = { 0x75, 0x31 };
	uint8_t results_2[] = { 0x00, 0x44 };

	assert(uint16_to_bytes(&buffer[0], test_value_1) == 2);
	assert(memcmp(buffer, results_1, 2) == 0);
	assert(uint16_to_bytes(&buffer[0], test_value_2) == 2);
	assert(memcmp(buffer, results_2, 2) == 0);
	assert(uint16_to_bytes(NULL, test_value_2) == 0);

	return 0;
}

/**
 * Test converting bytes to 32 bit uint
 */
uint8_t mtltest_bytes_to_uint32(void)
{
	uint32_t test_value_1 = 0x97481620;
	uint32_t test_value_2 = 0x7531;
	uint32_t test_value_3 = 0x1;
	uint32_t result;
	uint8_t buffer_1[] = { 0x97, 0x48, 0x16, 0x20 };
	uint8_t buffer_2[] = { 0x00, 0x00, 0x75, 0x31 };
	uint8_t buffer_3[] = { 0x00, 0x00, 0x00, 0x01 };

	assert(bytes_to_uint32(&buffer_1[0], &result) == 4);
	assert(result == test_value_1);
	assert(bytes_to_uint32(&buffer_2[0], &result) == 4);
	assert(result == test_value_2);
	assert(bytes_to_uint32(&buffer_3[0], &result) == 4);
	assert(result == test_value_3);
	assert(bytes_to_uint32(NULL, &result) == 0);
	assert(bytes_to_uint32(&buffer_3[0], NULL) == 0);

	return 0;
}

/**
 * Test converting bytes to 16 bit uint
 */
uint8_t mtltest_bytes_to_uint16(void)
{
	uint16_t test_value_1 = 0x7531;
	uint16_t test_value_2 = 0x44;
	uint16_t result;
	uint8_t buffer_1[] = { 0x75, 0x31 };
	uint8_t buffer_2[] = { 0x00, 0x44 };

	assert(bytes_to_uint16(&buffer_1[0], &result) == 2);
	assert(result == test_value_1);
	assert(bytes_to_uint16(&buffer_2[0], &result) == 2);
	assert(result == test_value_2);
	assert(bytes_to_uint16(NULL, &result) == 0);
	assert(bytes_to_uint16(&buffer_2[0], NULL) == 0);

	return 0;
}
