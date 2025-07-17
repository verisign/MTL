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
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mtl_error.h"
#include "mtl_util.h"

/*****************************************************************
* Convert a 32 bit unsigned integer to bit endian bytes
******************************************************************
 * @param buffer:     Byte array output
 * @param value:      Unsigned 32 bit integer to convert
 * @return number of bytes for output
 */
uint16_t uint32_to_bytes(unsigned char *buffer, uint32_t value)
{
	if (buffer == NULL) {
		LOG_ERROR("NULL Parameters");
		return 0;
	}

	if (BIG_ENDIAN_PLATFORM) {
		buffer[3] = (unsigned char)(value >> 24);
		buffer[2] = (unsigned char)(value >> 16);
		buffer[1] = (unsigned char)(value >> 8);
		buffer[0] = (unsigned char)value;
	} else {
		buffer[0] = (unsigned char)(value >> 24);
		buffer[1] = (unsigned char)(value >> 16);
		buffer[2] = (unsigned char)(value >> 8);
		buffer[3] = (unsigned char)value;
	}

	return 4;
}

/*****************************************************************
* Convert a 16 bit unsigned integer to bit endian bytes
******************************************************************
 * @param buffer:     Byte array output
 * @param value:      Unsigned 316 bit integer to convert
 * @return number of bytes for output
 */
uint16_t uint16_to_bytes(unsigned char *buffer, uint16_t value)
{
	if (buffer == NULL) {
		LOG_ERROR("NULL Parameters");
		return 0;
	}

	if (BIG_ENDIAN_PLATFORM) {
		buffer[1] = (unsigned char)(value >> 8);
		buffer[0] = (unsigned char)value;
	} else {
		buffer[0] = (unsigned char)(value >> 8);
		buffer[1] = (unsigned char)value;
	}

	return 2;
}

/*****************************************************************
* Convert a 32 bit endian byte array to unsigned integer
******************************************************************
 * @param buffer:     Byte array input
 * @param value:      Unsigned 32 bit integer result
 * @return number of bytes for input
 */
uint16_t bytes_to_uint32(unsigned char *buffer, uint32_t * value)
{
	if ((buffer == NULL) || (value == NULL)) {
		LOG_ERROR("NULL Parameters");
		return 0;
	}
	*value = 0;

	if (BIG_ENDIAN_PLATFORM) {
		*value += buffer[3] << 24;
		*value += buffer[2] << 16;
		*value += buffer[1] << 8;
		*value += buffer[0];
	} else {
		*value += buffer[0] << 24;
		*value += buffer[1] << 16;
		*value += buffer[2] << 8;
		*value += buffer[3];
	}

	return 4;
}

/*****************************************************************
* Convert a 16 bit endian byte array to unsigned integer
******************************************************************
 * @param buffer:     Byte array input
 * @param value:      Unsigned 16 bit integer result
 * @return number of bytes for input
 */
uint16_t bytes_to_uint16(unsigned char *buffer, uint16_t * value)
{
	if ((buffer == NULL) || (value == NULL)) {
		LOG_ERROR("NULL Parameters");
		return 0;
	}
	*value = 0;

	if (BIG_ENDIAN_PLATFORM) {
		*value += buffer[1] << 8;
		*value += buffer[0];
	} else {
		*value += buffer[0] << 8;
		*value += buffer[1];
	}

	return 2;
}
