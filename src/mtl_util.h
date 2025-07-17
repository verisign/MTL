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
/**
 *  \file mtl_util.h
 *  \brief MTL Mode integer utility functions.
 * Functions for converting between MTL buffer bytes and unsigned integers
*/
#ifndef __MTL_UTIL_H__
#define __MTL_UTIL_H__

#include <stddef.h>
#include <stdint.h>

// Definitions
/** Macro for testing if the platform uses big or little endian */
#define BIG_ENDIAN_PLATFORM (!*(uint8_t *)&(uint16_t){1})

// Function Prototypes
/**
 * Convert a 32 bit unsigned integer to bit endian bytes
 * @param buffer     Byte array output
 * @param value      Unsigned 32 bit integer to convert
 * @return number of bytes for output
 */
uint16_t uint32_to_bytes(unsigned char *buffer, uint32_t value);

/**
 * Convert a 16 bit unsigned integer to bit endian bytes
 * @param buffer     Byte array output
 * @param value      Unsigned 316 bit integer to convert
 * @return number of bytes for output
 */
uint16_t uint16_to_bytes(unsigned char *buffer, uint16_t value);

/**
 * Convert a 32 bit endian byte array to unsigned integer
 * @param buffer     Byte array input
 * @param value      Unsigned 32 bit integer result
 * @return number of bytes for input
 */
uint16_t bytes_to_uint32(unsigned char *buffer, uint32_t * value);

/**
 * Convert a 16 bit endian byte array to unsigned integer
 * @param buffer     Byte array input
 * @param value      Unsigned 16 bit integer result
 * @return number of bytes for input
 */
uint16_t bytes_to_uint16(unsigned char *buffer, uint16_t * value);

#endif				//__MTL_UTIL_H__
