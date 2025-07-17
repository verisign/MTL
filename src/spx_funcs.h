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
 *  \file spx_funcs.h
 *  \brief General wrapper functions for hashing or padding
 *  General functions for hashing or padding operations. These functions 
 *  adopt a simple interface so that they are easy to replace if a specific 
 *  implementation is desired for a specific library or target platform.
*/
#ifndef __SPX_FUNCS_H__
#define __SPX_FUNCS_H__

#include <stddef.h>
#include <stdint.h>

// Definitions
/** Byte size of a SHA2_256 hash */ 
#define SHA2_256_BLOCK_SIZE 64
/** Byte size of a SHA2_512 hash */ 
#define SHA2_512_BLOCK_SIZE 128

// Function Prototypes
/**
 * Block Pad data
 * @param data:      Byte array of data to pad
 * @param data_len:  Length of the data to pad
 * @param block_len: Block size to use for padding
 * @param buffer:    Byte array output
 * @return total size of padded data
 */
uint32_t block_pad(uint8_t * data, uint32_t data_len, uint32_t block_len,
		   uint8_t ** buffer);

/**
 * MGF1 function for SHA-256 hash function
 * @param out     Padded output buffer
 * @param out_len: Size of the output buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */		   
void mgf1_256(unsigned char *out, unsigned long outlen,
	      const unsigned char *in, unsigned long inlen);

/**
 * MGF1 function for SHA-512 hash function
 * @param out:     Padded output buffer
 * @param out_len: Size of the output buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */		  
void mgf1_512(unsigned char *out, unsigned long outlen,
	      const unsigned char *in, unsigned long inlen);

/**
 * SHA256 Hash Function - Based on OpenSSL EVP API
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */		  
void sha256(uint8_t * out, const uint8_t * in, size_t inlen);

/**
 * SHA512 Hash Function - Based on OpenSSL EVP API
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */
void sha512(uint8_t * out, const uint8_t * in, size_t inlen);

/**
 * SHAKE256 Hash Function - Based on OpenSSL EVP API
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */
void shake256(uint8_t * out, const uint8_t * in, size_t inlen, size_t hash_len);

#endif				//__SPX_FUNCS_H__
