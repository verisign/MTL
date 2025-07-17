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
// The functions in this file can be replaced by routines in the SPHINCS+ library

#include <math.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mtl_error.h"
#include "mtl_util.h"
#include "spx_funcs.h"

/*****************************************************************
* Block Pad data
****************************************************************** 
 * @param data:      Byte array of data to pad
 * @param data_len:  Length of the data to pad
 * @param block_len: Block size to use for padding
 * @param buffer:    Byte array output
 * @return total size of padded data
 */
uint32_t block_pad(uint8_t * data, uint32_t data_len, uint32_t block_len,
		   uint8_t ** buffer)
{
	uint32_t block_size =
	    (uint32_t) ceil((double)data_len / (double)block_len) * block_len;
	uint8_t *pad_buffer = malloc(block_size);
	memset(pad_buffer, 0, block_size);

#ifdef PADDING_FILL_NONZERO
	uint16_t fill_value = block_size - data_len;
	memset(pad_buffer, fill_value, block_size);
#endif

	memset(pad_buffer, 0, block_size);
	memcpy(pad_buffer, data, data_len);
	*buffer = pad_buffer;

	return block_size;
}

/*****************************************************************
* MGF1 function for SHA-256 hash function
******************************************************************
 * @param out:     Padded output buffer
 * @param out_len: Size of the output buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */
void mgf1_256(unsigned char *out, unsigned long out_len,
	      const unsigned char *in, unsigned long in_len)
{
	uint8_t buffer[in_len + 4];
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned long block = 0;

	if ((out == NULL) || (in == NULL) || (in_len == 0) || (out_len == 0)) {
		return;
	}
	memcpy(buffer, in, in_len);

	// Update each full block in the output
	for (block = 0; block < out_len / (SHA2_256_BLOCK_SIZE/2); block++) {
		uint32_to_bytes(buffer + in_len, block);
		sha256(out + (block * (SHA2_256_BLOCK_SIZE/2)), buffer, in_len + 4);
	}
	// Fill the remaining bytes in the output block
	if (out_len % (SHA2_256_BLOCK_SIZE/2) > 0) {
		uint32_to_bytes(buffer + in_len, block);
		sha256(hash, buffer, in_len + 4);
		memcpy(out + (block * (SHA2_256_BLOCK_SIZE/2)), hash,
		       out_len % (SHA2_256_BLOCK_SIZE/2));
	}
}

/*****************************************************************
* MGF1 function for SHA-512 hash function
******************************************************************
 * @param out:     Padded output buffer
 * @param out_len: Size of the output buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */
void mgf1_512(unsigned char *out, unsigned long out_len,
	      const unsigned char *in, unsigned long in_len)
{
	uint8_t buffer[in_len + 4];
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned long block = 0;

	if ((out == NULL) || (in == NULL) || (in_len == 0) || (out_len == 0)) {
		return;
	}
	memcpy(buffer, in, in_len);

	// Update each full block in the output
	for (block = 0; block < out_len / (SHA2_512_BLOCK_SIZE/2); block++) {
		uint32_to_bytes(buffer + in_len, block);
		sha512(out + (block * (SHA2_512_BLOCK_SIZE/2)), buffer, in_len + 4);
	}
	// Fill the remaining bytes in the output block
	if (out_len % (SHA2_512_BLOCK_SIZE/2) > 0) {
		uint32_to_bytes(buffer + in_len, block);
		sha512(hash, buffer, in_len + 4);
		memcpy(out + (block * (SHA2_512_BLOCK_SIZE/2)), hash,
		       out_len % (SHA2_512_BLOCK_SIZE/2));
	}
}

/*****************************************************************
* SHA256 Hash Function - Based on OpenSSL EVP API
******************************************************************
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */
void sha256(uint8_t * out, const uint8_t * in, size_t in_len)
{
	EVP_MD *hash_func = NULL;
	EVP_MD_CTX *mdctx = NULL;
	unsigned int hash_len;

	if ((out == NULL) || (in == NULL) || (in_len == 0)) {
		return;
	}
	// Create the SHA256 instantiation
	hash_func = (EVP_MD *) EVP_sha256();
	mdctx = EVP_MD_CTX_new();

	// Initalize the digest
	if (1 != EVP_DigestInit_ex(mdctx, hash_func, NULL)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to allocate hash function");
		return;
	}
	// Add the data buffer
	if (1 != EVP_DigestUpdate(mdctx, in, in_len)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to add message to digest");
		return;
	}
	// Finalize the digest
	if (1 != EVP_DigestFinal_ex(mdctx, &out[0], &hash_len)) {
		LOG_ERROR("Unable to finalize digest");
	}

	EVP_MD_CTX_free(mdctx);
}

/*****************************************************************
* SHA512 Hash Function - Based on OpenSSL EVP API
******************************************************************
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */
void sha512(uint8_t * out, const uint8_t * in, size_t in_len)
{
	EVP_MD *hash_func = NULL;
	EVP_MD_CTX *mdctx = NULL;
	unsigned int hash_len;

	if ((out == NULL) || (in == NULL) || (in_len == 0)) {
		return;
	}
	// Create the SHA512 instantiation
	hash_func = (EVP_MD *) EVP_sha512();
	mdctx = EVP_MD_CTX_new();

	// Initalize the digest
	if (1 != EVP_DigestInit_ex(mdctx, hash_func, NULL)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to allocate hash function");

		return;
	}
	// Add the data buffer
	if (1 != EVP_DigestUpdate(mdctx, in, in_len)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to add message to digest");
		return;
	}
	// Finalize the digest
	if (1 != EVP_DigestFinal_ex(mdctx, &out[0], &hash_len)) {
		LOG_ERROR("Unable to compute digest");
	}

	EVP_MD_CTX_free(mdctx);
}

/*****************************************************************
* SHAKE256 Hash Function - Based on OpenSSL EVP API
******************************************************************
 * @param out:     output hash buffer
 * @param in:      Input buffer
 * @param in_len:  Size of the input buffer
 * @return none
 */
void shake256(uint8_t * out, const uint8_t * in, size_t in_len, size_t hash_len)
{
	EVP_MD *hash_func = NULL;
	EVP_MD_CTX *mdctx = NULL;

	if ((out == NULL) || (in == NULL) || (in_len == 0) || (hash_len == 0)) {
		return;
	}
	// Create the SHAKE256 instantiation
	hash_func = (EVP_MD *) EVP_shake256();
	mdctx = EVP_MD_CTX_new();

	// Initalize the digest
	if (1 != EVP_DigestInit_ex(mdctx, hash_func, NULL)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to allocate hash function");

		return;
	}
	// Add the data buffer
	if (1 != EVP_DigestUpdate(mdctx, in, in_len)) {
		EVP_MD_CTX_free(mdctx);
		LOG_ERROR("Unable to add message to digest");
		return;
	}
	// Finalize the digest
	if (1 != EVP_DigestFinalXOF(mdctx, &out[0], hash_len)) {
		LOG_ERROR("Unable to compute digest");
	}

	EVP_MD_CTX_free(mdctx);
}
