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
#ifndef __MTL_SIGN_TOOL_H__
#define __MTL_SIGN_TOOL_H__

#include <stdint.h>
#include "mtl_example_util.h"

/* Type definitions */
// Quick linked list for leaf node ids
typedef struct leaf_queue
{
	uint32_t leaf_id;
	char *filename;
	struct leaf_queue *next;
} leaf_queue;

/*****************************************************************
 * Setup a private key
 ******************************************************************
 * @param pkey          Private key buffer
 * @param pkey_length   Length of the private key buffer
 * @param sk, secret key value
 * @param sk_len, length of the secret key
 * @param pk, public key value
 * @param pk_len, length of the public key
 * @param keystr: string name of the used signature algorithm
 * @param randomize: flag indicating if randomization should be used
 * @param params, Underlying singnature scheme parameters
 * @param algo_type, Algorithm type identifier 
 * @return MTL context for verification of MTL signatures
 */
MTL_CTX *setup_private_key(uint8_t *pkey, size_t pkey_len,
						   uint8_t **sk, uint32_t *sk_len,
						   uint8_t **pk, uint32_t *pk_len, char **keystr,
						   uint16_t *randomize, void **params, uint8_t *algo_type);

#endif //__MTL_SIGN_TOOL_H__