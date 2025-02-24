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
#ifndef __MTL_VERIFY_TOOL_H__
#define __MTL_VERIFY_TOOL_H__

#include <stdbool.h>
#include "mtl_example_util.h"

/* Type definitions */

/* Function Prototypes*/

/*****************************************************************
 * Parse a ladder from a buffer and verify it if possible
 ******************************************************************
 * @param ctx            An initialized MTL context
 * @param algo           Alogorithm for verifying ladder signature
 * @param buffer         Byte buffer containing the ladder
 * @param buffer_len     Length of the buffer
 * @param curr_ladder    Pointer which will return the current ladder
 * @param pk             Pointer to the public key fr verification
 * @param verbose_buffer File pointer (or null) for the verbose output
 * @param encoding       Output format desired (e.g. Base64 encoded?)
 * @param signed_ladder  Flag to print the long signature or not
 * @param quiet_mode     Flag to only print error messages
 * @return MTLSTATUS indicating MLT_OK or error value
 */
MTLSTATUS parse_ladder(MTL_CTX *ctx, ALGORITHM *algo, uint8_t *buffer,
					 size_t buffer_len, LADDER **curr_ladder, uint8_t *pk,
					 FILE *verbose_buffer, data_encoding encoding,
					 uint8_t signed_ladder, bool quiet_mode);

/*****************************************************************
 * Verify the authentication path given a good ladder
 ******************************************************************
 * @param ctx            An initialized MTL context
 * @param auth_path      Authentication path to verify
 * @param ladder         Ladder to use to verify the auth_path
 * @param msg            Message to verify wtih the auth path
 * @param msg_len        Length of the message to verify
 * @param mtl_rand       Randomizer value to use for validation
 * @param verbose_buffer File pointer (or null) for the verbose output
 * @return 0 on success or int value for error
 */
MTLSTATUS verify_auth_path(MTL_CTX * ctx, AUTHPATH *auth_path, LADDER* ladder,
                         uint8_t* msg, size_t msg_len, RANDOMIZER *mtl_rand,
						 FILE* verbose_buffer);


/*****************************************************************
 * Setup a public key
 ******************************************************************
 * @param algo           MTL alogorithm identifier used
 * @param pkey           Public key used to sign the ladder
 * @param sid            MTL Series Identifier used
 * @param ctx_str        Optional signature context string
 * @return MTL context for verification of MTL signatures
 */
MTL_CTX *setup_public_key(ALGORITHM *algo, uint8_t *pkey,
						  SERIESID *sid, char *ctx_str);

#endif //__MTL_VERIFY_TOOL_H__