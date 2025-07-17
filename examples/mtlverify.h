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
#ifndef __MTL_VERIFY_TOOL_H__
#define __MTL_VERIFY_TOOL_H__

#include <stdbool.h>
#include "mtllib.h"
#include "mtl.h"

/* Type definitions */

/* Function Prototypes*/


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

#endif //__MTL_VERIFY_TOOL_H__