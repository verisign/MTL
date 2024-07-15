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
#ifndef __MTL_VERBOSE_OUTPUT_H__
#define __MTL_VERBOSE_OUTPUT_H__

#include "mtl.h"
#include "mtltool.h"
#include "mtlverify.h"

#define MAX_BUFFER_SIZE 65535

size_t mtl_buffer2bin(uint8_t* input, size_t input_len, uint8_t** output, data_encoding encoding);
ALGORITHM *get_underlying_signature(char *algo_str, ALGORITHM* algos);
char *mtl_str2upper(char *data);
void mtl_print_auth_path(AUTHPATH* auth_path, RANDOMIZER* mtl_rand, uint32_t hash_len, FILE *stream);
void mtl_print_ladder(LADDER* ladder, FILE *stream);
void mtl_print_ladder_signature(uint8_t* sig, size_t sig_len, FILE* stream);
void mtl_print_rung(RUNG* rung, FILE* stream);
void mtl_print_message(uint8_t* message, uint32_t message_len, FILE* stream);
void mtl_print_signature_scheme(ALGORITHM* algo, FILE* stream);
void mtl_print_mtl_buffer(char* label, uint8_t *buffer, uint32_t buffer_length, FILE* stream);

#endif  // __MTL_VERBOSE_OUTPUT_H__