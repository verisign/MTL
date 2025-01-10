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
#ifndef __MTL_TOOL_H__
#define __MTL_TOOL_H__

#include "mtl.h"

#define ALG_NONE 0
#define SPX_ALG_SHAKE 1
#define SPX_ALG_SHA2  2

#define SIMPLE 0
#define ROBUST 1

typedef struct ALGORITHM {
	char *name;
	uint16_t sec_param;
	uint16_t nist_level;
	uint8_t randomize;
	uint8_t robust;
	char opt;
	uint8_t algo;
	char *oqs_str;
	uint8_t oid_len;
	uint8_t oid[16];
} ALGORITHM;

typedef struct QUEUE_NODE {
	uint32_t index;
	struct QUEUE_NODE *next;
} QUEUE_NODE;

// Function Prototypes
uint8_t sign_records(FILE * input, FILE * output, MTL_CTX * ctx,
		     char *oqs_str, uint8_t * sk, uint8_t* oid, size_t oid_len);
uint8_t verify_records(FILE * input, int signfd, MTL_CTX * ctx,
		       char *oqs_str, uint8_t * pk, uint8_t* oid, size_t oid_len);
uint8_t new_key(char *keystr, char *keyfilename, char* ctx_str);

#endif
