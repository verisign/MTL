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
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

#include "mtl_util.h"
#include "mtltool.h"
#include "mtlverify.h"
#include "mtl_example_util.h"

 #include <openssl/evp.h>


/*****************************************************************
* Get Underlying Signature
******************************************************************
 * @param algo_str, C character string representing the algorithm
 * @return ALGORITHM structure element with the properties for
 *         the specific algorithm, or NULL if not found
 */
ALGORITHM *get_underlying_signature(char *algo_str, ALGORITHM* algos)
{
	uint16_t algo_idx = 0;

	while (algos[algo_idx].name != NULL) {
		if (strcmp(algos[algo_idx].name, (char *)algo_str) == 0) {
			return &algos[algo_idx];
		}
		algo_idx++;
	}

	return NULL;
}



/*****************************************************************
* Convert a string to upper case in place
******************************************************************
 * @param data, string to convert (in place)
 * @return Converted string pointer
 */
char *mtl_str2upper(char *data)
{
	char *p = data;

	for (; *p; ++p)
		*p = toupper(*p);
	return data;
}



/*****************************************************************
* Convert an encoded buffer to the binary in memory format
******************************************************************
 * @param input     encoded input buffer
 * @param input_len length of the encoded input buffer
 * @param output    pointer for the output buffer (user frees)
 * @param encoding  format the input buffer is using
 * @return size of the output buffer
 */
size_t mtl_buffer2bin(uint8_t* input, size_t input_len, uint8_t** output, data_encoding encoding) {
	uint8_t* buffer = NULL;
	size_t buffer_size;
	uint8_t byte_val;
	char tmp[3];
	int b64_len;
	uint8_t b64_buff[MAX_BUFFER_SIZE];
	EVP_ENCODE_CTX *ctx = NULL;
	int status;

	if(input_len >= MAX_BUFFER_SIZE) {
		LOG_ERROR("Invalid input length, greater than the buffer size");
		*output = NULL;
		return 0;
	}

	if(encoding == BASE64_STRING) {
		ctx = EVP_ENCODE_CTX_new();

		EVP_DecodeInit(ctx);
		status = EVP_DecodeUpdate(ctx, &b64_buff[0], &b64_len, input, input_len);
		if((status != 0) && (status != 1)) {
			*output = NULL;
			EVP_ENCODE_CTX_free(ctx);
			return 0;
		}
		buffer_size = b64_len;
		status = EVP_DecodeFinal(ctx, &b64_buff[b64_len], &b64_len);
		if(status != 1) {
			*output = NULL;
			EVP_ENCODE_CTX_free(ctx);
			return 0;			
		}
		buffer_size += b64_len;
		buffer = calloc(1, buffer_size);
		memcpy(buffer, &b64_buff[0], buffer_size);
		EVP_ENCODE_CTX_free(ctx);
	} else {
		if(input_len % 2 != 0) {
			*output = NULL;
			return 0;				
		}
		buffer_size = input_len/2;

   		for (size_t i = 0; i < input_len; i+=2) {
			tmp[0] = input[i];
			tmp[1] = input[i+1];
			tmp[2] = '\0';
			if(sscanf(tmp, "%hhx", &byte_val) != 1) {
				*output = NULL;
				return 0;		
			}
			b64_buff[i/2] = byte_val;
		}
		buffer = calloc(1, buffer_size);
		memcpy(buffer, &b64_buff[0], buffer_size);		
	}
	*output = buffer;
	return buffer_size;
}

static void verbose_print_block(char* descript, FILE* stream) {
	uint32_t len = 45 - strlen(descript);
	uint32_t i = 0;

	if(strlen(descript) == 0) {
		fprintf(stream, " ========");
		for(i=0; i<len+2; i++) {
			fprintf(stream, "=");
		}
		fprintf(stream," \n\n");
	} else {
		fprintf(stream," ======== %s ", descript);
		for(i=0; i<len; i++) {
			fprintf(stream,"=");
		}
		fprintf(stream," \n");
	}
}


static void verbose_print_buffer(char* descript, uint8_t* buffer, uint32_t buffer_len, FILE* stream) {
	uint32_t i =0;

    fprintf(stream, "    %15s - ", descript);
	for(i=0; i<buffer_len; i++) {
		fprintf(stream , "%02x", buffer[i]);
	}
	fprintf(stream, "\n");
}


static void verbose_print_hex(char* descript, uint32_t value, FILE* stream) {
	fprintf(stream, "    %15s - %02x\n", descript, value);
}

static void verbose_print_number(char* descript, uint32_t value, FILE* stream) {
	fprintf(stream, "    %15s - %02d\n", descript, value);
}

static void verbose_print_string(char* descript, char* str, FILE* stream) {
	fprintf(stream, "    %15s - %s\n", descript, str);
}

static void verbose_print_rung(char* descript, uint32_t l, uint32_t r, uint8_t* buffer, uint32_t buffer_len, FILE* stream) {
	uint32_t i =0;

    fprintf(stream, "    %15s (%d,%d) ", descript, l, r);
	for(i=0; i<buffer_len; i++) {
		fprintf(stream , "%02x", buffer[i]);
	}
	fprintf(stream, "\n");
}


void mtl_print_auth_path(AUTHPATH* auth_path, RANDOMIZER* mtl_rand, uint32_t hash_len, FILE *stream) {
	uint32_t hash;

	if(stream != NULL) {
		if(auth_path != NULL) {
			verbose_print_block("Authentication Path", stream);
			if(mtl_rand != NULL) {
				verbose_print_buffer("Randomizer", mtl_rand->value, hash_len, stream);
			}
			verbose_print_hex("Flags", auth_path->flags, stream);
			verbose_print_buffer("SID",  auth_path->sid.id, auth_path->sid.length, stream);		
			verbose_print_number("Leaf Index", auth_path->leaf_index, stream);
			verbose_print_number("Left Rung", auth_path->rung_left, stream);
			verbose_print_number("Right Rung", auth_path->rung_right, stream);
			verbose_print_number("Hash Count", auth_path->sibling_hash_count, stream);
			for(hash=0; hash<auth_path->sibling_hash_count; hash++) {
				verbose_print_buffer("Path Hash", &auth_path->sibling_hash[hash*hash_len], hash_len, stream);
			}
			verbose_print_block("", stream);
		}
	}
}

void mtl_print_ladder(LADDER* ladder, FILE *stream) {
	RUNG* r = NULL;
	uint16_t rc = 0;

	if(stream != NULL) {
		verbose_print_block("Ladder Values", stream);
		verbose_print_hex("Flags", ladder->flags, stream);
		verbose_print_buffer("SID",  ladder->sid.id, ladder->sid.length, stream);		
		verbose_print_number("Rung Count", ladder->rung_count, stream);
		for(rc=0; rc<ladder->rung_count; rc++) {
			r = (RUNG *) ((uint8_t *) ladder->rungs + (sizeof(RUNG) * rc));
			verbose_print_rung("Ladder Rung", r->left_index, r->right_index, r->hash, r->hash_length, stream);
		}
		verbose_print_block("", stream); 
	}
}

void mtl_print_ladder_signature(uint8_t* sig, size_t sig_len, FILE* stream) {
	if(stream != NULL) {
		verbose_print_block("Ladder Signature", stream);
		verbose_print_number("Signature Len", sig_len, stream);
		verbose_print_buffer("Signature", sig, sig_len, stream);
		verbose_print_block("", stream);        
	}
}

void mtl_print_rung(RUNG* rung, FILE* stream) {
	if(stream != NULL) {
		verbose_print_block("Ladder Rung Values", stream);
		verbose_print_rung("Ladder Rung", rung->left_index, rung->right_index, rung->hash, rung->hash_length, stream);
		verbose_print_block("", stream); 		
	}
}


void mtl_print_message(uint8_t* message, uint32_t message_len, FILE* stream) {
	if(stream != NULL) {	
		verbose_print_block("Signature Message", stream);
		verbose_print_number("Msg Length", message_len, stream);
		verbose_print_buffer("Msg Bytes", message, message_len, stream);
		verbose_print_block("", stream); 		
	}
}


void mtl_print_signature_scheme(ALGORITHM* algo, FILE* stream) {
	if(stream != NULL) {
		verbose_print_block("MTL Signature Scheme", stream);
		verbose_print_string("Scheme", algo->name, stream);
		verbose_print_number("Security Param", algo->sec_param, stream);
		verbose_print_number("NIST Level", algo->nist_level, stream);
		verbose_print_hex("Randomizing", algo->randomize, stream);
		verbose_print_hex("Robust", algo->robust, stream);
		verbose_print_string("Underlying Sig", algo->oqs_str, stream);
		verbose_print_number("OID Length", algo->oid_len, stream);
		verbose_print_buffer("OID Value", algo->oid, algo->oid_len, stream);
		verbose_print_block("", stream); 	
	}
}

void mtl_print_mtl_buffer(char* label, uint8_t *buffer, uint32_t buffer_length, FILE* stream) {
	if(stream != NULL) {
		verbose_print_block(label, stream);	
		verbose_print_number("Length", buffer_length, stream);			
		verbose_print_buffer("Value", buffer, buffer_length, stream);
		verbose_print_block("", stream); 			
	}
}