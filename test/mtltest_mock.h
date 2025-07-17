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
#ifndef __MTLTEST_MOCK_H__
#define __MTLTEST_MOCK_H__

// Mock function prototypes
uint8_t mtl_test_hash_msg(void *parameters,
			  SERIESID * sid,
			  uint32_t node_id,
			  uint8_t * randomizer,
			  uint32_t randomizer_len,
			  uint8_t * msg_buffer,
			  uint32_t msg_length, uint8_t * hash,
			  uint32_t hash_length, char * ctx,
			  uint8_t ** rmtl, uint32_t * rmtl_len);
uint8_t mtl_test_hash_leaf(void *params,
			   SERIESID * sid,
			   uint32_t node_id,
			   uint8_t * msg_buffer,
			   uint32_t msg_length,
			   uint8_t * hash, uint32_t hash_length);
uint8_t mtl_test_hash_node(void *params,
			   SERIESID * sid,
			   uint32_t left_index,
			   uint32_t right_index,
			   uint8_t * left_hash,
			   uint8_t * right_hash,
			   uint8_t * hash, uint32_t hash_length);

#endif				// __MTLTEST_MOCK_H__
