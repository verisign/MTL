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
#ifndef __MTL_TEST_SPX_INTERNAL__
#define __MTL_TEST_SPX_INTERNAL__

// Data arrays for the tests
// Compressed Address Structures
const uint8_t adrs_compress[] =
    { 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t adrs_compress_alt[] =
    { 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t adrs_comporess_invalid[] =
    { 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x11, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
	0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00
};

const uint8_t adrs_full[] = { 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x00, 0x00, 0x00, 0x11,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x09
};

const uint8_t adrs_full_invalid[] = { 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x01, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x00, 0x00, 0x00, 0x11,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x08,
	0x00, 0x00, 0x00, 0x09
};

// Randomizer array for the tests
const uint16_t randomizer_len = 32;
const uint8_t randomizer[] = { 0x49, 0xf6, 0x4a, 0xce, 0xea, 0xa3, 0xee, 0x0d,
	0x4c, 0x61, 0xe2, 0x79, 0x88, 0x08, 0x6b, 0x2d,
	0x66, 0x2f, 0x35, 0x9d, 0x03, 0xfe, 0x70, 0x3c,
	0x46, 0x52, 0x09, 0x9b, 0x01, 0x5e, 0xb5, 0x0c
};

const uint8_t randomizer_alt[] =
    { 0x49, 0xf6, 0x4a, 0xce, 0xea, 0xa3, 0xee, 0x0d,
	0x4c, 0x61, 0xe2, 0x79, 0x88, 0x08, 0x6b, 0xff,
	0x66, 0x2f, 0x35, 0x9d, 0x03, 0xfe, 0x70, 0x3c,
	0x46, 0x52, 0x09, 0x9b, 0x01, 0x5e, 0xb5, 0x0c
};

// SEED for the test seed data values
const uint8_t seed[] = { 0x66, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
	0x06, 0xb5, 0x59, 0x89, 0x75, 0x08, 0xe7, 0x2c,
	0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
	0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
};

const uint8_t seed_alt[] = { 0x66, 0x87, 0x0c, 0x58, 0x1e, 0x05, 0x1e, 0x75,
	0x06, 0xb5, 0x59, 0x89, 0x75, 0x09, 0xf8, 0x2c,
	0x03, 0x69, 0x6e, 0x98, 0x22, 0x87, 0x08, 0xe2,
	0xf1, 0x85, 0xb2, 0xe5, 0x60, 0xbf, 0xaa, 0x46
};

// Public key data for the test PK data values
const uint8_t pubkey[] = { 0xb3, 0x07, 0xb6, 0xed, 0x82, 0x4e, 0x9f, 0x39,
	0xbe, 0x88, 0x2d, 0xff, 0xf6, 0xda, 0x04, 0x71,
	0x20, 0x39, 0xdf, 0xd9, 0x42, 0x45, 0xda, 0x64,
	0x3e, 0xd3, 0x84, 0xe7, 0x7b, 0xc6, 0x5e, 0x83
};

const uint8_t pubkey_alt[] = { 0xb4, 0x11, 0xb6, 0xed, 0x82, 0x4e, 0x9f, 0x39,
	0xbe, 0x88, 0x82, 0xff, 0xf6, 0xda, 0x04, 0x71,
	0x20, 0x39, 0xdf, 0xd9, 0x42, 0x45, 0xda, 0x64,
	0x3e, 0xd3, 0x84, 0xe7, 0x7b, 0xc6, 0x5e, 0x83
};

// SID Data value
const uint8_t sid_val[] = { 0x28, 0xe7, 0x56, 0xf0, 0xb4, 0x61, 0xf6, 0x79 };
const uint8_t sid_val_alt[] =
    { 0xff, 0xff, 0xff, 0xf0, 0xb4, 0x61, 0xf6, 0x79 };

// Child Node Hash Inputs
const uint8_t hash_left[] = { 0x8a, 0x44, 0x26, 0x42, 0xad, 0x4a, 0x96, 0x1f,
	0xb4, 0x47, 0x52, 0x3b, 0x26, 0x42, 0xe7, 0x9b,
	0x65, 0xf4, 0x46, 0x49, 0xf1, 0xbd, 0x62, 0xa6,
	0xc4, 0x19, 0xd8, 0x82, 0xdf, 0x2d, 0x9a, 0xd0
};

const uint8_t hash_right[] = { 0xe7, 0xf1, 0x10, 0x39, 0xf3, 0xa9, 0x2a, 0xdf,
	0xcc, 0xbc, 0x6c, 0x9f, 0x54, 0x60, 0xef, 0xdd,
	0x97, 0x95, 0xc9, 0x0d, 0x00, 0x75, 0x1c, 0xc1,
	0x61, 0x6f, 0x0c, 0x2f, 0xf6, 0x9d, 0x3d, 0x77
};

const uint8_t hash_left_alt[] =
    { 0xa8, 0x44, 0x62, 0x42, 0xad, 0x4a, 0x96, 0x1f,
	0xb4, 0x47, 0x52, 0x3b, 0x26, 0x42, 0xe7, 0x9b,
	0x65, 0xf4, 0x46, 0x49, 0xf1, 0xbd, 0x62, 0xa6,
	0xc4, 0x19, 0xd8, 0x82, 0xdf, 0x2d, 0x9a, 0xd0
};

const uint8_t hash_right_alt[] =
    { 0x7e, 0x1f, 0x01, 0x93, 0xf3, 0xa9, 0x2a, 0xdf,
	0xcc, 0xbc, 0x6c, 0x9f, 0x54, 0x60, 0xef, 0xdd,
	0x97, 0x95, 0xc9, 0x0d, 0x00, 0x75, 0x1c, 0xc1,
	0x61, 0x6f, 0x0c, 0x2f, 0xf6, 0x9d, 0x3d, 0x77
};

#endif				//__MTL_TEST_SPX_INTERNAL__
