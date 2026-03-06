/*
	Copyright (c) 2026, VeriSign, Inc.
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
 *  \file mtl_error.h
 *  \brief MTL macro functions that can report macros or disable error reporting.
*/
#ifndef __MTL_INDEX_H__
#define __MTL_INDEX_H__

#include <stddef.h>
#include <stdint.h>

// Change this to switch between 32bit and 64bit MTL
#define MTL_INDEX_LEN 8

/** The size of a leaf index */
#if MTL_INDEX_LEN == 4
	typedef uint32_t MTL_INDEX;
#elif MTL_INDEX_LEN == 8
	typedef uint64_t MTL_INDEX;
#else
	#error "Unsupported MTL_INDEX size"
#endif

/** Maximum leaf index supported by a single set
 * 
 */
#if MTL_INDEX_LEN == 4
	#define MTL_NODE_SET_MAX_LEAF 0x7fffffffU
#elif MTL_INDEX_LEN == 8
	#define MTL_NODE_SET_MAX_LEAF 0x7fffffffffffffffULL
#else
	#error "Unsupported MTL_INDEX size"
#endif


/** Maximum index supported by an node set
 * 
 */
#define MTL_NODE_SET_MAX_INDEX (2*MTL_NODE_SET_MAX_LEAF)

#endif				// __MTL_INDEX_H