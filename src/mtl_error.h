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
/**
 *  \file mtl_error.h
 *  \brief MTL macro functions that can report macros or disable error reporting.
*/
#ifndef __MTL_ERROR_H__
#define __MTL_ERROR_H__

#include <stdio.h>

// #definitions
/** Definition declaring logging is on by default (1) - Remove or undeclare to stop error logging. */
#define MTL_DEBUG_LOG 1

#if MTL_DEBUG_LOG == 1
/** Logging Function Macro definition */
#define LOG_ERROR(msg)  if(1) {fprintf(stderr,"\x1B[31m    "\
                               "ERROR (%s:%s:%d): %s\x1B[0m\n",\
                               __FILE__,__FUNCTION__,__LINE__,msg);}
#else
#define LOG_ERROR(msg)
#endif

// Return Status Values
/** MTL status return code */ 
#ifndef MTL_RETURN_CODES_DEF
#define MTL_RETURN_CODES_DEF 1
typedef enum { MTL_OK, MTL_NULL_PTR, MTL_RESOURCE_FAIL, MTL_BAD_PARAM, MTL_ERROR, MTL_BOGUS } MTLSTATUS;
#define LOG_ERROR_WITH_CODE(ftn,code)  if(1) { \
	static const char* MTLSTATUS_STR[] = { "MTL_OK", "MTL_NULL_PTR", "MTL_RESOURCE_FAIL", "MTL_BAD_PARAM", "MTL_ERROR", "MTL_BOGUS" };\
	fprintf(stderr,"\x1B[31mERROR (%s:%s:%d): %s returned %s\x1B[0m\n",\
            __FILE__,__FUNCTION__,__LINE__,ftn,MTLSTATUS_STR[code]);}
#endif

#endif				// __MTL_ERROR_H