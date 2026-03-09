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
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "mtl_example_util.h"

/*****************************************************************
 * Load a file into a memory buffer and return the size
 ******************************************************************
 * @return None
 */
MTLLIB_STATUS buffer_from_file(char* filename, MTLLIB_BUFFER** buffer) {
    FILE* infile = NULL;
	int fd = -1;
    size_t filesize = 0;
	uint8_t *buffer_raw = NULL;

    if((filename != NULL) && (buffer != NULL)) {
		fd = open(filename, O_RDONLY, S_IRUSR | S_IWUSR); 
		if (fd < 0) { 
			perror("Error opening file");
            return MTLLIB_BUFFER_ISSUE; 
		} 
        infile = fdopen(fd, "rb");
        if (infile == NULL) {
            perror("Error opening file");
            return MTLLIB_BUFFER_ISSUE;
        }

        fseek(infile, 0, SEEK_END);
        filesize = ftell(infile);
        fseek(infile, 0, SEEK_SET);

        buffer_raw = malloc(filesize);
        if(buffer_raw == NULL) {
            perror("Error allocating memory");
            return 0;
        }
        fread(buffer_raw, 1, filesize, infile);
        fclose(infile);

		// We create a new data buffer and append because we want the data to be  
		// freed when the buffer is deconstructed, i.e.
		// mtllib_buffer_initialize(buffer, filesize, buffer_raw) would make the
		// caller responsible for freeing both buffer_raw and buffer
		if (mtllib_buffer_initialize(buffer, filesize, NULL) != MTLLIB_OK) {
			free(buffer_raw);
			return MTLLIB_BUFFER_ISSUE;
		}
		if (mtllib_buffer_append(*buffer, buffer_raw, filesize) != MTLLIB_OK) {
			free(buffer_raw);
			return MTLLIB_BUFFER_ISSUE;
		}

    }
	else {
		return MTLLIB_NULL_PARAMS;
	}

	free(buffer_raw);
    return MTLLIB_OK;
}

/*****************************************************************
 * Write a memory buffer to a file
 ******************************************************************
 * @return MTLLIB_OK on success, other on error
 */
MTLLIB_STATUS buffer_to_file(char* filename, MTLLIB_BUFFER* buffer) {
	FILE* output_file = NULL;
	int fd = -1;

	if((filename != NULL) && (buffer != NULL)) {
		fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR); 
		if (fd < 0) { 
			perror("Error opening file");
            return MTLLIB_BUFFER_ISSUE; // Exit with an error code 
		} 
        output_file = fdopen(fd, "wb");
        if (output_file == NULL) {
            perror("Error opening file");
            return MTLLIB_BUFFER_ISSUE; // Exit with an error code
        }
	}
    if (output_file == NULL) {
        return MTLLIB_BUFFER_ISSUE;
    }            
    if(fwrite(mtllib_buffer_data_ptr(buffer), mtllib_buffer_in_use(buffer), 1, output_file) == 0) {
        return MTLLIB_BUFFER_ISSUE;
    }
    fclose(output_file);
    return MTLLIB_OK;
}