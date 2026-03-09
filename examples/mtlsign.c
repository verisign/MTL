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

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <oqs/sig.h>

#include "mtllib.h"

#include "mtlsign.h"



/*****************************************************************
 * Print the usage for the tool
 ******************************************************************
 * @return None
 */
static void print_usage(void)
{
    printf("\n MTL Example Signature Tool    %s\n", MTL_LIB_VERSION);
    printf(" ---------------------------------------------------------------------\n");
    printf(" Usage: mtlsign [options] key_file msg_file_1 msg_file_2 ...\n");
    printf("\n    RETURN VALUE\n");
    printf("      0 on success or number for error\n");
    printf("\n    OPTIONS\n");
    printf("      -h            Print this help message\n");
    printf("      -r            Reconstruct full signatures from the same ladder rather\n");
    printf("                      than generating a fresh signed ladder each time\n");
    printf("\n    PARAMETERS\n");
    printf("      key_file      The key_file name/path where the generated key should be read\n");
    printf("      msg_file_x    File that contains the message to sign (in binary or base64 format)\n");
    printf("\n    EXAMPLE USAGE\n");
    printf("      mtlsign ./testkey.key ./message1.bin ./message2.bin\n");
    printf("\n");    
}

/*****************************************************************
 * MTL Signing Tool
 ******************************************************************
 * @param argc Argument count
 * @param argv Argument values
 * @return 0 for success or value for error status
 */
int main(int argc, char **argv)
{
    char flag;
    bool reconstruct = false;
    char *key_filename = NULL;
    char *message_filename = NULL;  
    char output_filename[256+15];
    size_t key_file_size = 0;
    MTLLIB_BUFFER *key_buffer = NULL;
    MTLLIB_CTX* ctx = NULL;
    MTL_HANDLE *handle = NULL;
    MTLLIB_BUFFER *message = NULL;
    MTLLIB_BUFFER *ladder = NULL;
    MTLLIB_BUFFER *condensed_sig = NULL;
    MTLLIB_BUFFER *full_sig = NULL;
    MTLLIB_STATUS mtllib_errno;
    int i = 0;
    MTL_INDEX leaf_max = 0;

    // Gracefully shutdown upon encountering an error
    #define HANDLE_ERRORS(status_code) \
    if(status_code != MTLLIB_OK)\
    {\
        fprintf(stderr, "Error signing\n");\
        mtllib_buffer_free(key_buffer);\
        mtllib_buffer_free(ladder);\
        mtllib_buffer_free(condensed_sig);\
        mtllib_buffer_free(full_sig);\
        mtllib_sign_free_handle(&handle);\
        exit(status_code);\
    }

	// Setup default file permissions (key and signatures)
    // to be read and write only for owner of application
	umask(0177);

    while ((flag = getopt(argc, argv, "hr")) != -1)
    {
        switch (flag)
        {
        case 'h':
            print_usage();
            exit(0);
            break;
        case 'r':
            reconstruct = true;
            break;
        default:
            break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 1)
    {
        printf("Error: not enough arguments\n");
        print_usage();
        return (1);
    }
    key_filename = argv[0];
    argc -= 1;
    argv += 1;

    // Load the key
    mtllib_errno = buffer_from_file(key_filename, &key_buffer);
    HANDLE_ERRORS(mtllib_errno);

    mtllib_errno = mtllib_key_from_buffer(key_buffer, &ctx);
    HANDLE_ERRORS(mtllib_errno);

    mtllib_errno = mtllib_buffer_free(key_buffer);
    HANDLE_ERRORS(mtllib_errno);

    // Sign all the messages in a batch
    for (i = 0; i < argc; i++)
    {
        // Read message from file and add it to the tree
        message_filename = argv[i];
        mtllib_errno = buffer_from_file(message_filename, &message);
        HANDLE_ERRORS(mtllib_errno);

        // Sign the message and add it to the tree
        mtllib_errno = mtllib_sign_append(ctx, message, &handle);
        HANDLE_ERRORS(mtllib_errno);
        leaf_max = handle->leaf_index; // keep track of the maximum added leaf_index

        // Memory cleanup
        mtllib_sign_free_handle(&handle);
        mtllib_buffer_free(message);
    }

    // Output updated state before signatures
    key_file_size = mtllib_key_to_buffer_length(ctx);
    mtllib_errno = mtllib_buffer_initialize(&key_buffer, key_file_size, NULL);
    HANDLE_ERRORS(mtllib_errno);

    mtllib_errno = mtllib_key_to_buffer(ctx, key_buffer);
    HANDLE_ERRORS(mtllib_errno);

    mtllib_errno = buffer_to_file(key_filename, key_buffer);
    HANDLE_ERRORS(mtllib_errno);

    mtllib_errno = mtllib_buffer_free(key_buffer);
    HANDLE_ERRORS(mtllib_errno);

    // Write the signatures to files
    /* Signed Ladder */
    mtllib_errno = mtllib_buffer_initialize(&ladder, mtllib_sign_get_signed_ladder_length(ctx), NULL);
    HANDLE_ERRORS(mtllib_errno);
    mtllib_errno = mtllib_sign_get_signed_ladder(ctx, ladder);
    HANDLE_ERRORS(mtllib_errno);

    strncpy(output_filename, key_filename, 256);
    strncat(output_filename, ".ladder", 8);
    mtllib_errno = buffer_to_file(output_filename, ladder);
    HANDLE_ERRORS(mtllib_errno);

    handle = calloc(1,sizeof(MTL_HANDLE));
    if (handle == NULL) {
        HANDLE_ERRORS(errno);
    }
    for (i = 0; i < argc; i++)
    {
        handle->leaf_index = leaf_max - (argc - 1) + i;
        
        /* Condensed Signatures */
        mtllib_errno = mtllib_buffer_initialize(&condensed_sig, mtllib_sign_get_condensed_sig_length(ctx, handle), NULL);
        HANDLE_ERRORS(mtllib_errno);
        mtllib_errno = mtllib_sign_get_condensed_sig(ctx, handle, condensed_sig);
        HANDLE_ERRORS(mtllib_errno);

        strncpy(output_filename, argv[i], 256);
        strncat(output_filename, ".condensed_sig", 15);
        mtllib_errno = buffer_to_file(output_filename, condensed_sig);
        HANDLE_ERRORS(mtllib_errno);

        /* Full Signatures */
        mtllib_errno = mtllib_buffer_initialize(&full_sig, mtllib_sign_get_full_sig_length(ctx, handle), NULL);
        HANDLE_ERRORS(mtllib_errno);
        if (reconstruct) {
            mtllib_errno = mtllib_buffer_append(full_sig, condensed_sig->buffer_data,condensed_sig->buffer_position);
            HANDLE_ERRORS(mtllib_errno);
            mtllib_errno = mtllib_buffer_append(full_sig, ladder->buffer_data, ladder->buffer_position);
            HANDLE_ERRORS(mtllib_errno);
        }
        else {
            mtllib_errno = mtllib_sign_get_full_sig(ctx, handle, full_sig);
            HANDLE_ERRORS(mtllib_errno);
        }

        strncpy(output_filename, argv[i], 256);
        strncat(output_filename, ".full_sig", 10);
        mtllib_errno = buffer_to_file(output_filename, full_sig);
        HANDLE_ERRORS(mtllib_errno);


        mtllib_buffer_free(condensed_sig);
        mtllib_buffer_free(full_sig);

    }

    // Memory cleanup
    mtllib_buffer_free(ladder);
    mtllib_sign_free_handle(&handle);
    mtllib_key_free(ctx);

    return 0;
}
