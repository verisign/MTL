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

#include "mtl_example_util.h"

#include "mtllib.h"
#include "mtllib_util.h"
#include "mtllib_buffer.h"

/*****************************************************************
 * Generate a new key for the given signature scheme string
 ******************************************************************
 * @param keystr, key string (from CFRG-MTL-Draft)
 * @param key_file, name of file to write secret key information to
 * @param pubkey_file, name of file to write public key information to
 * @return 0 on success, other values on failure
 */
uint8_t new_key(char *keystr, char *key_file, char *pubkey_file)
{
    MTLLIB_CTX *mtl_ctx = NULL;
    MTLLIB_BUFFER *key_buffer = NULL;
    MTLLIB_BUFFER *pubkey_buffer = NULL;
    MTLLIB_STATUS mtllib_errno;
    size_t buffer_length;

    // Gracefully shutdown upon encountering an error
    #define HANDLE_ERRORS(status) \
    if(status != MTLLIB_OK)\
    {\
        fprintf(stderr, "Error generating key\n");\
        mtllib_buffer_free(key_buffer);\
        mtllib_buffer_free(pubkey_buffer);\
        exit(status);\
    }

    // Create a new key for algorithm `keystr' and save it in  `mtl_ctx'
    mtllib_errno = mtllib_key_new(keystr, &mtl_ctx);
    HANDLE_ERRORS(mtllib_errno);

    // Initalize buffers to serialize keys and state before output
    /* Secret Key */
    buffer_length = mtllib_key_to_buffer_length(mtl_ctx);
    mtllib_errno = mtllib_buffer_initialize(&key_buffer, buffer_length, NULL);
    HANDLE_ERRORS(mtllib_errno);
    /* Public Key */
    buffer_length = mtllib_pubkey_to_buffer_length(mtl_ctx);
    mtllib_errno = mtllib_buffer_initialize(&pubkey_buffer, buffer_length, NULL);
    HANDLE_ERRORS(mtllib_errno);

    // Write the keys and state to the buffers
    mtllib_errno = mtllib_key_to_buffer(mtl_ctx, key_buffer);
    HANDLE_ERRORS(mtllib_errno);
    mtllib_errno = mtllib_pubkey_to_buffer(mtl_ctx, pubkey_buffer);
    HANDLE_ERRORS(mtllib_errno);

    // Write buffers to output files
    buffer_to_file(key_file, key_buffer);
    buffer_to_file(pubkey_file, pubkey_buffer);

    // Clean up memory
    mtllib_buffer_free(key_buffer);
    mtllib_buffer_free(pubkey_buffer);
    mtllib_key_free(mtl_ctx);
    return 0;
}

/*****************************************************************
 * Print the usage for the tool
 ******************************************************************
 * @return None
 */
static void print_usage(void)
{
    printf("\n MTL Example Keygen Tool    %s\n", MTL_LIB_VERSION);
    printf(" ---------------------------------------------------------------------\n");
    printf(" Usage: mtlkeygen filename algorithm_str\n");
    printf("\n    RETURN VALUE\n");
    printf("      0 on success or number for error\n");
    printf("\n    OPTIONS\n");
    printf("      -h    Print this tool usage help message\n");
    printf("\n    PARAMETERS\n");
    printf("      filename      The name to use for key files\n");
    printf("      algorithm_str The algorithm string for type of key to generate\n");
    printf("                    See the list of supported algorithm strings below\n");
    printf("\n    EXAMPLE USAGE\n");
    printf("      mtlkeygen my_key SLH-DSA-SHAKE-128s-MTL-SHAKE-128\n");
    printf("\n");
    printf("    SUPPORTED ALGORITHMS\n");
    mtllib_key_write_algorithms(stdout);
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
    char key_filename[256+7] = {0};
    char pubkey_filename[256+7] = {0};

    // Setup example outputs (key and signatures) to be
    // read and write only for owner of application
    umask(0177);

    while ((flag = getopt(argc, argv, "h")) != -1)
    {
        switch (flag)
        {
        case 'h':
            print_usage();
            exit(0);
            break;
        default:
            break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 2)
    {
        fprintf(stderr, "Not enough arguments\n");
        print_usage();
        return 1;
    }
    if (strlen(argv[0]) > 256)
    {
        fprintf(stderr, "Filename too long\n");
        return 1;
    }

    // Open necessary files
    /* Secret key file */
    strncpy(key_filename, argv[0], 256);
    strncat(key_filename, ".key", 7);

    /* Public key file */
    strncpy(pubkey_filename, argv[0], 256);
    strncat(pubkey_filename, ".pub", 7);


    // Generate a key and write to the files
    new_key(argv[1], key_filename, pubkey_filename);

    printf("%s.key generated successfully\n", argv[0]);

    return 0;
}
