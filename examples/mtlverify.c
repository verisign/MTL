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
#include <stdbool.h>

#include <oqs/sig.h>

#include "mtlverify.h"
#include "mtl_example_util.h"
#include "mtllib.h"
#include "mtllib_util.h"

/*****************************************************************
 * Print the usage for the tool
 ******************************************************************
 * @return None
 */
static void print_usage(void)
{
    printf("\n MTL Example Signature Verification Tool    %s\n", MTL_LIB_VERSION);
    printf(" ---------------------------------------------------------------------\n");
    printf(" Usage: mtlverify [options] algorithm_str key_file message_file signature_file [ladder_file]\n");
    printf("\n    RETURN VALUE\n");
    printf("      0 on success or number for error\n");
    printf("\n    OPTIONS\n");
    printf("      -h              Print this help message\n");
    printf("      -t              Trust the cached ladder (do not verify the signature on it)\n");
    printf("      -v              Use verbose output\n");
    printf("\n    PARAMETERS\n");
    printf("      algorithm_str  The algorithms string identifying the algorithm to verify\n");
    printf("      pubkey_file    The file name/path where the public key should be read\n");
    printf("      message_file   File holding the message to verify\n");
    printf("      signature_file File holding the signature on the message (full or condensed)\n");
    printf("      ladder_file    (Optional) holds the signed ladder on the message. Required if signature_file contains a condensed signature\n");
    printf("\n    EXAMPLE USAGE\n");
    printf("      mtlverify ML-DSA-44-MTL-SHAKE-128 keyfile.pub message.txt message.condensed_sig keyfile.ladder\n");
    printf("\n");
    printf("    SUPPORTED ALGORITHMS\n");
    mtllib_key_write_algorithms(stdout);
    printf("\n");
}

/*****************************************************************
 * MTL Signature Verification Tool
 ******************************************************************
 * @param argc Argument count
 * @param argv Argument values
 * @return 0 for success or value for error status
 */
int main(int argc, char **argv)
{
    char flag;
    char *keystr = NULL;
    MTLLIB_STATUS mtllib_errno = MTLLIB_INDETERMINATE;
    char *key_filename = NULL;
    MTLLIB_BUFFER *key_buffer = NULL;
    char *message_filename = NULL;
    MTLLIB_BUFFER *message_buffer = NULL;
    char *signature_filename = NULL;
    MTLLIB_BUFFER *signature_buffer = NULL;
    char *ladder_filename = NULL;
    MTLLIB_BUFFER *ladder_buffer = NULL;
    bool ladder_input = false;
    bool assume_ladder_valid = false;
    MTLLIB_CTX *ctx = NULL;

    // Gracefully shutdown upon encountering an error
    #define HANDLE_ERRORS(status_code) \
    if(status_code != MTLLIB_OK)\
    {\
        mtllib_buffer_free(key_buffer);\
        mtllib_buffer_free(message_buffer);\
        mtllib_buffer_free(signature_buffer);\
        mtllib_buffer_free(ladder_buffer);\
        mtllib_key_free(ctx);\
        printf("ERROR\n");\
        exit(status_code);\
    }

    while ((flag = getopt(argc, argv, "ht")) != -1)
    {
        switch (flag)
        {
        case 'h':
            print_usage();
            exit(0);
            break;
        case 't':
            assume_ladder_valid = true;
            break;
        default:
            break;
        }
    }

    argc -= optind;
    argv += optind;

    // Read input parameters
    if (argc < 4 || argc > 5) {
        printf("Error: wrong number of arguments (%d)\n",argc);
        print_usage();
        exit(1);
    }
    if (argc == 5) {
        ladder_input = true;
    } else {
        ladder_input = false;
    }

    keystr = argv[0];
    key_filename = argv[1];
    message_filename = argv[2];
    signature_filename = argv[3];
    if (ladder_input) {
        ladder_filename = argv[4];
    }

    // Read data from the input files
    mtllib_errno = buffer_from_file(key_filename, &key_buffer);
    HANDLE_ERRORS(mtllib_errno);

    mtllib_errno = buffer_from_file(message_filename, &message_buffer);
    HANDLE_ERRORS(mtllib_errno);

    mtllib_errno = buffer_from_file(signature_filename, &signature_buffer);
    HANDLE_ERRORS(mtllib_errno);

    if (ladder_input) {
        mtllib_errno = buffer_from_file(ladder_filename, &ladder_buffer);
        HANDLE_ERRORS(mtllib_errno);
    }

    // Parse input into data structures
    mtllib_errno = mtllib_pubkey_from_buffer(keystr, &ctx, key_buffer, mtllib_buffer_data_ptr(signature_buffer));
    HANDLE_ERRORS(mtllib_errno);

    // Run verification functions
    if (ladder_input && !assume_ladder_valid) {
        mtllib_errno = mtllib_verify_signed_ladder(ctx, ladder_buffer);
        HANDLE_ERRORS(mtllib_errno);
    }

    mtllib_errno = mtllib_verify(ctx, message_buffer, signature_buffer, ladder_buffer, NULL);

    // Memory cleanup
    mtllib_buffer_free(key_buffer);
    mtllib_buffer_free(message_buffer);
    mtllib_buffer_free(signature_buffer);
    mtllib_buffer_free(ladder_buffer);
    mtllib_key_free(ctx);

    // Both these return codes indicate correct verification; OK_VALIDATED_LADDER occurs when there's no input ladder
    if (mtllib_errno == MTLLIB_OK || mtllib_errno == MTLLIB_OK_VALIDATED_LADDER) {
        printf("Signature ACCEPTED\n");
        return 0;
    }
    else {
        printf("Signature REJECTED\n");
        return mtllib_errno;
    }
}