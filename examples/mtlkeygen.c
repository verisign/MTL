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
#include "mtl_spx.h"
#include "mtl_util.h"

#include "mtllib.h"
#include "mtllib_util.h"

/*****************************************************************
 * Generate a new key for the given signature scheme string
 ******************************************************************
 * @param keystr, key string (from CFRG-MTL-Draft)
 * @param keyfilename, name of file to write key information to
 * @param ctx_str, an optional context string (or NULL)
 * @return 0 on success, other values on failure
 */
uint8_t new_key(char *keystr, char *keyfilename, char *ctx_str)
{
    size_t i = 0;
    MTLLIB_CTX *mtl_ctx = NULL;
    size_t buffer_len = 0;
    uint8_t *buffer = NULL;
    FILE *keyfile = NULL;

    if (keystr == NULL)
    {
        LOG_ERROR("Invalid key algorithm\n");
        return 1;
    }
    if (keyfilename == NULL)
    {
        LOG_ERROR("the key filename was invalid\n");
        return 1;
    }

    if (mtllib_key_new(keystr, &mtl_ctx, ctx_str) != MTLLIB_OK)
    {
        LOG_ERROR("the key filename was invalid\n");
        return 1;
    }

    buffer_len = mtllib_key_to_buffer(mtl_ctx, &buffer);

    if ((buffer == NULL) || (buffer_len == 0))
    {
        LOG_ERROR("Unable to get the key buffer\n");
        return 1;
    }
    // Write the file
    if ((keyfile = fopen(keyfilename, "wb")) == NULL)
    {
        LOG_ERROR("Unable to open the keyfile");
        free(buffer);
        mtllib_key_free(mtl_ctx);
        return 1;
    }
    fwrite(buffer, buffer_len, 1, keyfile);
    free(buffer);
    fclose(keyfile);

    uint8_t *pubkey = NULL;
    size_t key_len = mtllib_key_get_pubkey_bytes(mtl_ctx, &pubkey);

    printf("Public Key,%s,", keystr);
    for (i = 0; i < mtl_ctx->mtl->sid.length; i++)
    {
        printf("%02x", mtl_ctx->mtl->sid.id[i]);
    }
    for (i = 0; i < key_len; i++)
    {
        printf("%02x", pubkey[i]);
    }
    printf("\n");

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
    printf(" Usage: mtlkeygen [options] key_file algorithm_str [context_str]\n");
    printf("\n    RETURN VALUE\n");
    printf("      0 on success or number for error\n");
    printf("\n    OPTIONS\n");
    printf("      -h    Print this tool usage help message\n");
    printf("      -q    Do not print non-error messages");
    printf("\n    PARAMETERS\n");
    printf("      key_file      The key_file name/path where the generated key should be stored\n");
    printf("      algorithm_str The algorithm string for type of key to generate\n");
    printf("                    See the list of supported algorithm strings below\n");
    printf("      context_str   An optional context string to use with this key\n");
    printf("\n    EXAMPLE USAGE\n");
    printf("      mtlkeygen ./testkey.key SPHINCS+-MTL-SHA2-128S-SIMPLE\n");
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
    char *algo_str;
    char *keyfilename = NULL;
    char *context_str = NULL;
    uint8_t result;
    bool quiet_mode = false;

    // Setup example outputs (key and signatures) to be
    // read and write only for owner of application
    umask(0177);

    while ((flag = getopt(argc, argv, "hq")) != -1)
    {
        switch (flag)
        {
        case 'h':
            print_usage();
            exit(0);
            break;
        case 'q':
            quiet_mode = true;
            break;
        default:
            break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 2)
    {
        LOG_ERROR("Not enough arguments\n");
        print_usage();
        return 1;
    }

    // Check that the key filename is not in existence
    if (access(argv[0], F_OK) == 0)
    {
        LOG_ERROR("key file already exists\n");
        return 1;
    }
    algo_str = mtl_str2upper(argv[1]);

    // Use a context string if it is provided
    if (argc > 2)
    {
        context_str = argv[2];
        if (!quiet_mode)
        {
            printf("Using Context String: %s\n", context_str);
        }
    }

    if (algo_str == NULL)
    {
        LOG_ERROR("Invalid key algorithm\n");
        return 1;
    }

    result = new_key(algo_str, argv[0], context_str);

    free(keyfilename);

    return result;
}
