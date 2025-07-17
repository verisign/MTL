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
#include <stdbool.h>

#include <oqs/sig.h>

#include "mtlverify.h"
#include "mtl_example_util.h"
#include "mtllib.h"
#include "mtllib_util.h"

/*****************************************************************
 * Verify the authentication path given a good ladder
 ******************************************************************
 * @param ctx            An initialized MTL context
 * @param auth_path      Authentication path to verify
 * @param ladder         Ladder to use to verify the auth_path
 * @param msg            Message to verify wtih the auth path
 * @param msg_len        Length of the message to verify
 * @param mtl_rand       Randomizer value to use for validation
 * @param verbose_buffer File pointer (or null) for the verbose output
 * @return MTL_OK
 */
MTLSTATUS verify_auth_path(MTL_CTX * ctx, AUTHPATH *auth_path, LADDER* ladder,
                         uint8_t* msg, size_t msg_len, RANDOMIZER *mtl_rand,
                         FILE* verbose_buffer) {
    RUNG *rung;

    // Verify the signature
    rung = mtl_rung(auth_path, ladder);
    if(rung == NULL) { 
        LOG_ERROR("NULL mtl_rung");
        return MTL_NULL_PTR; 
        }

    LOG_MESSAGE("\nMTL Validation - Using the following rung and authentication path:", verbose_buffer);
    mtl_print_rung(rung, verbose_buffer);
    mtl_print_auth_path(auth_path, mtl_rand, ladder->rungs->hash_length, verbose_buffer);
    mtl_print_message(msg, msg_len, verbose_buffer);
    // Only value not printed is the hash of the message

    return mtl_hash_and_verify(ctx, msg, msg_len, mtl_rand, auth_path, rung);
}

/*****************************************************************
 * Print the usage for the tool
 ******************************************************************
 * @return None
 */
static void print_usage(void)
{
    printf("\n MTL Example Signature Verification Tool    %s\n", MTL_LIB_VERSION);
    printf(" ---------------------------------------------------------------------\n");
    printf(" Usage: mtlverify [options] algorithm_str key_file message_str signature_str [ladder_str]\n");
    printf("\n    RETURN VALUE\n");
    printf("      0 on success or number for error\n");
    printf("\n    OPTIONS\n");
    printf("      -b              Message files and signatures use base64 encoding rather than binary data in hex format\n");
    printf("      -h              Print this help message\n");
    printf("      -l= ladder_file File that contains the signed ladder, rather than passing in as a parameter string\n");
    printf("      -q              Do not print non-error messages\n");
    printf("      -s              Output the ladder signature with the validated ladder\n");
    printf("      -t              Trust the cached ladder (do not verify the signature on it)\n");
    printf("      -v              Use verbose output\n");
    printf("\n    PARAMETERS\n");
    printf("      algorithm_str The algorithms string for type of key to generate\n");
    printf("                    See the list of supported algorithm strings below\n");
    printf("      key_file      The key_file name/path where the generated key should be read\n");
    printf("      message_str   Hex string that represents the message to verify (or base64 format if used with -b option)\n");
    printf("      signature_str Hex string that represents the signature on the message (or base64 format if used with -b option)\n");
    printf("      ladder_str    Optinal hex string that represents the signed ladder on the message\n");
    printf("\n    EXAMPLE USAGE (line break added for readability)\n");
    printf("      mtlverify -q SPHINCS+-MTL-SHA2-128S-SIMPLE d568a8c5f343b9fac1ab74367430d417db4d31cb0ad26f6d82af66eaae60928f  883814c80c\n");
    printf("                4310b4f0e8 4b8b1e65b9f506be27c61b82dc03add300008b7da2ad29a8de3c000000000000000000000007000396354149b979b8b1c9\n");
    printf("                81a305129b903fd91f511efc5d83497e54a7c5bd75224cfdfeb120de9dff0eede77b71b2fff0ec -l ./testkey.key\n");    
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
    MTL_ALGORITHM_PROPS *algorithm = NULL;
    uint8_t *keyparam = NULL;
    size_t keyparam_len = 0;
    uint8_t *msgparam = NULL;
    size_t msgparam_len = 0;
    uint8_t *sigparam = NULL;
    size_t sigparam_len = 0;
    uint8_t *ladparam = NULL;
    size_t ladparam_len = 0;
    data_encoding format = HEX_STRING;
    bool provide_verified_ladder = false;
    bool verify_ladder = true;
    uint8_t verify_status = MTLLIB_NO_LADDER;
    AUTHPATH *auth_path;
    RANDOMIZER *mtl_rand;
    uint32_t sig_size = 0;
    char *ctx_str = NULL;
    FILE *verbose_buffer = NULL;
    char *ladder_filename = NULL;
    bool quiet_mode = false;
    MTLLIB_CTX *ctx = NULL;  
    size_t ladder_len = 0;
    LADDER *ladder = NULL;
    bool full_ladder = false;
    size_t condensed_len = 0;
    char* ladder_buffer_ptr = NULL;
    size_t ladder_buffer_len = 0;    

    while ((flag = getopt(argc, argv, "bhl:qstv")) != -1)
    {
        switch (flag)
        {
        case 'b':
            format = BASE64_STRING;
            break;
        case 'h':
            print_usage();
            exit(0);
            break;
        case 'l':
            ladder_filename = realpath(optarg, NULL);
            break;
        case 'q':
            quiet_mode = true;
            break;
        case 's':
            provide_verified_ladder = true;
            break;
        case 't':
            verify_ladder = false;
            break;
        case 'v':
            verbose_buffer = stdout;
            break;
        default:
            break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 4)
    {
        printf("Error: not enough arguments\n");
        print_usage();
        exit(1);
    }
    else
    {
        // Process parameters
        algorithm = mtllib_util_get_algorithm_props(mtl_str2upper(argv[0]));
        if (algorithm == NULL)
        {
            LOG_ERROR("Invalid algorithm parameter input\n");
            exit(2);
        }
        keyparam_len = mtl_buffer2bin((uint8_t *)argv[1], strlen(argv[1]), &keyparam, format);
        msgparam_len = mtl_buffer2bin((uint8_t *)argv[2], strlen(argv[2]), &msgparam, format);
        sigparam_len = mtl_buffer2bin((uint8_t *)argv[3], strlen(argv[3]), &sigparam, format);

        if ((keyparam == NULL) || (msgparam == NULL) || (sigparam == NULL) ||
            (keyparam_len == 0) || (msgparam_len == 0) || (sigparam_len == 0))
        {
            free(ladder_filename);
            LOG_ERROR("Invalid key, mesage, or signature parameter input\n");
            exit(2);
        }

        if (ladder_filename != NULL)
        {
            // Do any filtering on the ladder_filename here to restrict access if desired
            if(format == BASE64_STRING) {
                // Read the ladder from the file
                FILE *ladder_file = fopen(ladder_filename, "rb");
                fseek(ladder_file, 0, SEEK_END);
                size_t hexladparam_len = ftell(ladder_file);
                fseek(ladder_file, 0, SEEK_SET);

                uint8_t* hexladparam = malloc(hexladparam_len);
                if(hexladparam == NULL) {
                    LOG_ERROR("Unable to allocate memory for ladder buffer");
                    exit(2);
                }
                fread(hexladparam, hexladparam_len, 1, ladder_file);
                fclose(ladder_file);

                size_t trim_bytes = 0;
                // Trim any trailing whitespace because EVP_Decode does not like it
                for(size_t i=hexladparam_len-1; i>0; i--) {
                    if(!isspace(hexladparam[i])) {
                        break;
                    }
                    hexladparam[i] = '\0';
                    trim_bytes++;
                }

                ladparam_len = mtl_buffer2bin(hexladparam, hexladparam_len -  trim_bytes, &ladparam, format);
                free(hexladparam);
            } else {
                // Read the ladder from the file
                FILE *ladder_file = fopen(ladder_filename, "rb");
                fseek(ladder_file, 0, SEEK_END);
                ladparam_len = ftell(ladder_file);
                fseek(ladder_file, 0, SEEK_SET);

                if (ladparam_len > MTL_MAX_BUFFER_SIZE)
                {
                    LOG_ERROR("Invalid ladder length, exceeds max buffer");
                    return (1);
                }
                ladparam = malloc(ladparam_len);
                fread(ladparam, ladparam_len, 1, ladder_file);
                fclose(ladder_file);
            }
        }
        else if ((argc > 4) && (ladparam == NULL))
        {
            ladparam_len = mtl_buffer2bin((uint8_t *)argv[4], strlen(argv[4]), &ladparam, format);
            if (ladparam == NULL)
            {
                free(ladder_filename);
                LOG_ERROR("Invalid ladder parameter input\n");
                exit(2);
            }
        }
    }

    // Fetch the signature parameters
    sig_size = mtl_auth_path_from_buffer((char *)sigparam, sigparam_len, algorithm->sec_param, 8, &mtl_rand, &auth_path);
    if (sig_size == 0)
    {
        free(ladder_filename);
        LOG_ERROR("ERROR: Authentication Path is Invalid\n");
        exit(3);
    }

    // Setup the key for this validation
    if(mtllib_key_pubkey_from_params(algorithm->name, &ctx, ctx_str, keyparam + algorithm->sid_len, 
                                     keyparam_len - algorithm->sid_len, keyparam, algorithm->sid_len) != MTLLIB_OK) {
        LOG_ERROR("ERROR: Unable to load the public key\n");
        exit(3);
    }
    if(ctx == NULL) {
        LOG_ERROR("ERROR: Unable to load the public key\n");
        exit(3);        
    }  

    verify_status = MTLLIB_NO_LADDER;
    // If a cached ladder was provided, try to validate the authentication path with it
    if (ladparam_len != 0)
    {
        LOG_MESSAGE("Verifying MTL signature with cached ladder:", verbose_buffer);
        verify_status = mtllib_verify(ctx, msgparam, msgparam_len, sigparam, sigparam_len, ladparam, ladparam_len, NULL);
        if((verify_status == MTLLIB_OK)&&(verify_ladder))
        {                
            verify_status = mtllib_verify_signed_ladder(ctx, ladparam, ladparam_len);
        } 
    }

    // If the cached ladder does not work, see if the MTL signature is a full signature and validate it
    if (verify_status != MTLLIB_OK)
    {
        LOG_MESSAGE("Unable to validate with the cached ladder", verbose_buffer);
        full_ladder = true;
        verify_status = mtllib_verify(ctx, msgparam, msgparam_len, sigparam, sigparam_len, NULL, 0, &condensed_len);
        if(verify_status != MTLLIB_OK)
        {
            LOG_MESSAGE("There is no ladder to use for validating this signature.  Please fetch a valid ladder.\n", verbose_buffer);
            verify_status = MTLLIB_NO_LADDER;
        }
    }

    if(verify_status == MTLLIB_OK)
    {
        LOG_MESSAGE("MTL authentication path was successfully validated", verbose_buffer);
        mtl_print_mtl_buffer("Condensed Signature", sigparam, sig_size, verbose_buffer);
    }

    if ((quiet_mode == false) && (verify_status == MTLLIB_OK) && (provide_verified_ladder))
    {
        // Assume the ladder was an input parameter
        ladder_buffer_ptr = (char*)ladparam;
        ladder_buffer_len = ladparam_len;

        // if the ladder was from a full signature
        if(full_ladder) {
            ladder_buffer_ptr = (char*)sigparam + condensed_len;
            ladder_buffer_len = sig_size - condensed_len;
        }

        // Get the ladder from the buffer
        ladder_len = mtl_ladder_from_buffer(ladder_buffer_ptr, ladder_buffer_len, ctx->algo_params->sec_param, ctx->mtl->sid.length, &ladder);
        if (ladder_len == 0) {
            LOG_ERROR("Unable to read ladder from buffer");
            return MTLLIB_NO_LADDER;
        }

        uint8_t* buffer = NULL;
        ladder_len = mtl_ladder_to_buffer(ladder, ladder->rungs->hash_length, &buffer);
        if (ladder_len == 0) {
            mtl_ladder_free(ladder);
            LOG_ERROR("Unable to read ladder from buffer");
            return MTLLIB_NO_LADDER;
        }

        printf(" Validated ladder buffer for cache:       ");
        mtl_write_buffer(buffer, ladder_len, stdout, format, true);
    }

    // Free the data that was created above
    free(ladder_filename);
    mtl_randomizer_free(mtl_rand);
    mtl_authpath_free(auth_path);
    mtllib_key_free(ctx);

    free(keyparam);
    free(sigparam);
    free(msgparam);
    free(ladparam);

    return (verify_status);
}
