/*
    Copyright (c) 2024, VeriSign, Inc.
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

#include "mtltool_io.h"
#include "mtlverify.h"
#include "mtl_example_util.h"
#include "mtl_spx.h"
#include "mtl_util.h"
#include "schemes.h"

/*****************************************************************
 * Parse a ladder from a buffer and verify it if possible
 ******************************************************************
 * @param ctx            An initialized MTL context
 * @param algo           Alogorithm for verifying ladder signature
 * @param buffer         Byte buffer containing the ladder
 * @param buffer_len     Length of the buffer
 * @param curr_ladder    Pointer which will return the current ladder
 * @param pk             Pointer to the public key fr verification
 * @param verbose_buffer File pointer (or null) for the verbose output
 * @param encoding       Output format desired (e.g. Base64 encoded?)
 * @param signed_ladder  Flag to print the long signature or not
 * @param quiet_mode     Flag to only print error messages
 * @return MTLSTATUS indicating MLT_OK or error value
 */
MTLSTATUS parse_ladder(MTL_CTX *ctx, ALGORITHM *algo, uint8_t *buffer,
                     size_t buffer_len, LADDER **curr_ladder, uint8_t *pk,
                     FILE *verbose_buffer, data_encoding encoding,
                     uint8_t signed_ladder, bool quiet_mode)
{
    uint8_t *underlying_buffer = NULL;
    OQS_SIG *sig = NULL;
    uint32_t underlying_buffer_len;
    uint32_t underlying_sig_len;
    MTLSTATUS return_code = 0;

    size_t ladder_buff_len = 0;
    uint8_t *ladder_sig = NULL;
    size_t ladder_sig_len = 0;
    LADDER *ladder = NULL;
    size_t cache_ladder_size = 0;

    // Verify the ladder signature
    sig = OQS_SIG_new(algo->oqs_str);
    if (sig == NULL)
    {
        return 2;
    }

    // Get the ladder from the buffer
    ladder_buff_len = mtl_ladder_from_buffer((char*)buffer, buffer_len, algo->sec_param, ctx->sid.length, &ladder);
    if (ladder_buff_len == 0) {
		LOG_ERROR("Unable to read ladder from buffer");
		return MTL_ERROR;
	}
    mtl_print_ladder(ladder, verbose_buffer);

    // Verify the signature on the ladder if it is provided
    if (buffer_len - ladder_buff_len > 100)
    {
        LOG_MESSAGE("MTL ladder includes a signature for validation", verbose_buffer);
        ladder_sig = buffer + ladder_buff_len;
        ladder_sig_len = buffer_len - ladder_buff_len;
        mtl_print_ladder_signature(ladder_sig, ladder_sig_len, verbose_buffer);

        // Get the scheme separated ladder buffer
        underlying_buffer_len = mtl_get_scheme_separated_buffer(ctx, ladder,
                                                                ctx->nodes.hash_size, &underlying_buffer, algo->oid, algo->oid_len);
        mtl_print_mtl_buffer("MTL Scheme Separated Buffer", underlying_buffer, underlying_buffer_len, verbose_buffer);

        // Get the signature length incase it is helpful
        bytes_to_uint32(ladder_sig, &underlying_sig_len);

        // Verify the signature
        if (OQS_SIG_verify(sig, underlying_buffer, underlying_buffer_len,
                           ladder_sig + 4, sig->length_signature, pk) != OQS_SUCCESS)
        {
            return_code = MTL_BOGUS;
            *curr_ladder = NULL;
            mtl_ladder_free(ladder);
        }
        else
        {
            return_code = MTL_OK;
            *curr_ladder = ladder;

            if (quiet_mode == false)
            {
                // Output the ladder buffer
                cache_ladder_size = ladder_buff_len;
                if((encoding == BASE64_STRING) && (signed_ladder)) {
                    cache_ladder_size = buffer_len;
                }
                if((encoding == HEX_STRING) && (signed_ladder)) {
                    cache_ladder_size += sig->length_signature + 4;
                }

                printf(" Validated ladder buffer for cache:       ");
                mtl_write_buffer(buffer, cache_ladder_size, stdout, encoding, true);
            }
        }
        free(underlying_buffer);
    }
    else
    {
        LOG_MESSAGE("MTL ladder does not include a signature to validate the ladder\n", verbose_buffer);
        return_code = MTL_BOGUS;
        *curr_ladder = ladder;
    }
    if (sig != NULL)
    {
        OQS_SIG_free(sig);
    }

    return return_code;
}

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
 * Setup a public key
 ******************************************************************
 * @param algo           MTL alogorithm identifier used
 * @param pkey           Public key used to sign the ladder
 * @param sid            MTL Series Identifier used
 * @param ctx_str        Optional signature context string
 * @return MTL context for verification of MTL signatures
 */
MTL_CTX *setup_public_key(ALGORITHM *algo, uint8_t *pkey,
                          SERIESID *sid, char *ctx_str)
{
    MTL_CTX *mtl_ctx = NULL;
    SEED seed;
    SPX_PARAMS *params = NULL;
    MTLSTATUS return_code;

    if (algo == NULL)
    {
        fprintf(stderr, "mtlverify - ERROR, invalid or unrecognized key\n");
        return mtl_ctx;
    }

    // Data needed for operation
    PKSEED_INIT(seed, pkey, algo->sec_param);
    return_code = mtl_initns(&mtl_ctx, &seed, sid, ctx_str);
    if(return_code != MTL_OK){
        LOG_ERROR_WITH_CODE("mtl_initns",return_code);
    }

    // Algorithm Selection
    params = malloc(sizeof(SPX_PARAMS));
    params->robust = algo->robust;

    // Initalize the parameters
    PKSEED_INIT(params->pk_seed, pkey, algo->sec_param);
    PKROOT_INIT(params->pk_root, pkey + algo->sec_param,
                algo->sec_param);
    SKPRF_CLEAR(params->prf, algo->sec_param);

    // Setup the signature scheme specific functions
    if (algo->algo == SPX_ALG_SHAKE)
    {
        mtl_set_scheme_functions(mtl_ctx, params, 0,
                                 spx_mtl_node_set_hash_message_shake,
                                 spx_mtl_node_set_hash_leaf_shake,
                                 spx_mtl_node_set_hash_int_shake, ctx_str);
    }
    else if (algo->algo == SPX_ALG_SHA2)
    {
        mtl_set_scheme_functions(mtl_ctx, params, 0,
                                 spx_mtl_node_set_hash_message_sha2,
                                 spx_mtl_node_set_hash_leaf_sha2,
                                 spx_mtl_node_set_hash_int_sha2, ctx_str);
    }
    else
    {
        printf("ERROR: Bad algorithm\n");
        free(mtl_ctx);
        mtl_ctx = NULL;
    }

    mtl_ctx->randomize = 1;
    return mtl_ctx;
}

/*****************************************************************
 * Print the algorithms supported
 ******************************************************************
 *
 */
static void print_algorithms()
{
    uint16_t algo_idx = 0;

    printf("    SUPPORTED ALGORITHMS\n");
    while (algos[algo_idx].name != NULL)
    {
        printf("      %s\n", algos[algo_idx].name);
        algo_idx++;
    }
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
    printf("      -q              Do not print non-error messages");
    printf("      -s              Output the ladder signature with the validated ladder\n");
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
    print_algorithms();
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
    ALGORITHM *algorithm = NULL;
    uint8_t *keyparam = NULL;
    size_t keyparam_len = 0;
    uint8_t *msgparam = NULL;
    size_t msgparam_len = 0;
    uint8_t *sigparam = NULL;
    size_t sigparam_len = 0;
    uint8_t *ladparam = NULL;
    size_t ladparam_len = 0;
    data_encoding format = HEX_STRING;
    bool provide_signed_ladder = false;
    uint8_t verify_status = 255;
    MTL_CTX *mtl_ctx = NULL;
    AUTHPATH *auth_path;
    RANDOMIZER *mtl_rand;
    uint32_t sig_size = 0;
    LADDER *full_ladder = NULL;
    LADDER *cache_ladder = NULL;
    size_t full_sig_len = 0;
    char *ctx_str = NULL;
    FILE *verbose_buffer = NULL;
    char *ladder_filename = NULL;
    bool quiet_mode = false;

    while ((flag = getopt(argc, argv, "bhl:qsv")) != -1)
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
            provide_signed_ladder = true;
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
        algorithm = get_underlying_signature(mtl_str2upper(argv[0]), algos);
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
            if (ladder_filename != NULL)
            {
                free(ladder_filename);
            }
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
                if (ladder_filename != NULL)
                {
                    free(ladder_filename);
                }
                LOG_ERROR("Invalid ladder parameter input\n");
                exit(2);
            }
        }
    }
    mtl_print_signature_scheme(algorithm, verbose_buffer);

    // Fetch the signature parameters
    sig_size = mtl_auth_path_from_buffer((char *)sigparam, sigparam_len, algorithm->sec_param, 8, &mtl_rand, &auth_path);
    if (sig_size == 0)
    {
        if (ladder_filename != NULL)
        {
            free(ladder_filename);
        }
        LOG_ERROR("ERROR: Authentication Path is Invalid\n");
        exit(3);
    }

    // Setup the key for this validation
    mtl_ctx = setup_public_key(algorithm, keyparam, &auth_path->sid, ctx_str);

    // If a cached ladder was provided, try to validate the signature with it
    if (ladparam_len != 0)
    {
        LOG_MESSAGE("Verifying MTL signature with cached ladder:", verbose_buffer);
        verify_status = parse_ladder(mtl_ctx, algorithm, ladparam, ladparam_len, &cache_ladder, keyparam, verbose_buffer, format, provide_signed_ladder, quiet_mode);
        // Status can be 0 (Ladder and signature verify) or 1 (Ladder is ok but no signature)
        if ((verify_status == 0) || (verify_status == 1))
        {
            verify_status = verify_auth_path(mtl_ctx, auth_path, cache_ladder, msgparam, msgparam_len, mtl_rand, verbose_buffer);
            if(verify_status == MTL_OK) {
                LOG_MESSAGE("MTL authentication path was successfully validated", verbose_buffer);
                mtl_print_mtl_buffer("Condensed Signature", sigparam, sig_size, verbose_buffer);
            }
            else
            {
                LOG_MESSAGE("MTL authentication failed validation\n", verbose_buffer);
            }
        }
        else
        {
            LOG_MESSAGE("Unable to validate the cached ladder", verbose_buffer);
        }

        if (cache_ladder != NULL)
        {
            mtl_ladder_free(cache_ladder);
            cache_ladder = NULL;
        }
    }
    // See if the MTL signature is a full signature and validate it if possible
    if (verify_status != 0)
    {
        full_sig_len = sigparam_len - sig_size;
        if (full_sig_len > 100)
        {
            LOG_MESSAGE("Verifying MTL signature with ladder from full signature:", verbose_buffer);
            verify_status = parse_ladder(mtl_ctx, algorithm, sigparam + sig_size, full_sig_len, &full_ladder, keyparam, verbose_buffer, format, provide_signed_ladder, quiet_mode);
            // Satus has to be 0 as there is no other ladder to use
            if (verify_status == 0)
            {
                verify_status = verify_auth_path(mtl_ctx, auth_path, full_ladder, msgparam, msgparam_len, mtl_rand, verbose_buffer);
                if (verify_status == 0)
                {
                    LOG_MESSAGE("MTL authentication path was successfully validated", verbose_buffer);
                    mtl_print_mtl_buffer("Condensed Signature", sigparam, sig_size, verbose_buffer);
                }
                else
                {
                    LOG_MESSAGE("MTL authentication failed validation", verbose_buffer);
                }
            }
            else
            {
                LOG_MESSAGE("Unable to validate the provided ladder", verbose_buffer);
            }

            if (full_ladder != NULL)
            {
                mtl_ladder_free(full_ladder);
                full_ladder = NULL;
            }
        }
        else
        {
            LOG_MESSAGE("There is no ladder to use for validating this signature.  Please fetch a valid ladder.\n", verbose_buffer);
            verify_status = 2;
        }
    }

    // Free the data that was created above
    if (ladder_filename != NULL)
    {
        free(ladder_filename);
    }
    mtl_randomizer_free(mtl_rand);
    mtl_authpath_free(auth_path);
    free(mtl_ctx->sig_params);
    mtl_free(mtl_ctx);

    free(keyparam);
    free(sigparam);
    free(msgparam);
    if (ladparam != NULL)
    {
        free(ladparam);
    }

    return (verify_status);
}
