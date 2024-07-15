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

#include <oqs/sig.h>

#include "mtltool.h"
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
 * @return 0 on success, 1 on ladder w/o validation, or int for error
 */
uint8_t parse_ladder(MTL_CTX * ctx, ALGORITHM* algo, uint8_t* buffer,
                     size_t buffer_len, LADDER** curr_ladder, uint8_t* pk,
                     FILE* verbose_buffer, data_encoding encoding,
                     uint8_t signed_ladder) {
    uint8_t *underlying_buffer = NULL;
    OQS_SIG *sig = NULL;
    uint32_t underlying_buffer_len;
    uint32_t underlying_sig_len;
    uint8_t return_code = 0;

    size_t   ladder_buff_len = 0;
    uint8_t* ladder_sig = NULL;
    size_t   ladder_sig_len = 0;
    uint8_t  output_buff[65535];
    uint32_t i;
    LADDER * ladder = NULL;

    // Verify the ladder signature
    sig = OQS_SIG_new(algo->oqs_str);
    if (sig == NULL) {
        return 2;
    }

    // Get the ladder from the buffer
    ladder_buff_len = mtl_ladder_from_buffer((char*)buffer, buffer_len, algo->sec_param, ctx->sid.length, &ladder);
    mtl_print_ladder(ladder, verbose_buffer);


    // Verify the signature on the ladder if it is provided
    if(buffer_len - ladder_buff_len > 100) {
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
                             ladder_sig + 4, sig->length_signature, pk) != OQS_SUCCESS) {
                    return_code = 2;
                    *curr_ladder = NULL;
                    mtl_ladder_free(ladder);
        } else {
            return_code = 0;
            *curr_ladder = ladder;

            // Output the ladder buffer
            printf(" Validated ladder buffer for cache: ");
            if(encoding == BASE64_STRING) {
                if(signed_ladder) {
                    EVP_EncodeBlock(&output_buff[0], buffer, buffer_len);
                    printf("      %s\n", output_buff);				
                } else {
                    EVP_EncodeBlock(&output_buff[0], buffer, ladder_buff_len);
                    printf("      %s\n", output_buff);
                }
            } else {
                if(signed_ladder) {
                    printf("      ");
                    for(i=0; i<ladder_buff_len + sig->length_signature + 4; i++) {
                        printf("%02x", buffer[i]);
                    }
                    printf("\n");					
                } else {
                    printf("      ");
                    for(i=0; i<ladder_buff_len; i++) {
                        printf("%02x", buffer[i]);
                    }
                    printf("\n");
                }
            }		
        }
        free(underlying_buffer);
    } else {
        LOG_MESSAGE("MTL ladder does not include a signature to validate the ladder\n", verbose_buffer);
        return_code = 1;
        *curr_ladder = ladder;		
    }
    if(sig != NULL) {
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
 * @return 0 on success or int value for error
 */
uint8_t verify_auth_path(MTL_CTX * ctx, AUTHPATH *auth_path, LADDER* ladder,
                         uint8_t* msg, size_t msg_len, RANDOMIZER *mtl_rand,
                         FILE* verbose_buffer) {
    RUNG *rung;

    // Verify the signature
    rung = mtl_rung(auth_path, ladder);
    if(rung == NULL) { return 1; }

    LOG_MESSAGE("\nMTL Validation - Using the following rung and authentication path:", verbose_buffer);
    mtl_print_rung(rung, verbose_buffer);
    mtl_print_auth_path(auth_path, mtl_rand, ladder->rungs->hash_length, verbose_buffer);
    mtl_print_message(msg, msg_len, verbose_buffer);
    // Only value not printed is the hash of the message

    return mtl_hash_and_verify(ctx, msg, msg_len, mtl_rand, auth_path,rung);
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
MTL_CTX* setup_public_key(ALGORITHM* algo, uint8_t* pkey,
                                 SERIESID* sid, char* ctx_str) {
    MTL_CTX *mtl_ctx = NULL;
    SEED seed;
    SPX_PARAMS *params = NULL;

    if(algo == NULL) {
        fprintf(stderr, "mtlverify - ERROR, invalid or unrecognized key\n");
        return mtl_ctx;
    }

    // Data needed for operation
    PKSEED_INIT(seed, pkey, algo->sec_param);
    mtl_initns(&mtl_ctx, &seed, sid, ctx_str);

    // Algorithm Selection
    params = malloc(sizeof(SPX_PARAMS));
    params->robust = algo->robust;

    // Initalize the parameters
    PKSEED_INIT(params->pk_seed, pkey, algo->sec_param);
    PKROOT_INIT(params->pk_root, pkey + algo->sec_param,
                algo->sec_param);
    SKPRF_CLEAR(params->prf, algo->sec_param);				

    // Setup the signature scheme specific functions
    if (algo->algo == SPX_ALG_SHAKE) {
        mtl_set_scheme_functions(mtl_ctx, params, 0,
                        spx_mtl_node_set_hash_message_shake,
                        spx_mtl_node_set_hash_leaf_shake,
                        spx_mtl_node_set_hash_int_shake, ctx_str);
    } else if (algo->algo == SPX_ALG_SHA2) {
        mtl_set_scheme_functions(mtl_ctx, params, 0,
                        spx_mtl_node_set_hash_message_sha2,
                        spx_mtl_node_set_hash_leaf_sha2,
                        spx_mtl_node_set_hash_int_sha2, ctx_str);
    } else {
        printf("ERROR: Bad algorithm\n");
        free(mtl_ctx);
        mtl_ctx = NULL;
    }

    mtl_ctx->randomize = 1;
    return mtl_ctx;
}


/*****************************************************************
* Print the usage for the tool
******************************************************************
 * @return None
 */
static void print_usage(void)
{
    printf("\n MTL Example Signature Tool    v.1.1.0\n");
    printf(" ---------------------------------------------------------------------\n");
    printf(" Usage: mtlverify [OPTIONS] algorithm key message signature <ladder>\n");
    printf("    RETURN CODE\n");
    printf("      return value - 0 on success or number for error\n");
    printf("    OPTIONS\n");
    printf("      -b\tInputs are base64 encoded rather than hex strings\n");
    printf("      -h\tPrint this help message\n");
    printf("      -s\tOuptut the ladder signature with the validated ladder\n");
    printf("      -v\tUse verbose output\n");
    printf("    PARAMETERS\n");
    printf("      algorithm (required)\tAlgorithm string for MTL key used to sign message\n");
    printf("      key (required)\t\tpublic key value to use for validation\n");
    printf("      message (required)\tmessage to verify\n");
    printf("      signature (required)\tsignature on message\n");
    printf("      ladder (optional)\t\tLadder for use with condensed signatures\n");
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
    ALGORITHM* algorithm = NULL;
    uint8_t* keyparam = NULL;
    size_t   keyparam_len = 0;
    uint8_t* msgparam = NULL;
    size_t   msgparam_len = 0;
    uint8_t* sigparam = NULL;
    size_t   sigparam_len = 0;
    uint8_t* ladparam = NULL;
    size_t   ladparam_len = 0;	
    data_encoding format = HEX_STRING;
    bool_param provide_signed_ladder = FALSE;
    uint8_t verify_status = 255;
    MTL_CTX *mtl_ctx = NULL;
    AUTHPATH *auth_path;
     RANDOMIZER *mtl_rand;
    uint32_t sig_size = 0;
    LADDER *full_ladder = NULL;
    LADDER *cache_ladder = NULL;
    size_t full_sig_len = 0;
    char* ctx_str = NULL;
    FILE* verbose_buffer = NULL;

    while ((flag = getopt(argc, argv, "bhsv")) != -1) {
        switch (flag) {
            case 'b':
                format = BASE64_STRING;
                break;
            case 'h':
                print_usage();
                exit(0);			
                break;
            case 's':
                provide_signed_ladder = TRUE;
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

    if (argc < 4) {
        printf("Error: not enough arguments\n");
        print_usage();
        exit(1);
    } else {
        //Process parameters
        algorithm = get_underlying_signature(mtl_str2upper(argv[0]), algos);
        if(algorithm == NULL) {
            LOG_ERROR("ERROR: Invalid algorithm parameter input\n");
            exit(2);            
        }
        keyparam_len = mtl_buffer2bin((uint8_t*)argv[1], strlen(argv[1]), &keyparam, format);
        msgparam_len = mtl_buffer2bin((uint8_t*)argv[2], strlen(argv[2]), &msgparam, format);
        sigparam_len = mtl_buffer2bin((uint8_t*)argv[3], strlen(argv[3]), &sigparam, format);
        if((keyparam == NULL)  || (msgparam == NULL)  || (sigparam == NULL) ||
           (keyparam_len == 0) || (msgparam_len == 0) || (sigparam_len == 0))  {
            LOG_ERROR("ERROR: Invalid key, mesage, or signature parameter input\n");
            exit(2);
        }		

        if(argc > 4) {
            ladparam_len = mtl_buffer2bin((uint8_t*)argv[4], strlen(argv[4]), &ladparam, format);		
            if(ladparam == NULL) {
                LOG_ERROR("ERROR: Invalid ladder parameter input\n");
                exit(2);
            }
        }
    }

    mtl_print_signature_scheme(algorithm, verbose_buffer);

    // Fetch the signature parameters
    sig_size = mtl_auth_path_from_buffer((char*)sigparam, sigparam_len, algorithm->sec_param, 8, &mtl_rand, &auth_path);
    if(sig_size == 0) {
        LOG_ERROR("ERROR: Authentication Path is Invalid\n");
        exit(3);
    } 

    // Setup the key for this validation
    mtl_ctx = setup_public_key(algorithm, keyparam, &auth_path->sid, ctx_str);

    // If a cached ladder was provided, try to validate the signature with it
    if(ladparam_len != 0) {
        LOG_MESSAGE("Verifying MTL signature with cached ladder:", verbose_buffer);
        verify_status = parse_ladder(mtl_ctx, algorithm, ladparam, ladparam_len, &cache_ladder, keyparam, verbose_buffer, format, provide_signed_ladder);
        // Status can be 0 (Ladder and signature verify) or 1 (Ladder is ok but no signature)
        if((verify_status == 0)||(verify_status == 1)) {
            verify_status = verify_auth_path(mtl_ctx, auth_path, cache_ladder, msgparam, msgparam_len, mtl_rand, verbose_buffer);
            if(verify_status == 0) {
                LOG_MESSAGE("MTL authentication path was successfully validated", verbose_buffer);
                mtl_print_mtl_buffer("Condensed Signature", sigparam, sig_size, verbose_buffer);
            } else { 
                LOG_MESSAGE("MTL authentication failed validation\n", verbose_buffer);
            }
        } else {
            LOG_MESSAGE("Unable to validate the cached ladder", verbose_buffer);
        }

        if(cache_ladder != NULL) {
            mtl_ladder_free(cache_ladder);
            cache_ladder = NULL;
        }
    } 
    // See if the MTL signature is a full signature and validate it if possible
    if(verify_status != 0) {
        full_sig_len = sigparam_len - sig_size;
        if(full_sig_len > 100) {
            LOG_MESSAGE("Verifying MTL signature with ladder from full signature:", verbose_buffer);		
            verify_status = parse_ladder(mtl_ctx, algorithm, sigparam + sig_size, full_sig_len, &full_ladder, keyparam, verbose_buffer, format, provide_signed_ladder);
            // Satus has to be 0 as there is no other ladder to use
            if(verify_status == 0) {
                verify_status = verify_auth_path(mtl_ctx, auth_path, full_ladder, msgparam, msgparam_len, mtl_rand, verbose_buffer);
                if(verify_status == 0) {
                    LOG_MESSAGE("MTL authentication path was successfully validated", verbose_buffer);
                    mtl_print_mtl_buffer("Condensed Signature", sigparam, sig_size, verbose_buffer);
                } else { 
                    LOG_MESSAGE("MTL authentication failed validation", verbose_buffer);
                }
            } else {
                LOG_MESSAGE("Unable to validate the provided ladder", verbose_buffer);
            }

            if(full_ladder != NULL) {
                mtl_ladder_free(full_ladder);
                full_ladder = NULL;
            }
        } else {
            LOG_MESSAGE("There is no ladder to use for validating this signature.  Please fetch a valid ladder.\n", verbose_buffer);			
            verify_status = 2;
        }
    }

    // Free the data that was created above
    mtl_randomizer_free(mtl_rand);
    mtl_authpath_free(auth_path);
    free(mtl_ctx->sig_params);
    mtl_free(mtl_ctx);

    free(keyparam);
    free(sigparam);
    free(msgparam);
    if(ladparam != NULL) {
        free(ladparam);
    }

    return (verify_status);
}
