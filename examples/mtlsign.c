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

#include "mtltool_io.h"
#include "mtl_example_util.h"
#include "mtl_spx.h"
#include "mtl_util.h"
#include "schemes.h"

#include "mtlsign.h"

#define PRIVATE_KEY_FAIL \
    if (*keystr != NULL) \
    {                    \
        free(*keystr);   \
        *keystr = NULL;  \
    }                    \
    if (*sk != NULL)     \
    {                    \
        free(*sk);       \
        *sk = NULL;      \
    }                    \
    if (*pk != NULL)     \
    {                    \
        free(*pk);       \
        *pk = NULL;      \
    }                    \
    return NULL;

/*****************************************************************
 * Setup a private key
 ******************************************************************
 * @param pkey          Private key buffer
 * @param pkey_length   Length of the private key buffer
 * @param sk, secret key value
 * @param sk_len, length of the secret key
 * @param pk, public key value
 * @param pk_len, length of the public key
 * @param keystr: string name of the used signature algorithm
 * @param randomize: flag indicating if randomization should be used
 * @param params, Underlying singnature scheme parameters
 * @param algo_type, Algorithm type identifier 
 * @return MTL context for verification of MTL signatures
 */
MTL_CTX *setup_private_key(uint8_t *pkey, size_t pkey_len,
                           uint8_t **sk, uint32_t *sk_len,
                           uint8_t **pk, uint32_t *pk_len, char **keystr,
                           uint16_t *randomize, void **params, uint8_t *algo_type)
{
    MTL_CTX *mtl_ctx = NULL;
    SEED seed;
    uint32_t tree_pages = 0;
    uint32_t randomizer_pages = 0;
    uint32_t index = 0;
    uint32_t length = 0;
    uint32_t leaf_count = 0;
    uint16_t hash_size = 0;
    SERIESID sid;
    uint8_t ctx_str_len = 0;
    char *ctx_str;
    size_t offset = 0;
    SPX_PARAMS *param_ptr;
    ALGORITHM *algo = NULL;

    if (pkey == NULL)
    {
        fprintf(stderr, "mtlverify - ERROR, invalid or unrecognized key\n");
        return mtl_ctx;
    }

    if (pkey_len - offset > 4)
    {
        // ID String & Length
        if (bytes_to_uint32(pkey + offset, &length) == 0)
        {
            PRIVATE_KEY_FAIL;
        }
        offset += 4;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }
    if (pkey_len - offset > length)
    {
        *keystr = calloc(1, length + 1);
        memcpy(*keystr, pkey + offset, length);
        offset += length;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }

    if ((algo = get_underlying_signature(*keystr, algos)) == NULL)
    {
        PRIVATE_KEY_FAIL
    }
    *algo_type = algo->algo;

    // Create the scheme specific parameters
    if ((*algo_type == SPX_ALG_SHAKE) || (*algo_type == SPX_ALG_SHA2))
    {
        param_ptr = malloc(sizeof(SPX_PARAMS));
        param_ptr->robust = algo->robust;

        PKSEED_INIT(param_ptr->pk_seed, *pk, algo->sec_param);
        PKROOT_INIT(param_ptr->pk_root, *pk + algo->sec_param,
                    algo->sec_param);
        SKPRF_INIT(param_ptr->prf, *sk + algo->sec_param,
                   algo->sec_param);
        *params = param_ptr;
    }
    else
    {
        LOG_ERROR("Unsupported Algorithm Type");
    }

    // Secret Key & Length - Note not encrypted (for demo purposes only)
    if (pkey_len - offset > 4)
    {
        if (bytes_to_uint32(pkey + offset, sk_len) == 0)
        {
            PRIVATE_KEY_FAIL;
        }
        offset += 4;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }
    if (pkey_len - offset > *sk_len)
    {
        *sk = calloc(1, *sk_len);
        memcpy(*sk, pkey + offset, *sk_len);
        offset += *sk_len;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }

    // Public Key & Length
    if (pkey_len - offset > 4)
    {
        if (bytes_to_uint32(pkey + offset, pk_len) == 0)
        {
            PRIVATE_KEY_FAIL;
        }
        offset += 4;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }
    if (pkey_len - offset > *pk_len)
    {
        *pk = calloc(1, *pk_len);
        memcpy(*pk, pkey + offset, *pk_len);
        offset += *pk_len;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }

    // If Randomizer is used
    if (pkey_len - offset > 2)
    {
        if (bytes_to_uint16(pkey + offset, randomize) == 0)
        {
            free(*sk);
            *sk = NULL;
            free(*pk);
            *pk = NULL;
            return NULL;
        }
        offset += 2;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }

    // Read the context string if any
    if (pkey_len - offset > 1)
    {
        ctx_str_len = pkey[offset];
        offset += 1;

        if (ctx_str_len == 0)
        {
            ctx_str = NULL;
        }
        else
        {
            ctx_str = calloc(1, ctx_str_len);
            memcpy(ctx_str, pkey + offset, ctx_str_len);
            offset += ctx_str_len;
        }
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }

    // Setup the MTL Context
    sid.length = 8;
    if (pkey_len - offset > sid.length)
    {
        memcpy(sid.id, pkey + offset, sid.length);
        offset += sid.length;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }

    // Leaf Count
    if (pkey_len - offset > 4)
    {
        if (bytes_to_uint32(pkey + offset, &leaf_count) == 0)
        {
            PRIVATE_KEY_FAIL;
        }
        offset += 4;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }

    // Hash Size
    if (pkey_len - offset < 2)
    {
        PRIVATE_KEY_FAIL
        if (bytes_to_uint16(pkey + offset, &hash_size) == 0)
        {
            PRIVATE_KEY_FAIL;
        }
        offset += 4;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }
    if (hash_size > EVP_MAX_MD_SIZE)
    {
        PRIVATE_KEY_FAIL;
    }

    PKSEED_INIT(seed, *pk, hash_size);
    mtl_initns(&mtl_ctx, &seed, &sid, ctx_str);
    free(ctx_str);

    mtl_ctx->nodes.leaf_count = leaf_count;
    mtl_ctx->nodes.hash_size = (uint16_t)hash_size;
    // Tree Page Count
    if (pkey_len - offset > 4)
    {
        if (bytes_to_uint32(pkey + offset, &tree_pages) == 0)
        {
            PRIVATE_KEY_FAIL;
        }
        offset += 4;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }

    // // Randomizer Page Count
    if (pkey_len - offset > 4)
    {
        if (bytes_to_uint32(pkey + offset, &randomizer_pages) == 0)
        {
            PRIVATE_KEY_FAIL;
        }
        offset += 4;
    }
    else
    {
        PRIVATE_KEY_FAIL;
    }

    for (index = 0; index < tree_pages; index++)
    {
        mtl_ctx->nodes.tree_pages[index] =
            malloc(mtl_ctx->nodes.tree_page_size);
        if (pkey_len - offset > mtl_ctx->nodes.tree_page_size)
        {
            memcpy(mtl_ctx->nodes.tree_pages[index], pkey + offset, mtl_ctx->nodes.tree_page_size);
            offset += mtl_ctx->nodes.tree_page_size;
        }
        else
        {
            PRIVATE_KEY_FAIL;
        }
    }

    for (index = 0; index < randomizer_pages; index++)
    {
        mtl_ctx->nodes.randomizer_pages[index] =
            malloc(mtl_ctx->nodes.tree_page_size);
        if (pkey_len - offset > mtl_ctx->nodes.tree_page_size)
        {
            memcpy(mtl_ctx->nodes.randomizer_pages[index], pkey + offset, mtl_ctx->nodes.tree_page_size);
            offset += mtl_ctx->nodes.tree_page_size;
        }
        else
        {
            PRIVATE_KEY_FAIL;
        }
    }

    return mtl_ctx;
}

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
    printf("      -b            Message files and signatures use base64 encoding rather than binary data in hex format\n");
    printf("      -h            Print this help message\n");
    printf("      -i= NodeID    Get the latest signature info for a NodeID rather than signing a message\n");
    printf("      -l            Produce full signatures instead of condensed signature\n");
    printf("      -v            Use verbose output\n");
    printf("\n    PARAMETERS\n");
    printf("      key_file      The key_file name/path where the generated key should be read/updated\n");
    printf("      msg_file_x    File that contains the message to sign (in binary or base64 format)\n");
    printf("\n    EXAMPLE USAGE\n");
    printf("      mtlsign -l -i 0 ./testkey.key ./message1.bin ./message2.bin\n");
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
    uint8_t *msgparam = NULL;
    size_t msgparam_len = 0;
    data_encoding format = HEX_STRING;
    bool provide_signed_ladder = false;
    MTL_CTX *mtl_ctx = NULL;
    AUTHPATH *auth_path;
    RANDOMIZER *mtl_rand;
    uint32_t sig_size = 0;
    FILE *verbose_buffer = NULL;
    uint32_t leaf_index = 0;
    SPX_PARAMS *params = NULL;
    uint8_t algo_type = ALG_NONE;

    uint8_t *sk;
    uint32_t sk_len;
    uint8_t *pk;
    uint32_t pk_len;
    char *keystr;
    uint16_t randomize;
    LADDER *ladder = NULL;
    uint8_t *ladder_sig = NULL;
    size_t ladder_sig_len;
    uint8_t *sig_buffer = NULL;
    uint8_t *ladder_buffer = NULL;
    uint32_t ladder_buffer_len = 0;
    uint8_t *underlying_buffer = NULL;
    uint32_t underlying_buffer_len = 0;
    OQS_SIG *sig = NULL;
    char *keyfilename = NULL;
    leaf_queue *leaves = NULL;
    leaf_queue *last_leaf = NULL;
    bool key_updated = false;
    FILE *output = stdout;
    uint8_t overlap = 0;    
    size_t ladder_write_len = 0;
    size_t sig_write_len = 0;
    uint8_t* sig_write = NULL;


    while ((flag = getopt(argc, argv, "bhlvi:")) != -1)
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
            provide_signed_ladder = true;
            break;
        case 'v':
            verbose_buffer = stdout;
            break;
        case 'i':
            // Add the leaf index to the queue to later print
            if (leaves == NULL)
            {
                leaves = calloc(1, sizeof(leaf_queue));
                last_leaf = leaves;
            }
            else
            {
                last_leaf->next = calloc(1, sizeof(leaf_queue));
                last_leaf = last_leaf->next;
            }
            last_leaf->leaf_id = atol(optarg);
            last_leaf->filename = NULL;

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
    keyfilename = realpath(argv[0], NULL);
    if(keyfilename == NULL) {
        fprintf(stderr, "ERROR - Unable to load key file\n");
        return (2);        
    }
    // Do any filtering on the message_file here to restrict access if desired

    // Load the key
    if (load_private_key(keyfilename, &sk, &sk_len, &pk, &pk_len, &keystr, &randomize,
                         &mtl_ctx, (void *)&params, &algo_type) != 0)
    {
        fprintf(stderr, "ERROR - Unable to load key file\n");
        return (2);
    }
    argc--;
    argv++;

    ALGORITHM *algo = get_underlying_signature(keystr, algos);
    if (algo == NULL)
    {
        return (1);
    }

    // Algorithm Selection
    if (algo_type == SPX_ALG_SHAKE)
    {
        mtl_set_scheme_functions(mtl_ctx, params, randomize,
                                 spx_mtl_node_set_hash_message_shake,
                                 spx_mtl_node_set_hash_leaf_shake,
                                 spx_mtl_node_set_hash_int_shake, mtl_ctx->ctx_str);
    }
    else if (algo_type == SPX_ALG_SHA2)
    {
        mtl_set_scheme_functions(mtl_ctx, params, randomize,
                                 spx_mtl_node_set_hash_message_sha2,
                                 spx_mtl_node_set_hash_leaf_sha2,
                                 spx_mtl_node_set_hash_int_sha2, mtl_ctx->ctx_str);
    }
    else
    {
        printf("ERROR: Bad algorithm\n");
        return (1);
    }

    mtl_print_signature_scheme(algo, verbose_buffer);

    while (argc > 0)
    {
        char *message_file = realpath(argv[0], NULL);
        if(message_file == NULL) {
            LOG_ERROR("Message file does not exist!");
            return (2);     
        }        
        // Do any filtering on the message_file here to restrict access if desired

        // Read message from file
        FILE *msg_file = fopen(message_file, "rb");
        if(msg_file == NULL) {
            LOG_ERROR("Message file does not exist!");
            return (2);           
        }
        fseek(msg_file, 0, SEEK_END);
        size_t msg_file_len = ftell(msg_file);
        fseek(msg_file, 0, SEEK_SET);

        if (msg_file_len > MTL_MAX_BUFFER_SIZE)
        {
            LOG_ERROR("Invalid message length, exceeds max buffer");
            return (1);
        }

        uint8_t *message = malloc(msg_file_len + 1);
        if(message == NULL) {
            LOG_ERROR("Unable to allocate memory");
            return (1);           
        }
        fread(message, msg_file_len, 1, msg_file);
        fclose(msg_file);

        // Convert it to bin if necessary
        if (format == BASE64_STRING)
        {
            msgparam_len = mtl_buffer2bin(message, msg_file_len, &msgparam, format);
            if(mtl_hash_and_append(mtl_ctx, msgparam, msgparam_len, &leaf_index) != MTL_OK) {
                LOG_ERROR("Unable to add message to node set");
                return (1); 
            }
            free(msgparam);
        }
        else
        {
            if(mtl_hash_and_append(mtl_ctx, message, msg_file_len, &leaf_index) != MTL_OK) {
                LOG_ERROR("Unable to add message to node set");
                return (1);                 
            }
        }
        key_updated = true;
        free(message);

        // Add the leaf index to the queue to later print
        if (leaves == NULL)
        {
            leaves = calloc(1, sizeof(leaf_queue));
            last_leaf = leaves;
        }
        else
        {
            last_leaf->next = calloc(1, sizeof(leaf_queue));
            last_leaf = last_leaf->next;
        }
        last_leaf->leaf_id = leaf_index;
        last_leaf->filename = message_file;

        argc--;
        argv++;
    }

    // For leaf index in queue generate the auth path
    leaf_queue *tmp_leaf = leaves;
    while (leaves != NULL)
    {
        if (leaves->leaf_id < mtl_ctx->nodes.leaf_count)
        {
            mtl_randomizer_and_authpath(mtl_ctx, leaves->leaf_id, &mtl_rand, &auth_path);

            sig_size =
                mtl_auth_path_to_buffer(mtl_rand, auth_path,
                                        mtl_ctx->nodes.hash_size, &sig_buffer);

            if (leaves->filename != NULL)
            {
                printf("%s,%u,", leaves->filename, leaves->leaf_id);
            }
            else
            {
                printf(",%u,", leaves->leaf_id);
            }

            // auth_path to bytes (hex or base64)
            mtl_write_buffer(sig_buffer, sig_size, output, format, true);
            mtl_authpath_free(auth_path);
            mtl_randomizer_free(mtl_rand);
            free(sig_buffer);
        }
        tmp_leaf = leaves;
        leaves = leaves->next;
        free(tmp_leaf->filename);
        free(tmp_leaf);
    }

    // Generate the signed ladder
    if (provide_signed_ladder == true)
    {
        // Generate and sign ladder (if requested)
        ladder = mtl_ladder(mtl_ctx);
        ladder_buffer_len = mtl_ladder_to_buffer(ladder, mtl_ctx->nodes.hash_size, &ladder_buffer);

        // Get the scheme separated ladder buffer
        underlying_buffer_len =
            mtl_get_scheme_separated_buffer(mtl_ctx, ladder,
                                            mtl_ctx->nodes.hash_size,
                                            &underlying_buffer, algo->oid, algo->oid_len);
        // Sign the ladder with the underlying scheme
        sig = OQS_SIG_new(algo->oqs_str);
        if (sig == NULL)
        {
            return (2);
        }
        // Ladder length is signature length + 4 bytes (2 extra in case doing b64 below)
        ladder_sig = malloc(sig->length_signature + 6);
        uint32_to_bytes(&ladder_sig[2], sig->length_signature);
        if(OQS_SIG_sign(sig, ladder_sig + 6, &ladder_sig_len, underlying_buffer,
                     underlying_buffer_len, sk) == OQS_ERROR) {
            LOG_ERROR("Unable to sign ladder\n");
            return (2);
        }

        /********************************************************************
         * Output the signed ladder
         * Note: This program writes the ladder buffer then the signature
         *     buffer which has no issues for binary output.  Base64 output
         *     expects a continous buffer as it uses binary blocks of 3 bytes.
         *     Rather than allocate a big chunk of memory, copy to that, then
         *     convert it all to base64 at once we align the first buffer to 
         *     the boundary and squeeze the extra bytes into the second buffer
         *     to prevent the early buffer termination (and thus = in the
         *     middle of the output).
        ********************************************************************/
        ladder_write_len = ladder_buffer_len;
        sig_write_len = sig->length_signature + 4;
        sig_write = &ladder_sig[2];
        if(ladder_buffer_len < 3) {
            LOG_ERROR("Bad ladder length");
            return (2);
        }
        ladder_sig[0] = ladder_buffer[ladder_buffer_len - 2];
        ladder_sig[1] = ladder_buffer[ladder_buffer_len - 1]; 

        if(format == BASE64_STRING) {
            // Align to the nearest 3 bytes
            overlap = ladder_write_len % 3;
            // Adjust the lengths to the 3 byte boundary
            ladder_write_len -= overlap;
            sig_write_len += overlap;
            // Adjust the data to match the length
            sig_write = &ladder_sig[2-overlap];
        }

        // Write the data
        fprintf(output, "Ladder,,");
        mtl_write_buffer(ladder_buffer, ladder_write_len, output, format, false);
        mtl_write_buffer(sig_write, sig_write_len, output, format, true);      

        free(ladder_buffer);
        free(ladder_sig);
        OQS_SIG_free(sig);
        free(underlying_buffer);
        mtl_ladder_free(ladder);
    }

    // Output updated private key
    if ((keyfilename != NULL) && (key_updated == true))
    {
        write_key_file(keyfilename, sk, sk_len, pk, pk_len, keystr,
                       algo->randomize, mtl_ctx);
    }

    free(keystr);
    mtl_free(mtl_ctx);
    free(sk);
    free(pk);
    free(params);
    if (keyfilename != NULL)
    {
        free(keyfilename);
    }
    return (0);
}
