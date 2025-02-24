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
#include <sys/stat.h>


#include <oqs/sig.h>

#include "mtltool_io.h"
#include "mtl_example_util.h"
#include "mtl_spx.h"
#include "mtl_util.h"
#include "schemes.h"

#include "mtlsign.h"

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
    SERIESID sid;
    OQS_SIG *sig = NULL;
    FILE *fd;
    MTL_CTX *mtl_ctx = NULL;
    SEED seed;
    ALGORITHM *algo = get_underlying_signature(keystr, algos);
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t ret_code = 0;
    uint32_t i = 0;

    if (algo == NULL)
    {
        printf("ERROR: The algorithm (%s) was not found\n", keystr);
        return 1;
    }
    if (keyfilename == NULL) {
        printf("ERROR: the key filename was invalid\n");
        return 1;
    }
    // Create the new underlying singnature and allocate space for keys
    sig = OQS_SIG_new(algo->oqs_str);
    if (sig == NULL)
    {
        printf("ERROR: Unable to initalize keys\n");
        return 2;
    }
    public_key = malloc(sig->length_public_key);
    secret_key = malloc(sig->length_secret_key);

    if ((public_key == NULL) || (secret_key == NULL))
    {
        printf("ERROR: Unable allocate key memory\n");
        return 1;
    }
    // Poplulate the public and secret keys
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS)
    {
        printf("ERROR: Unable generate keys\n");
        return 2;
    }

    // Create the MTL Attributes
    fd = fopen("/dev/random", "r");
    if(fd == NULL) {
        // Unable to get the needed randomization
        printf("ERROR: cannot generate the appropriate random values\n");
        return 3;
    }
    sid.length = 8;
    fread(sid.id, sid.length, 1, fd);
    fclose(fd);

    seed.length = algo->sec_param;
    // Note SPHINCS+ PK = (PK.seed, PK.root)
    memcpy(&seed.seed, public_key, seed.length);
    mtl_initns(&mtl_ctx, &seed, &sid, ctx_str);

    ret_code =
        write_key_file(keyfilename, secret_key, sig->length_secret_key,
                       public_key, sig->length_public_key, keystr,
                       algo->randomize, mtl_ctx);

    printf("Public Key,%s,", keystr);
    for (i = 0; i < sig->length_public_key; i++)
    {
        printf("%02x", public_key[i]);
    }
    printf("\n");

    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);
    mtl_free(mtl_ctx);

    return ret_code;
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
    printf("\n MTL Example Keygen Tool    %s\n", MTL_LIB_VERSION);
    printf(" ---------------------------------------------------------------------\n");
    printf(" Usage: mtlkeygen [options] key_file algorithm_str [context_str]\n");
    printf("\n    RETURN VALUE\n");
    printf("      0 on success or number for error\n");
    printf("\n    OPTIONS\n");
    printf("      -h    Print this tool usage help message\n");
    printf("\n    PARAMETERS\n");
    printf("      key_file      The key_file name/path where the generated key should be stored\n");
    printf("      algorithm_str The algorithm string for type of key to generate\n");
    printf("                    See the list of supported algorithm strings below\n");
    printf("      context_str   An optional context string to use with this key\n");
    printf("\n    EXAMPLE USAGE\n");
    printf("      mtlkeygen ./testkey.key SPHINCS+-MTL-SHA2-128S-SIMPLE\n");
    printf("\n");
    print_algorithms();
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

	// Setup example outputs (key and signatures) to be
	// read and write only for owner of application
	umask(0133);

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
        printf("ERROR: Not enough arguments\n");
        print_usage();
        return (1);
    }

    // Check that the key filename is not in existence
    if (access(argv[0], F_OK) == 0) {
        printf("ERROR: key file already exists\n");
        return (1);
    }
    algo_str = mtl_str2upper(argv[1]);

    // Context String?
    if (argc > 2)
    {
        context_str = argv[2];
    }

    result = new_key(algo_str, argv[0], context_str);

    free(keyfilename);

    return result;
}
