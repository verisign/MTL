/*
	Copyright (c) 2023, VeriSign, Inc.
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
#include <endian.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <oqs/sig.h>

#include "mtltool.h"
#include "mtltool_io.h"
#include "mtl.h"
#include "mtl_util.h"
#include "mtl_spx.h"

#include "schemes.h"

/*****************************************************************
* Get Underlying Signature
******************************************************************
 * @param algo_str, C character string representing the algorithm
 * @return ALGORITHM structure element with the properties for
 *         the specific algorithm, or NULL if not found
 */
ALGORITHM *get_underlying_signature(char *algo_str)
{
	uint16_t algo_idx = 0;

	while (algos[algo_idx].name != NULL) {
		if (strcmp(algos[algo_idx].name, (char *)algo_str) == 0) {
			return &algos[algo_idx];
		}
		algo_idx++;
	}

	return NULL;
}

/*****************************************************************
* Sign each line in an ASCII file and write it to a signature file
******************************************************************
 * @param input, input file to read records from
 * @param output, output file to write signatures to
 * @param ctx, MTL context to use
 * @param oqs_str, underlying signature string in LibOQS form
 * @param sk, secret key to sign with
 * @return 0 on success, other values on failure
 */
uint8_t sign_records(FILE * input, FILE * output, MTL_CTX * ctx,
		     char *oqs_str, uint8_t * sk)
{
	uint8_t buffer[4096];
	size_t buffer_size = 4096;
	AUTHPATH *auth_path = NULL;
	RANDOMIZER *mtl_rand = NULL;
	LADDER *ladder = NULL;
	uint32_t leaf_index;
	QUEUE_NODE *head = NULL;
	QUEUE_NODE *tail = NULL;
	QUEUE_NODE *curr;
	uint8_t *sig_buffer = NULL;
	uint32_t sig_size = 0;
	uint8_t *ladder_buffer = NULL;
	uint32_t ladder_buffer_size = 0;
	uint8_t *underlying_buffer = NULL;
	OQS_SIG *sig = NULL;
	uint8_t *ladder_sig = NULL;
	size_t ladder_sig_len;
	uint32_t underlying_buffer_len = 0;	

	// Iterate through each line in the input file and
	// Add it to the MTL node set.  Since there can be many
	// Save the leaf index and do the ladder/authpath ops
	// Later for all signed records
	while (fgets((char *)&buffer[0], buffer_size, input)) {
		leaf_index =
		    mtl_hash_and_append(ctx, &buffer[0],
					strlen((char *)buffer));
		curr = malloc(sizeof(QUEUE_NODE));
		if (curr == NULL) {
			return 1;
		}
		curr->index = leaf_index;
		curr->next = NULL;

		if (tail == NULL) {
			head = curr;
			tail = curr;
		} else {
			tail->next = curr;
			tail = curr;
		}
	}

	// For each leaf index added, get the auth path
	ladder = mtl_ladder(ctx);
	ladder_buffer_size =
	    mtl_ladder_to_buffer(ladder, ctx->nodes.hash_size, &ladder_buffer);

	// Get the scheme separated ladder buffer
	underlying_buffer_len =
		    mtl_get_scheme_separated_buffer(ctx, ladder,
						    ctx->nodes.hash_size,
						    &underlying_buffer);
	// Sign the ladder with the underlying scheme
	sig = OQS_SIG_new(oqs_str);
	if (sig == NULL) {
		return 2;
	}
	ladder_sig = malloc(sig->length_signature + 4);
	uint32_to_bytes(ladder_sig, sig->length_signature);
	OQS_SIG_sign(sig, ladder_sig + 4, &ladder_sig_len, underlying_buffer,
		     underlying_buffer_len, sk);
	OQS_SIG_free(sig);

	// Create the auth paths for the signed records
	while (head != NULL) {
		mtl_randomizer_and_authpath(ctx, head->index, &mtl_rand,
					    &auth_path);
		curr = head;
		head = head->next;
		free(curr);

		sig_size =
		    mtl_auth_path_to_buffer(mtl_rand, auth_path,
					    ctx->nodes.hash_size, &sig_buffer);

		fwrite(sig_buffer, sig_size, 1, output);
		fwrite(ladder_buffer, ladder_buffer_size, 1, output);
		fwrite(ladder_sig, ladder_sig_len + 4, 1, output);
		free(sig_buffer);

		mtl_authpath_free(auth_path);
		mtl_randomizer_free(mtl_rand);
	}

	free(ladder_buffer);
	free(ladder_sig);
	mtl_ladder_free(ladder);
	return 0;
}

/*****************************************************************
* Verify each signature with its input record
******************************************************************
 * @param input, input file to read records from
 * @param signfd, input handle to the signture data
 * @param ctx, MTL context to use
 * @param oqs_str, underlying signature string in LibOQS form
 * @param sk, secret key to sign with
 * @return 0 on success, other values on failure
 */
uint8_t verify_records(FILE * input, int signfd, MTL_CTX * ctx,
		       char *oqs_str, uint8_t * pk)
{
	struct stat statbuf;
	char *ptr;
	uint32_t sig_size = 0;
	AUTHPATH *auth_path;
	RANDOMIZER *mtl_rand;
	RUNG *rung;
	uint64_t offset = 0;
	uint8_t buffer[4096];
	size_t buffer_size = 4096;
	LADDER *ladder = NULL;
	uint32_t failures = 0;
	uint8_t *underlying_buffer = NULL;
	OQS_SIG *sig = NULL;
	uint8_t *ladder_sig = NULL;
	uint32_t ladder_buffer_size;
	uint32_t underlying_buffer_len;
	uint32_t underlying_sig_len;

	if (fstat(signfd, &statbuf) < 0) {
		printf("ERROR: Unable to open file\n");
		return 1;
	}
	// Map the signature file for reading by the buffer tools
	ptr = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, signfd, 0);
	if (ptr == MAP_FAILED) {
		printf("ERROR: Memory Map Filed\n");
		return 2;
	}
	// Process the file
	while (offset < (uint64_t) statbuf.st_size) {
		// Read the MTL signature
		sig_size =
		    mtl_auth_path_from_buffer(ptr + offset,
					      ctx->nodes.hash_size,
					      ctx->sid.length,
					      &mtl_rand, &auth_path);
		offset += sig_size;

		// And the ladder
		ladder_buffer_size = mtl_ladder_from_buffer(ptr + offset, ctx->nodes.hash_size,
					   ctx->sid.length, &ladder);
		offset += ladder_buffer_size;

		// Verify the ladder signature
		sig = OQS_SIG_new(oqs_str);
		if (sig == NULL) {
			return 2;
		}
		ladder_sig = malloc(sig->length_signature + 4);
		memcpy(ladder_sig, ptr + offset, sig->length_signature + 4);
		offset += sig->length_signature + 4;

		// Get the scheme separated ladder buffer
		underlying_buffer_len =
		    mtl_get_scheme_separated_buffer(ctx, ladder,
						    ctx->nodes.hash_size,
						    &underlying_buffer);

		// Get the signature length incase it is helpful
		bytes_to_uint32(ladder_sig, &underlying_sig_len);

		// Verify the signature
		if (OQS_SIG_verify
		    (sig, underlying_buffer, underlying_buffer_len,
		     ladder_sig + 4, sig->length_signature, pk) != OQS_SUCCESS) {
			failures++;
			free(ladder_sig);
			continue;
		}
		free(ladder_sig);
		OQS_SIG_free(sig);
		free(underlying_buffer);

		// Get the input message
		fgets((char *)&buffer[0], buffer_size, input);

		// Verify the signature
		rung = mtl_rung(auth_path, ladder);
		if (mtl_hash_and_verify
		    (ctx, buffer, strlen((char *)buffer), mtl_rand, auth_path,
		     rung) != 0) {
			failures++;
		}
		mtl_randomizer_free(mtl_rand);
		mtl_authpath_free(auth_path);
		mtl_ladder_free(ladder);
	}

	munmap(ptr, statbuf.st_size);

	return failures;
}

/*****************************************************************
* Generate a new key for the given signature scheme string
******************************************************************
 * @param keystr, key string (from CFRG-MTL-Draft)
 * @param keyfilename, name of file to write key information to
 * @return 0 on success, other values on failure
 */
uint8_t new_key(char *keystr, char *keyfilename)
{
	SERIESID sid;
	OQS_SIG *sig = NULL;
	FILE *fd;
	MTL_CTX *mtl_ctx = NULL;
	SEED seed;
	ALGORITHM *algo = get_underlying_signature(keystr);
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t ret_code = 0;

	if (algo == NULL) {
		return 1;
	}
	// Create the new underlying singnature and allocate space for keys
	sig = OQS_SIG_new(algo->oqs_str);
	if (sig == NULL) {
		return 2;
	}
	public_key = malloc(sig->length_public_key);
	secret_key = malloc(sig->length_secret_key);

	if ((public_key == NULL) || (secret_key == NULL)) {
		return 1;
	}
	// Poplulate the public and secret keys
	if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
		return 2;
	}
	// Create the MTL Attributes
	fd = fopen("/dev/random", "r");
	sid.length = 8;
	fread(sid.id, sid.length, 1, fd);
	fclose(fd);

	seed.length = algo->sec_param;
	// Note SPHINCS+ PK = (PK.seed, PK.root)
	memcpy(&seed.seed, public_key, seed.length);
	mtl_initns(&mtl_ctx, seed, &sid);

	ret_code =
	    write_key_file(keyfilename, secret_key, sig->length_secret_key,
			   public_key, sig->length_public_key, keystr,
			   algo->randomize, mtl_ctx);
	OQS_SIG_free(sig);

	return ret_code;
}

/*****************************************************************
* Convert a string to upper case in place
******************************************************************
 * @param data, string to convert (in place)
 * @return Converted string pointer
 */
static char *str2upper(char *data)
{
	char *p = data;

	for (; *p; ++p)
		*p = toupper(*p);
	return data;
}

/*****************************************************************
* Print the usage for the tool
******************************************************************
 * @return None
 */
static void print_usage(void)
{
	printf("Usage: mtltool keygen <key file> <key string> \n");
	printf
	    ("       mtltool sign   <key file> <data file> <signature file>\n");
	printf
	    ("       mtltool verify <key file> <data file> <signature file>\n");
}

/*****************************************************************
* Print the usage for the tool
******************************************************************
 * @param data, string to convert (in place)
 * @return error status
 */
int main(int argc, char **argv)
{
	char *command = NULL;
	char *algo_str = NULL;
	FILE *input;
	FILE *sign;
	MTL_CTX *mtl_ctx = NULL;
	SPX_PARAMS *params = NULL;
	uint8_t algo_type = ALG_NONE;
	uint8_t *sk;
	uint32_t sk_len;
	uint8_t *pk;
	uint32_t pk_len;
	char *keystr;
	uint16_t randomize;
	uint8_t results;
	int failures;

	printf("\n MTL Example Signature Tool    v.1.0.0\n");
	command = "help";
	if (argc >= 2) {
		command = str2upper(argv[1]);
	}
	printf("  Operation: %s\n", command);
	if (RANDOMIZE) {
		printf("  Randomizer: Enabled\n");
	} else {
		printf("  Randomizer: Disabled\n");
	}

	// The following commmands are exclusive as you can only
	// run one at a time.
	// Generate a Key
	if (strcmp(command, "KEYGEN") == 0) {
		if (argc < 4) {
			printf("%s not enough arguments\n", command);
			print_usage();
			return (1);
		}
		printf("  Keyfile: %s\n", argv[2]);
		printf("  Signing Algorithm: %s\n", argv[3]);
		algo_str = str2upper(argv[3]);

		return new_key(algo_str, argv[2]);
	}
	// Sign a set of ASCII records from a datafile
	if (strcmp(command, "SIGN") == 0) {
		if (argc < 5) {
			printf("%s not enough arguments\n", command);
			print_usage();
			return (1);
		}
		printf("  Keyfile: %s\n", argv[2]);
		printf("  Data File: %s\n", argv[3]);
		printf("  Signature File: %s\n", argv[4]);

		// Load the key         
		if (load_private_key
		    (argv[2], &sk, &sk_len, &pk, &pk_len, &keystr, &randomize,
		     &mtl_ctx, (void *)&params, &algo_type) != 0) {
			fprintf(stderr, "ERROR - Unable to load key file\n");
			return (2);
		}
		// Algorithm Selection
		if (algo_type == SPX_ALG_SHAKE) {
			mtl_set_scheme_functions(mtl_ctx, params, randomize,
						 spx_mtl_node_set_hash_message_shake,
						 spx_mtl_node_set_hash_leaf_shake,
						 spx_mtl_node_set_hash_int_shake);
		} else if (algo_type == SPX_ALG_SHA2) {
			mtl_set_scheme_functions(mtl_ctx, params, randomize,
						 spx_mtl_node_set_hash_message_sha2,
						 spx_mtl_node_set_hash_leaf_sha2,
						 spx_mtl_node_set_hash_int_sha2);
		} else {
			printf("ERROR: Bad algorithm\n");
			return (1);
		}

		// Verify the data files can be opend
		input = fopen(argv[3], "r");
		sign = fopen(argv[4], "wb");
		if ((input == NULL) || (sign == NULL)) {
			printf
			    ("ERROR: Unable to open the input and signature files\n");
			return (1);
		}

		ALGORITHM *algo = get_underlying_signature(keystr);
		if (algo == NULL) {
			return (1);
		}
		// Sign the records
		sign_records(input, sign, mtl_ctx, algo->oqs_str, sk);
		fclose(input);
		fclose(sign);

		// Save the MTL state for the next run
		results =
		    write_key_file(argv[2], sk, sk_len, pk, pk_len, keystr,
				   randomize, mtl_ctx);
		mtl_free(mtl_ctx);
		free(params);

		return results;
	}
	// Verify a set of ASCII records from a datafile using the binary
	// signature data in the signature file 
	if (strcmp(command, "VERIFY") == 0) {
		if (argc < 5) {
			printf("%s not enough arguments\n", command);
			print_usage();
			return (1);
		}
		printf("  Keyfile: %s\n", argv[2]);
		printf("  Data File: %s\n", argv[3]);
		printf("  Signature File: %s\n", argv[4]);

		// Load the key 
		if (load_public_key
		    (argv[2], &pk, &pk_len, &keystr, &randomize, &mtl_ctx,
		     (void *)&params, &algo_type) != 0) {
			fprintf(stderr, "ERROR - Unable to load key file\n");
			return (2);
		}
		// Algorithm Selection
		if (algo_type == SPX_ALG_SHAKE) {
			mtl_set_scheme_functions(mtl_ctx, params, randomize,
						 spx_mtl_node_set_hash_message_shake,
						 spx_mtl_node_set_hash_leaf_shake,
						 spx_mtl_node_set_hash_int_shake);
		} else if (algo_type == SPX_ALG_SHA2) {
			mtl_set_scheme_functions(mtl_ctx, params, randomize,
						 spx_mtl_node_set_hash_message_sha2,
						 spx_mtl_node_set_hash_leaf_sha2,
						 spx_mtl_node_set_hash_int_sha2);
		} else {
			printf("ERROR: Bad algorithm\n");
			return (1);
		}

		int signfd = open(argv[4], O_RDONLY);
		input = fopen(argv[3], "r");
		if ((input == NULL) || (signfd == -1)) {
			printf
			    ("ERROR: Unable to open the input and signature files %p %d\n",
			     input, signfd);
			return (1);
		}

		ALGORITHM *algo = get_underlying_signature(keystr);
		if (algo == NULL) {
			return (1);
		}

		failures =
		    verify_records(input, signfd, mtl_ctx, algo->oqs_str, pk);
		close(signfd);
		fclose(input);
		// Free all the MTL key variables
		mtl_free(mtl_ctx);
		free(params);
		free(keystr);
		free(pk);

		return failures;
	}
	// Print out the help usade information
	if (strcmp(command, "help") == 0) {
		print_usage();
		return (0);
	}

	printf("Invalid command %s\n", command);
	print_usage();
	return (1);
}
