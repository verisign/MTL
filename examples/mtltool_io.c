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
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#include "mtl_error.h"
#include "mtl.h"
#include "mtl_spx.h"
#include "mtl_example_util.h"

#define PKSEED_INIT(ptr, value, len)  {ptr.length=len; memcpy(ptr.seed, value, len);}
#define PKROOT_INIT(ptr, value, len)  {ptr.length=len; memcpy(ptr.key, value, len);}
#define SKPRF_INIT(ptr, value, len)   {ptr.length=len; memcpy(ptr.data, value, len);}
#define SKPRF_CLEAR(ptr, len)        {ptr.length=len; memset(ptr.data, 0, len);}

extern ALGORITHM algos[];

/*****************************************************************
 * Write the key information to a file
 ****************************************************************** 
 * @param keyfilename, name for the keyfile to generate 
 * @param sk, secret key value
 * @param sk_len, length of the secret key
 * @param pk, public key value
 * @param pk_len, length of the public key 
 * @param keystr: string name of the used signature algorithm
 * @param randomize: flag indicating if randomization should be used
 * @param mtl_ctx, MTL context that includes signed nodes
 * @return 0 for success and 1 for failure
 */
uint8_t write_key_file(char *keyfilename, uint8_t * sk, uint32_t sk_len,
		       uint8_t * pk, uint32_t pk_len, char *keystr,
		       uint16_t randomize, MTL_CTX * mtl_ctx)
{
	uint32_t tree_pages = 0;
	uint32_t randomizer_pages = 0;
	uint32_t index;
	uint32_t id_str_length;
	FILE *keyfile = NULL;
	uint8_t ctx_str_len = 0;

	// Setup example outputs (key and signatures) to be
	// read and write only for owner of application
	umask(0133);

	if ((keyfile = fopen(keyfilename, "wb")) == NULL) {
		LOG_ERROR("Unable to open the keyfile");
		return 1;
	}
	// Save the key data
	// ID String & Length
	id_str_length = strlen(keystr);
	fwrite(&id_str_length, 4, 1, keyfile);
	fwrite(keystr, id_str_length, 1, keyfile);

	// Secret Key & Length - Note not encrypted (for demo purposes only)
	fwrite(&sk_len, 4, 1, keyfile);
	fwrite(sk, sk_len, 1, keyfile);

	// Public Key & Length 
	fwrite(&pk_len, 4, 1, keyfile);
	fwrite(pk, pk_len, 1, keyfile);

	// If Randomizer is used
	fwrite(&randomize, 2, 1, keyfile);

	// Write the context string if any
	if(mtl_ctx->ctx_str != NULL) {
		ctx_str_len = strlen(mtl_ctx->ctx_str);
		fwrite(&ctx_str_len, 1, 1, keyfile);
		fwrite(mtl_ctx->ctx_str, ctx_str_len, 1, keyfile);	
	} else {
		fwrite(&ctx_str_len, 1, 1, keyfile);
	}

	// Save the MTL tree data
	fwrite(&mtl_ctx->sid.id, mtl_ctx->sid.length, 1, keyfile);
	// Leaf Count
	fwrite(&mtl_ctx->nodes.leaf_count, 4, 1, keyfile);
	// Hash Size    
	fwrite(&mtl_ctx->nodes.hash_size, 2, 1, keyfile);
	for (index = 0; index < MTL_TREE_MAX_PAGES; index++) {
		if (mtl_ctx->nodes.tree_pages[index] != NULL) {
			tree_pages++;
		}
	}
	// Tree Hash Count
	fwrite(&tree_pages, 4, 1, keyfile);
	for (index = 0; index < MTL_TREE_RANDOMIZER_PAGES; index++) {
		if (mtl_ctx->nodes.randomizer_pages[index] != NULL) {
			randomizer_pages++;
		}
	}
	// Tree Randomizer Count
	fwrite(&randomizer_pages, 4, 1, keyfile);

	// Tree pages
	for (index = 0; index < tree_pages; index++) {
		fwrite(mtl_ctx->nodes.tree_pages[index],
		       mtl_ctx->nodes.tree_page_size, 1, keyfile);
	}
	// Randomizer pages
	for (index = 0; index < randomizer_pages; index++) {
		fwrite(mtl_ctx->nodes.randomizer_pages[index],
		       mtl_ctx->nodes.tree_page_size, 1, keyfile);
	}

	fclose(keyfile);
	return 0;
}

/*****************************************************************
 * Read the key information to a file
 ****************************************************************** 
 * @param keyfilename, name for the keyfile to read
 * @param sk, secret key value
 * @param sk_len, length of the secret key
 * @param pk, public key value
 * @param pk_len, length of the public key 
 * @param keystr: string name of the used signature algorithm
 * @param randomize: flag indicating if randomization should be used
 * @param mtl_ctx, MTL context that includes signed nodes
 * @return 0 for success and 1 for failure
 */
uint8_t read_key_file(char *keyfilename, uint8_t ** sk, uint32_t * sk_len,
		      uint8_t ** pk, uint32_t * pk_len, char **keystr,
		      uint16_t * randomize, MTL_CTX ** mtl_ctx)
{
	uint32_t tree_pages = 0;
	uint32_t randomizer_pages = 0;
	uint32_t index = 0;
	uint32_t length = 0;
	uint32_t leaf_count = 0;
	int32_t hash_size = 0;
	SEED seed;
	SERIESID sid;
	MTL_CTX *mtl;
	FILE *keyfile = NULL;
	uint16_t ctx_str_len = 0;
	char* ctx_str;
	MTLSTATUS return_code;

	if ((keyfile = fopen(keyfilename, "rb")) == NULL) {
		LOG_ERROR("Unable to open the keyfile");
		return 1;
	}
	// Save the key data
	// ID String & Length
	if(fread(&length, 4, 1, keyfile) != 1) {
		return 2;
	}
	if(length > MTL_MAX_BUFFER_SIZE) {
		return 2;
	}
	*keystr = calloc(1, length + 1);
	if(*keystr == NULL) {
		fclose(keyfile);
		return 2;
	}
	if(fread(*keystr, length, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;
		return 2;
	}

	// Secret Key & Length - Note not encrypted (for demo purposes only)
	if(fread(sk_len, 4, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		return 2;
	}
	if(*sk_len > EVP_MAX_MD_SIZE * 2) {
		free(*keystr);
		*keystr = NULL;		
		return 2;
	}
	*sk = calloc(1, *sk_len);
	if(*sk == NULL) {
		free(*keystr);
		*keystr = NULL;		
		return 2;		
	}
	if(fread(*sk, *sk_len, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		return 2;
	}

	// Public Key & Length 
	if(fread(pk_len, 4, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		return 2;
	}
	if(*pk_len > EVP_MAX_MD_SIZE) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		return 2;
	}
	*pk = calloc(1, *pk_len);
	if(*pk == NULL) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		return 2;		
	}
	if(fread(*pk, *pk_len, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		return 2;
	}

	// If Randomizer is used
	if(fread(randomize, 2, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		free(*pk);
		*pk = NULL;		
		return 2;
	}

	// Read the context string if any
	if(fread(&ctx_str_len, 1, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		free(*pk);
		*pk = NULL;		
		return 2;
	}
	if(ctx_str_len > 256) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		free(*pk);
		*pk = NULL;		
		return 2;		
	}
	if(ctx_str_len == 0) {
		ctx_str = NULL;
	} else {
		ctx_str = calloc(1, ctx_str_len);
		if(ctx_str == NULL) {
			free(*keystr);
			*keystr = NULL;		
			free(*sk);
			*sk = NULL;
			free(*pk);
			*pk = NULL;		
			return 2;			
		}
		fread(ctx_str, ctx_str_len, 1, keyfile);
	}

	// Setup the MTL Context
	sid.length = 8;
	if(fread(&sid.id, sid.length, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		free(*pk);
		*pk = NULL;		
		return 2;
	}
	// Leaf Count
	if(fread(&leaf_count, 4, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		free(*pk);
		*pk = NULL;		
		return 2;
	}
	// Hash Size
	if(fread(&hash_size, 2, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		free(*pk);
		*pk = NULL;		
		return 2;
	}
	if(hash_size < 0 || hash_size > EVP_MAX_MD_SIZE) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		free(*pk);
		*pk = NULL;		
		return 3;		
	}

	PKSEED_INIT(seed, *pk, hash_size);
	return_code = mtl_initns(&mtl, &seed, &sid, ctx_str);
	if(return_code != MTL_OK)
	{
		LOG_ERROR_WITH_CODE("mtl_initns",return_code);
		return MTL_ERROR;
	}
	free(ctx_str);

	mtl->nodes.leaf_count = leaf_count;
	mtl->nodes.hash_size = (uint16_t)hash_size;
	// Tree Page Count
	if(fread(&tree_pages, 4, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		free(*pk);
		*pk = NULL;		
		return 2;
	}
	// Randomizer Page Count
	if(fread(&randomizer_pages, 4, 1, keyfile) != 1) {
		free(*keystr);
		*keystr = NULL;		
		free(*sk);
		*sk = NULL;
		free(*pk);
		*pk = NULL;		
		return 2;
	}

	for (index = 0; index < tree_pages; index++) {
		mtl->nodes.tree_pages[index] =
		    malloc(mtl->nodes.tree_page_size);
		if(mtl->nodes.tree_pages[index] == NULL) {
			free(*keystr);
			*keystr = NULL;				
			free(*sk);
			*sk = NULL;
			free(*pk);
			*pk = NULL;		
			return 2;			
		}
		if(fread(mtl->nodes.tree_pages[index], mtl->nodes.tree_page_size,
		      1, keyfile) != 1) {
			free(*keystr);
			*keystr = NULL;				
			free(*sk);
			*sk = NULL;
			free(*pk);
			*pk = NULL;		
			return 2;
		}
	}

	for (index = 0; index < randomizer_pages; index++) {
		mtl->nodes.randomizer_pages[index] =
		    malloc(mtl->nodes.tree_page_size);
		if(mtl->nodes.randomizer_pages[index] == NULL) {
			free(*keystr);
			*keystr = NULL;				
			free(*sk);
			*sk = NULL;
			free(*pk);
			*pk = NULL;		
			return 2;	
		}
		if(fread(mtl->nodes.randomizer_pages[index],
		      mtl->nodes.tree_page_size, 1, keyfile) != 1) {
			free(*keystr);
			*keystr = NULL;				
			free(*sk);
			*sk = NULL;
			free(*pk);
			*pk = NULL;		
			return 2;				
		}
	}

	*mtl_ctx = mtl;

	fclose(keyfile);
	return 0;
}

/*****************************************************************
 * Load a MTL private key from a file
 ****************************************************************** 
 * @param keyfilename, name for the keyfile to read
 * @param sk, secret key value
 * @param sk_len, length of the secret key
 * @param pk, public key value
 * @param pk_len, length of the public key 
 * @param keystr: string name of the used signature algorithm
 * @param randomize: flag indicating if randomization should be used
 * @param mtl_ctx, MTL context that includes signed nodes
 * @param params, the scheme specific parameter set
 * @param algo_type, the scheme specific algorithm type 
 * @return 0 for success and 1 for failure
 */
uint8_t load_private_key(char *keyfilename, uint8_t ** sk, uint32_t * sk_len,
			 uint8_t ** pk, uint32_t * pk_len, char **keystr,
			 uint16_t * randomize, MTL_CTX ** mtl_ctx,
			 void **params, uint8_t * algo_type)
{
	SPX_PARAMS *param_ptr;
	ALGORITHM *algo = NULL;

	if (read_key_file
	    (keyfilename, sk, sk_len, pk, pk_len, keystr, randomize,
	     mtl_ctx) != 0) {
		return 1;
	}

	if ((algo = get_underlying_signature(*keystr, algos)) == NULL) {
		return 1;
	}
	*algo_type = algo->algo;

	// Create the scheme specific parameters
	if ((*algo_type == SPX_ALG_SHAKE) || (*algo_type == SPX_ALG_SHA2)) {
		param_ptr = malloc(sizeof(SPX_PARAMS));
		param_ptr->robust = algo->robust;

		PKSEED_INIT(param_ptr->pk_seed, *pk, algo->sec_param);
		PKROOT_INIT(param_ptr->pk_root, *pk + algo->sec_param,
			    algo->sec_param);
		SKPRF_INIT(param_ptr->prf, *sk + algo->sec_param,
			   algo->sec_param);
		*params = param_ptr;
	} else {
		LOG_ERROR("Unsupported Algorithm Type");
	}

	return 0;
}

/*****************************************************************
 * Load a MTL public key from a file
 ****************************************************************** 
 * @param keyfilename, name for the keyfile to read
 * @param pk, public key value
 * @param pk_len, length of the public key 
 * @param keystr: string name of the used signature algorithm
 * @param randomize: flag indicating if randomization should be used
 * @param mtl_ctx, MTL context that includes signed nodes
 * @param params, the scheme specific parameter set
 * @param algo_type, the scheme specific algorithm type
 * @return 0 for success and 1 for failure
 */
uint8_t load_public_key(char *keyfilename, uint8_t ** pk, uint32_t * pk_len,
			char **keystr, uint16_t * randomize, MTL_CTX ** mtl_ctx,
			void **params, uint8_t * algo_type)
{
	SPX_PARAMS *param_ptr;
	uint8_t *sk;
	uint32_t sk_len;
	ALGORITHM *algo = NULL;

	if (read_key_file
	    (keyfilename, &sk, &sk_len, pk, pk_len, keystr, randomize,
	     mtl_ctx) != 0) {
		return 1;
	}

	if ((algo = get_underlying_signature(*keystr, algos)) == NULL) {
		return 1;
	}
	*algo_type = algo->algo;

	// Create the scheme specific parameters
	if ((*algo_type == SPX_ALG_SHAKE) || (*algo_type == SPX_ALG_SHA2)) {
		param_ptr = malloc(sizeof(SPX_PARAMS));
		param_ptr->robust = algo->robust;

		PKSEED_INIT(param_ptr->pk_seed, *pk, algo->sec_param);
		PKROOT_INIT(param_ptr->pk_root, *pk + algo->sec_param,
			    algo->sec_param);
		SKPRF_CLEAR(param_ptr->prf, algo->sec_param);
		*params = param_ptr;
	} else {
		LOG_ERROR("Unsupported Algorithm Type");
	}
	free(sk);
	return 0;
}
