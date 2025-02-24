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
/**
 *  \file mtl_spx.h
 *  \brief MTL Mode Functions that are specific to the SPHINCS+ bindings
 *  The functions, data structures, and macros related to the MTL Mode
 *  SPHINCS+ specific operations. This code is required to do MTL Mode
 *  with SPHINCS+ but may not be needed if a different underlying signature
 *  scheme were being used.
*/
#ifndef __MTL_SPX_IMPL_H__
#define __MTL_SPX_IMPL_H__

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "mtl_node_set.h"
#include <math.h>

// Definitions
//@{
/** SPHINCS+ MTL Address - Type for Messages */
#define SPX_ADRS_MTL_MSG 16
/** SPHINCS+ MTL Address - Type for Data */
#define SPX_ADRS_MTL_DATA 17
/** SPHINCS+ MTL Address - Type for Trees */
#define SPX_ADRS_MTL_TREE 18

/** MTL message separator */
#define MTL_MSG_SEP 128
/** MTL ladder domain separator */
#define MTL_LADDER_SEP 129
//@}

//@{
/** SPHINCS+ MTL Address Offset (Uncompressed) - Layer Field */
#define ADRS_LAYER_ADDR 0*4
/** SPHINCS+ MTL Address Offset (Uncompressed) - Tree Field */
#define ADRS_TREE_ADDR 1*4
/** SPHINCS+ MTL Address Offset (Uncompressed) - Type Field */
#define ADRS_TYPE_ADDR 4*4
/** SPHINCS+ MTL Address Offset (Uncompressed) - Address 1 Field */
#define ADRS_ADDR_1 5*4
/** SPHINCS+ MTL Address Offset (Uncompressed) - Address 2 Field */
#define ADRS_ADDR_2 6*4
/** SPHINCS+ MTL Address Offset (Uncompressed) - Address  Field */
#define ADRS_ADDR_3 7*4
//@}

//@{
/** SPHINCS+ MTL Address Total Length (Uncompressed) */
#define ADRS_ADDR_SIZE 32
/** SPHINCS+ MTL Address Length (Uncompressed) - Layer Field */
#define ADRS_LAYER_ADDR_LEN 4
/** SPHINCS+ MTL Address Length (Uncompressed) - Tree Field */
#define ADRS_TREE_ADDR_LEN 12
/** SPHINCS+ MTL Address Length (Uncompressed) - Type Field */
#define ADRS_TYPE_ADDR_LEN 4
/** SPHINCS+ MTL Address Length (Uncompressed) - Address 1 Field */
#define ADRS_ADDR_1_LEN 4
/** SPHINCS+ MTL Address Length (Uncompressed) - Address 2 Field */
#define ADRS_ADDR_2_LEN 4
/** SPHINCS+ MTL Address Length (Uncompressed) - Address 3 Field */
#define ADRS_ADDR_3_LEN 4
//@}

//@{
/** SPHINCS+ MTL Address Offset (Compressed) - Layer Field */
#define ADRS_LAYER_ADDR_C 0	
/** SPHINCS+ MTL Address Offset (Compressed) - Tree Field */
#define ADRS_TREE_ADDR_C  1
/** SPHINCS+ MTL Address Offset (Compressed) - Type Field */
#define ADRS_TYPE_ADDR_C  9
/** SPHINCS+ MTL Address Offset (Compressed) - Address 1 Field */
#define ADRS_ADDR_1_C     13
/** SPHINCS+ MTL Address Offset (Compressed) - Address 2 Field */
#define ADRS_ADDR_2_C     14
/** SPHINCS+ MTL Address Offset (Compressed) - Address 3 Field */
#define ADRS_ADDR_3_C     18
//@}

//@{
/** SPHINCS+ MTL Address Total Length (Compressed) */
#define ADRS_ADDR_SIZE_C 22
/** SPHINCS+ MTL Address Length (Compressed) - Layer Field */
#define ADRS_LAYER_ADDR_C_LEN 1
/** SPHINCS+ MTL Address Length (Compressed) - Tree Field */
#define ADRS_TREE_ADDR_C_LEN  8
/** SPHINCS+ MTL Address Length (Compressed) - Type Field */
#define ADRS_TYPE_ADDR_C_LEN  4
/** SPHINCS+ MTL Address Length (Compressed) - Address 1 Field */
#define ADRS_ADDR_1_C_LEN     1
/** SPHINCS+ MTL Address Length (Compressed) - Address 2 Field */
#define ADRS_ADDR_2_C_LEN     4
/** SPHINCS+ MTL Address Length (Compressed) - Address 3 Field */
#define ADRS_ADDR_3_C_LEN     4
//@}

//@{
/** SPHINCS+ MTL Algorithm Value Definition (SHA2) */
#define SPX_MTL_SHA2 1
/** SPHINCS+ MTL Algorithm Value Definition (SHAKE) */
#define SPX_MTL_SHAKE 2
//@}

// Types & Structures
/**
 * \brief SPHINCS+ Public Key Wrapper Structure.
 */
typedef struct SPK_PUBKEY {
	/** Public Key Byte Value (Max Size is OpenSSL EVP_MAX_MD_SIZE - 64 bytes) */
	uint8_t key[EVP_MAX_MD_SIZE];
	/** Public Key Length */
	uint16_t length;
} SPK_PUBKEY;

/**
 * \brief SPHINCS+ PRF Value Wrapper
 */
typedef struct SPK_PRF {
	/** PRF Byte Value (Max Size is OpenSSL EVP_MAX_MD_SIZE  - 64 bytes) */	
	uint8_t data[EVP_MAX_MD_SIZE];
	/** PRF Length */
	uint16_t length;
} SPK_PRF;

/**
 * \brief Wrapper for the SPHINCS+ parameters used in MTL Mode
 */
typedef struct SPX_PARAMS {
	/** SPHINCS+ Public Key Seed Value */	
	SEED pk_seed;
	/** SPHINCS+ Public Key Root Value */	
	SPK_PUBKEY pk_root;
	/** SPHINCS+ PRF Value */	
	SPK_PRF prf;
	/** Flag indicating if SPHINCS+ srobust mode should be used */
	uint8_t robust;
} SPX_PARAMS;

// Function Prototypes
/**
 * MTL Node Set generate message with PRF SHA2 values
 * @param skprf       secret key prf data pointer
 * @param skprf_len   secret key prf data length
 * @param optrand     msg rand buffer data pointer
 * @param optrand_len msg rand buffer data length
 * @param addrs       address field buffer
 * @param addrs_len   address field buffer length
 * @param message     message buffer data pointer
 * @param message_len message buffer data length
 * @param rmtl        output of the prf function
 * @param hash_len    length of the hash for the scheme
 * @return 0 on success, integer on failure
 */
MTLSTATUS spx_mtl_node_set_prf_msg_sha2(uint8_t * skprf, uint32_t skprf_len,
				      uint8_t * optrand, uint32_t optrand_len,
				      uint8_t * message, uint32_t message_len,
				      uint8_t * rmtl, uint32_t hash_len);
/**
 * MTL Node Set generate message PRF SHAKE values
 * @param skprf       secret key prf data pointer
 * @param skprf_len   secret key prf data length
 * @param optrand     msg rand buffer data pointer
 * @param optrand_len msg rand buffer data length
 * @param addrs       address field buffer
 * @param addrs_len   address field buffer length
 * @param message     message buffer data pointer
 * @param message_len message buffer data length
 * @param rmtl        output of the prf function
 * @param hash_len    length of the hash for the scheme
 * @return 0 on success, integer on failure
 */					  
MTLSTATUS spx_mtl_node_set_prf_msg_shake(uint8_t * skprf, uint32_t skprf_len,
				       uint8_t * optrand, uint32_t optrand_len,
				       uint8_t * message, uint32_t message_len,
				       uint8_t * rmtl, uint32_t hash_len);
/**
 * Build the ADRS structure in compressed format
 * @param mtl_adrs  Bytes array to hold the ADRS structure
 * @param type  single byte ADRS type
 * @param addrs ADRS tree address data (8 bytes when compressed)
 * @param left  MTL tree address left value
 * @param right MTL tree address right value 
 * @return None
 */					   
uint8_t mtlns_adrs_compressed(uint8_t * ADRS, uint8_t type, SERIESID * sid,
			      uint32_t left, uint32_t right);
/**
 * Build the ADRS structure in uncompressed format
 * @param mtl_adrs  Bytes array to hold the ADRS structure
 * @param type  single byte ADRS type
 * @param addrs ADRS tree address data (8 bytes when compressed)
 * @param left  MTL tree address left value
 * @param right MTL tree address right value 
 * @return None
 */				  
uint8_t mtlns_adrs_full(uint8_t * ADRS, uint32_t type, SERIESID * sid,
			uint32_t left, uint32_t right);

/**
 * Hash the message set with the rand using SHA2 algorithms
 * @param params     SPHINCS+ public key seed & key
 * @param rand       PRF based rand for this message
 * @param rand_len   Length of the rand byte array
 * @param msg_buffer Byte array of the message that will be added
 * @param msg_len    Length of the msg_buffer array
 * @param hash       Pointer to byte array where hash is stored
 * @param hash_len   Length of hash byte array
 * @param ctx        MTL signature context string
 * @param rmtl       Generated randomness bytes for the hash
 * @param rmtl_len   Length of the randomness bytes
 * @return 0 if successful
 */
uint8_t spx_mtl_node_set_hash_message_sha2(void *parameters,
					   SERIESID * sid,
					   uint32_t node_id,
					   uint8_t * randomizer,
					   uint32_t randomizer_len,
					   uint8_t * msg_buffer,
					   uint32_t msg_length, uint8_t * hash,
					   uint32_t hash_length, char * ctx,
					   uint8_t ** rmtl, uint32_t * rmtl_len);

/**
 * Hash the message set with the rand using SHAKE algorithms
 * @param params     SPHINCS+ public key seed & key
 * @param rand       PRF based rand for this message
 * @param rand_len   Length of the rand byte array
 * @param msg_buffer Byte array of the message that will be added
 * @param msg_len    Length of the msg_buffer array
 * @param hash       Pointer to byte array where hash is stored
 * @param hash_len   Length of hash byte array
 * @param ctx        MTL signature context string
 * @param rmtl       Generated randomness bytes for the hash
 * @param rmtl_len   Length of the randomness bytes 
 * @return 0 if successful
 */					   
uint8_t spx_mtl_node_set_hash_message_shake(void *parameters,
					    SERIESID * sid,
					    uint32_t node_id,
					    uint8_t * randomizer,
					    uint32_t randomizer_len,
					    uint8_t * msg_buffer,
					    uint32_t msg_length, uint8_t * hash,
					    uint32_t hash_length, char * ctx,
						uint8_t ** rmtl, uint32_t * rmtl_len);
/**
 * Hash the message set with the rand
 * @param params     SPHINCS+ public key seed & key
 * @param sid        Series identifier for this MTL node set
 * @param node_id    Node identifier for this message
 * @param rand       PRF based rand for this message
 * @param rand_len   Length of the rand byte array
 * @param msg_buffer Byte array of the message that will be added
 * @param msg_len    Length of the msg_buffer array
 * @param hash       Pointer to byte array where hash is stored
 * @param hash_len   Length of hash byte array
 * @param ctx        MTL signature context string 
 * @param rmtl       Generated randomness bytes for the hash
 * @param rmtl_len   Length of the randomness bytes 
 * @param algorithm  Type of algorithm used (#defined values) 
 * @return 0 if successful
 */						
MTLSTATUS spx_mtl_node_set_hash_message(void *parameters,
				      SERIESID * sid,
				      uint32_t node_id,
				      uint8_t * randomizer,
				      uint32_t randomizer_len,
				      uint8_t * msg_buffer, uint32_t msg_length,
				      uint8_t * hash, uint32_t hash_length,
				      char * ctx, uint8_t ** rmtl,
					  uint32_t * rmtl_len, uint8_t algorithm);

/**
 * Algorithm 2: Hashing Two Child Nodes to Produce an Internal Node.
 * @param params     SPHINCS+ public key seed & key
 * @param sid        Series ID generated for the MTL node set
 * @param node_left   Node Id for the left child node
 * @param node_right  Node Id for the right child node
 * @param hash_left   Pointer to byte array for left child hash
 * @param hash_right  Pointer to byte array for right child hash
 * @param hash       Pointer where the resulting hash is placed
 * @param hash_len   Length of hash byte array
 * @param algorithm  Type of algorithm used (#defined values) 
 * @return 0 if successful 
 */
MTLSTATUS spx_mtl_node_set_hash_int(void *parameters,
				  SERIESID * sid,
				  uint32_t node_left,
				  uint32_t node_right,
				  uint8_t * hash_left,
				  uint8_t * hash_right, uint8_t * hash,
				  uint32_t hash_len, uint8_t algorithm);

/**
 * Algorithm 1: Hashing a Data Value to Produce a Leaf Node.
 * @param params     SPHINCS+ public key seed & key
 * @param sid        Series ID generated for the MTL node set
 * @param node_id     Message leaf index
 * @param msg_buffer Byte array of the message that will be added
 * @param msg_len    Length of the msg_buffer array
 * @param hash       Pointer to byte array where hash is stored
 * @param hash_len   Length of hash byte array
 * @param algorithm  Type of algorithm used (#defined values) 
 * @return 0 if successful 
 */				  
MTLSTATUS spx_mtl_node_set_hash_leaf(void *parameters, SERIESID * sid,
				   uint32_t node_id, uint8_t * msg_buffer,
				   uint32_t msg_buffer_len, uint8_t * hash,
				   uint32_t hash_len, uint8_t algorithm);

/**
 * Algorithm 1: SHA2 Hashing a Data Value to Produce a Leaf Node.
 * @param params     SPHINCS+ public key seed & key
 * @param sid        Series ID generated for the MTL node set
 * @param node_id     Message leaf index
 * @param msg_buffer Byte array of the message that will be added
 * @param msg_len    Length of the msg_buffer array
 * @param hash       Pointer to byte array where hash is stored
 * @param hash_len   Length of hash byte array
 * @return 0 if successful 
 */
uint8_t spx_mtl_node_set_hash_leaf_sha2(void *parameter,
					SERIESID * sid,
					uint32_t node_id,
					uint8_t * msg_buffer,
					uint32_t msg_buffer_len, uint8_t * hash,
					uint32_t hash_len);

/**
 * Algorithm 1: SHAKE Hashing a Data Value to Produce a Leaf Node.
 * @param params     SPHINCS+ public key seed & key
 * @param sid        Series ID generated for the MTL node set
 * @param node_id     Message leaf index
 * @param msg_buffer Byte array of the message that will be added
 * @param msg_len    Length of the msg_buffer array
 * @param hash       Pointer to byte array where hash is stored
 * @param hash_len   Length of hash byte array
 * @return 0 if successful 
 */					
uint8_t spx_mtl_node_set_hash_leaf_shake(void *parameters, SERIESID * sid,
					 uint32_t node_id, uint8_t * msg_buffer,
					 uint32_t msg_buffer_len,
					 uint8_t * hash, uint32_t hash_len);

/**
 * Algorithm 2: SHA2 Hashing Child Nodes to Produce an Internal Node.
 * @param params     SPHINCS+ public key seed & key
 * @param sid        Series ID generated for the MTL node set
 * @param node_left   Node Id for the left child node
 * @param node_right  Node Id for the right child node
 * @param hash_left   Pointer to byte array for left child hash
 * @param hash_right  Pointer to byte array for right child hash
 * @param hash       Pointer where the resulting hash is placed
 * @param hash_len   Length of hash byte array
 * @return 0 if successful 
 */
uint8_t spx_mtl_node_set_hash_int_sha2(void *parameters,
				       SERIESID * sid,
				       uint32_t node_left,
				       uint32_t node_right,
				       uint8_t * hash_left,
				       uint8_t * hash_right, uint8_t * hash,
				       uint32_t hash_len);

/**
 * Algorithm 2: SHAKE Hashing Child Nodes to Produce an Internal Node.
 * @param params     SPHINCS+ public key seed & key
 * @param sid        Series ID generated for the MTL node set
 * @param node_left   Node Id for the left child node
 * @param node_right  Node Id for the right child node
 * @param hash_left   Pointer to byte array for left child hash
 * @param hash_right  Pointer to byte array for right child hash
 * @param hash       Pointer where the resulting hash is placed
 * @param hash_len   Length of hash byte array
 * @return 0 if successful 
 */					   
uint8_t spx_mtl_node_set_hash_int_shake(void *parameters, SERIESID * sid,
					uint32_t node_left, uint32_t node_right,
					uint8_t * hash_left,
					uint8_t * hash_right, uint8_t * hash,
					uint32_t hash_len);

/**
 * Perform the SHA2 hashing for tree leaves (internal or leaf)
 * @param seed     SPHINCS+ public key seed 
 * @param seed_len Length of the SPHNICS+ public key
 * @param addrs    Compressed ADRS tree address structure
 * @param adrs_len Lenght of the ADRS tree address structure
 * @param data     Data value to hash 
 * @param data_len Length of the data value
 * @param hash     Pointer to byte array where hash is stored
 * @param hash_len Length of byte array
 * @return 0 if successful
 */
MTLSTATUS spx_sha2(uint8_t * seed, uint32_t seed_len,
		 uint8_t * adrs, uint32_t adrs_len,
		 uint8_t * data, uint32_t data_len,
		 uint8_t * hash, uint32_t hash_len);
/**
* Perform the SHAKE hashing for tree leaves (internal or leaf)
 * @param seed     SPHINCS+ public key seed 
 * @param seed_len Length of the SPHNICS+ public key
 * @param addrs    Compressed ADRS tree address structure
 * @param adrs_len Lenght of the ADRS tree address structure
 * @param data     Data value to hash 
 * @param data_len Length of the data value
 * @param hash     Pointer to byte array where hash is stored
 * @param hash_len Length of byte array
 * @return 0 if successful
 */		 
MTLSTATUS spx_shake(uint8_t * seed, uint32_t seed_len,
		  uint8_t * adrs, uint32_t adrs_len,
		  uint8_t * data, uint32_t data_len,
		  uint8_t * hash, uint32_t hash_len);

#endif				//__MTL_SPX_IMPL_H__
