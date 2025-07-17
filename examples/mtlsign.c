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

#include "mtllib.h"

#include "mtlsign.h"


/*****************************************************************
 * Load a file into a memory buffer and return the size
 ******************************************************************
 * @return None
 */
static size_t buffer_from_file(char* filename, uint8_t** buffer) {
    FILE* infile = NULL;
    size_t filesize = 0;

    if((filename != NULL) && (buffer != NULL)) {
        infile = fopen(filename, "rb");
        if (infile == NULL) {
            perror("Error opening file");
            return 0; // Exit with an error code
        }

        fseek(infile, 0, SEEK_END);
        filesize = ftell(infile);
        fseek(infile, 0, SEEK_SET);

        *buffer = malloc(filesize);
        if(*buffer == NULL) {
            return 0;
        }
        fread(*buffer, 1, filesize, infile);
        fclose(infile);
    }

    return filesize;
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
    char *keyfilename = NULL;
    bool key_updated = false;
    FILE *output = stdout;  
    size_t keyfile_size = 0;
    uint8_t *keybuffer = NULL;
    MTLLIB_CTX* ctx = NULL;
    MTL_HANDLE* handle = NULL;
    handle_queue* messages = NULL;
    handle_queue* messages_last =NULL;
    uint8_t* sig = NULL;
    size_t sig_len = 0;
    uint8_t* signed_ladder = NULL;
    size_t   signed_ladder_len = 0;
    uint8_t *message = NULL;
    size_t msg_file_len = 0;
    uint8_t* handle_zero = calloc(1, 64);
    MTLLIB_STATUS mtllib_errno;

	// Setup default file permissions (key and signatures)
    // to be read and write only for owner of application
	umask(0177);

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
        case 'i':
            // Add the leaf index to the queue to later print
            if (messages == NULL)
            {
                messages = calloc(1, sizeof(handle_queue));
                messages_last = messages;
            }
            else
            {
                messages_last->next = calloc(1, sizeof(handle_queue));
                messages_last = messages_last->next;
            }
            MTL_HANDLE* tmp_handle = calloc(1, sizeof(MTL_HANDLE));
            tmp_handle->leaf_index = atol(optarg);
            messages_last->handle = tmp_handle;
            strcpy(messages_last->filename,"");
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
        LOG_ERROR("ERROR - Unable to load key file\n");
        free(handle_zero);
        return (2);        
    }
    argc--;
    argv++;    
    // Do any filtering on the message_file here to restrict access if desired

    // Load the key
    keyfile_size = buffer_from_file(keyfilename, &keybuffer);


    if(mtllib_key_from_buffer(keybuffer, keyfile_size, &ctx) != MTLLIB_OK) {     
        LOG_ERROR("Unable to load key\n");
        free(handle_zero);
        return (2);    
    }
    free(keybuffer);
    keybuffer = NULL;

    while (argc > 0)
    {
        char *message_file = realpath(argv[0], NULL);
        if(message_file == NULL) {
            LOG_ERROR("Message file does not exist!");
            mtllib_key_free(ctx);
            free(handle_zero);
            return (2);     
        }        
        // Do any filtering on the message_file here to restrict access if desired

        // Read message from file
        msg_file_len = buffer_from_file(message_file, &message);        

        // Convert it to bin if necessary
        if (format == BASE64_STRING)
        {
            msgparam_len = mtl_buffer2bin(message, msg_file_len, &msgparam, format);
            mtllib_errno = mtllib_sign_append(ctx, msgparam, msgparam_len, &handle);
        } else 
        {
            mtllib_sign_append(ctx, message, msg_file_len, &handle) ;
        }
        free(msgparam);
        if (mtllib_errno != MTLLIB_OK) {
                LOG_ERROR("Unable to add message to node set");
                free(handle);
                free(message_file);
                mtllib_key_free(ctx);                
                free(handle_zero);
                return (1);                 
        }

        key_updated = true;
        free(message);

        // Add the leaf index to the queue to later print
        if (messages == NULL)
        {
            messages = calloc(1, sizeof(handle_queue));
            if(messages == NULL) {
                LOG_ERROR("Unable to add message to proof set");
                free(handle);
                free(message_file);
                mtllib_key_free(ctx);                
                free(handle_zero);
                free(message);                
                return (1);               
            }
            messages_last = messages;
        }
        else
        {
            messages_last->next = calloc(1, sizeof(handle_queue));
            if(messages == NULL) {
                LOG_ERROR("Unable to add message to proof set");
                free(handle);
                free(message_file);
                mtllib_key_free(ctx);                
                free(handle_zero);
                free(message);                
                return (1);               
            }
            messages_last = messages_last->next;
        }
        strncpy(messages_last->filename, message_file, 1024);
        messages_last->handle = handle;
        free(message_file);

        argc--;
        argv++;
    }

    // For leaf index in queue generate the auth path
    handle_queue *tmp_handle = messages;
    while (messages != NULL)
    {
        if(memcmp(messages->handle->sid,handle_zero, messages->handle->sid_len) == 0) {
            // If this is an extend path only then SID will be null
            memcpy(messages->handle->sid, ctx->mtl->sid.id, messages->handle->sid_len);
        }

        if((messages->handle->leaf_index < ctx->mtl->nodes.leaf_count) && 
           (memcmp(messages->handle->sid, ctx->mtl->sid.id, messages->handle->sid_len) == 0) &&
           (messages->handle->sid_len == ctx->mtl->sid.length)) {
                // Get the message buffer and write it to output
                if(mtllib_sign_get_condensed_sig(ctx, messages->handle, &sig, &sig_len) != MTLLIB_OK) {
                    LOG_ERROR("Unable to get condensed signature");
                }

                if (strlen(messages->filename) > 0)
                {
                    fprintf(output, "%s,%u,", messages->filename, messages->handle->leaf_index);
                }
                else
                {
                    fprintf(output, ",%u,", messages->handle->leaf_index);
                }

                mtl_write_buffer(sig, sig_len, output, format, true);
                free(sig);
           }
        tmp_handle = messages;
        messages = messages->next;
        mtllib_sign_free_handle(&tmp_handle->handle);
        free(tmp_handle);
    }
    free(handle_zero);

    // Generate the signed ladder
    if (provide_signed_ladder == true)
    {
        if(mtllib_sign_get_signed_ladder(ctx, &signed_ladder, &signed_ladder_len) != MTLLIB_OK) {
            LOG_ERROR("Unable to get signed ladder");
        }

        // Write the data
        fprintf(output, "Ladder,,");
        mtl_write_buffer(signed_ladder, signed_ladder_len, output, format, true);

        free(signed_ladder);
    }

    // Output updated private key
    if ((keyfilename != NULL) && (key_updated == true))
    {
        keyfile_size = mtllib_key_to_buffer(ctx, &keybuffer);
        if(keyfile_size > 0) {
            FILE* outfile = fopen(keyfilename, "wb");
            if (outfile == NULL) {
                return 1; // Exit with an error code
            }            
            if(fwrite(keybuffer, keyfile_size, 1, outfile) == 0) {
                LOG_ERROR("Unable to write the private key to a file");
            }
            fclose(outfile);
        }
        free(keybuffer);
    }

    mtllib_key_free(ctx);
    free(keyfilename);
    return (0);
}
