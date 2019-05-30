#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * MCrypt API available online:
 * http://linux.die.net/man/3/mcrypt
 * Cmd to install mcrypt under ubuntu:
 * sudo apt-get install libmcrypt-dev
 * sudo apt-get install ruby-dev
 * gem install ruby-mcrypt -v '0.2.0'
 */
#include <mcrypt.h>

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

int encrypt(
        void* buffer,
        int buffer_len, /* Because the plaintext could include null bytes*/
        char* IV,
        char* key,
        int key_len
){
    MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
    int blocksize = mcrypt_enc_get_block_size(td);
    if( buffer_len % blocksize != 0 ){return 1;}

    mcrypt_generic_init(td, key, key_len, IV);
    mcrypt_generic(td, buffer, buffer_len);
    mcrypt_generic_deinit (td);
    mcrypt_module_close(td);

    return 0;
}

int decrypt(
        void* buffer,
        int buffer_len,
        char* IV,
        char* key,
        int key_len
){
    MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
    int blocksize = mcrypt_enc_get_block_size(td);
    if( buffer_len % blocksize != 0 ){return 1;}

    mcrypt_generic_init(td, key, key_len, IV);
    mdecrypt_generic(td, buffer, buffer_len);
    mcrypt_generic_deinit (td);
    mcrypt_module_close(td);

    return 0;
}

void display(char* ciphertext, int len){
    int v;
    for (v=0; v<len; v++){
        printf("%d ", ciphertext[v]);
    }
    printf("\n");
}

int main()
{
    MCRYPT td, td2;
    char * plaintext = "test text 123";
    char* IV = "AAAAAAAAAAAAAAAA";
    char *key = "0123456789abcdef";
    int keysize = 16; /* 128 bits */
    char* buffer;
    int buffer_len = 16;

    buffer = calloc(1, buffer_len);
    strncpy(buffer, plaintext, buffer_len);

    printf("==C==\n");
    printf("plain:   %s\n", plaintext);
    encrypt(buffer, buffer_len, IV, key, keysize);
    printf("cipher:  "); display(buffer , buffer_len);
    decrypt(buffer, buffer_len, IV, key, keysize);
    printf("decrypt: %s\n", buffer);

    return 0;
}