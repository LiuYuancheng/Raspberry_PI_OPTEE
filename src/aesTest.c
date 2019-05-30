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
 * Compile: 
 * gcc aesTest.c -lmcrypt -lltdl
 */
#include <mcrypt.h>

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

//--------------------------------------------------------------------
int encrypt(
        void* buffer,
        int buffer_len, /* Because the plaintext could include null bytes*/
        char* IV,
        char* key,
        int key_len
){
    MCRYPT td = mcrypt_module_open("rijndael-256", NULL, "cbc", NULL);
    int blocksize = mcrypt_enc_get_block_size(td);
    if( buffer_len % blocksize != 0 ){return 1;}

    mcrypt_generic_init(td, key, key_len, IV);
    mcrypt_generic(td, buffer, buffer_len);
    mcrypt_generic_deinit (td);
    mcrypt_module_close(td);

    return 0;
}

//--------------------------------------------------------------------
int decrypt(
        void* buffer,
        int buffer_len,
        char* IV,
        char* key,
        int key_len
){
    MCRYPT td = mcrypt_module_open("rijndael-256", NULL, "cbc", NULL);
    int blocksize = mcrypt_enc_get_block_size(td);
    if( buffer_len % blocksize != 0 ){return 1;}

    mcrypt_generic_init(td, key, key_len, IV);
    mdecrypt_generic(td, buffer, buffer_len);
    mcrypt_generic_deinit (td);
    mcrypt_module_close(td);

    return 0;
}

//--------------------------------------------------------------------
void display(char* ciphertext, int len){
    int v;
    for (v=0; v<len; v++){
        printf("%d", ciphertext[v]);
    }
    printf("\n");
}

int main()
{
    MCRYPT td, td2;
    char plaintext[32];
    char IV[32];
    char key[32];
    int keysize = 32; /* 256 bits */
    char* buffer;
    int buffer_len = 256;
    
    memset(plaintext, 0xa5, sizeof(plaintext)); 
    memset(IV, 0xa5, sizeof(IV));
    memset(key, 0xa5, sizeof(key)); 

    buffer = calloc(1, buffer_len);
    strncpy(buffer, plaintext, buffer_len);

    printf("==C==\n");
    printf("plain:   %X\n", plaintext);
    encrypt(buffer, buffer_len, IV, key, keysize);
    //printf("%s", buffer);
    printf("cipher:  "); display(buffer , buffer_len);
    //char * msg = "h63TBxj+KTO1hcEdcM0FVbAQxTJPbK+KiotXUFfGXmKLjshjIbNxx0TRvF1Kkm91";
    //FILE *write_ptr;
    //write_ptr = fopen("output","wb");  // w for write, b for binary
    //fwrite(buffer,sizeof(buffer),1,write_ptr);

    //unsigned char fbuffer[32];
    //FILE *ptr;
    //ptr = fopen("output","rb");  // r for read, b for binary
    //fread(fbuffer,sizeof(fbuffer),1,ptr); // read 32 bytes to our buffer
    //decrypt(buffer, buffer_len, IV, key, keysize);
    decrypt(buffer, buffer_len, IV, key, keysize);
    printf("decrypt: %X\n", buffer);


    return 0;
}
