/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*	Name: trustClient
	Purpose: This module used optee to create a truct TCP client application
			to connection to the server to down load the AES256 encrypted challeage 
			value to calculate the gate way program. This file is edited based on 
			the optee aes example

	Author:      Yuancheng Liu
	Created:     2019/05/28
	Copyright: (c) 2017, Linaro Limited, 2019,  YC
*/
#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netdb.h> 
#include <sys/socket.h> 

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <aes_ta.h>

#define AES_TEST_BUFFER_SIZE	32
#define AES_TEST_KEY_SIZE	32
#define AES_TEST_IV_SIZE	16

#define DECODE			0
#define ENCODE			1
#define SA struct sockaddr 
#define SWATT_PUFF		1549465112

/*progress bar to show the swatt steps.*/
#define PBSTR "============================================================"
#define PBWIDTH 60

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

struct IPtuple{
    char ipAddr[20];
    int port;
};
//-------------------------------------------------------------------------------

/*TEE session setup.*/
void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
						   TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			 res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}
//-------------------------------------------------------------------------------

/*AES encryptiong and decription*/
// Set AES encode/decode, algo mode, key size(AES128/256).
void prepare_aes(struct test_ctx *ctx, int encode)
{	
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
									 TEEC_VALUE_INPUT,
									 TEEC_VALUE_INPUT,
									 TEEC_NONE);

	op.params[0].value.a = TA_AES_ALGO_CBC;	// algo mode.
	op.params[1].value.a = TA_AES_SIZE_256BIT; // Keysize
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE : TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			 res, origin);
}

// Set AES encryption/decryption key.
void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			 res, origin);
}

// Set AES initialization vector.
void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			 res, origin);
}

// Data encryption/decryption.
void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_MEMREF_TEMP_OUTPUT,
									 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			 res, origin);
}
//-------------------------------------------------------------------------------

/* File SWATT data calculation. */

// Read firmware file as bytes array.
char *readFileBytes(const char *name)
{
	FILE *fl = fopen(name, "r");
	fseek(fl, 0, SEEK_END);
	long len = ftell(fl);
	//len = 128000; // Haroon's orignal python code use this value, why? 
	char *ret = malloc(len);
	fseek(fl, 0, SEEK_SET);
	fread(ret, 1, len, fl);
	fclose(fl);
	return ret;
}

// Show a progress bar. 
void printProgress (double percentage)
{
    int val = (int) (percentage * 100);
    int lpad = (int) (percentage * PBWIDTH);
    int rpad = PBWIDTH - lpad;
    printf ("\r%3d%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
    fflush (stdout);
}

// Calculate the firmware file SWATT int value.
int get_swatt(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	
	// Set the parameters
	int m = 300;
	int addrNum = 100; // how many addresses swatt are going to check.
	int state[m];
	int puff = SWATT_PUFF;
	char challenge[key_sz];
	strncpy(challenge, key, key_sz);
	int challengeInt[key_sz];
	printf("SWATT: Challenge string is <%s>\n", challenge);
	
	// Read the firmware file. 
	char *ret = readFileBytes("firmwareSample");
	
	// reference func: string_to_list <IOT_ATT.py>
    for (int t = 0; t < key_sz; t++)
		challengeInt[t] = (int)challenge[t];

	// reference func: setKey <IOT_ATT.py>
	for (int i = 0; i < m; i++)
		state[i] = i;
	int j = 0;
	for (int i = 0; i < m; i++)
	{
		j = (j + state[i] + challengeInt[i % key_sz]) % m;
		int tmp = state[i];
		state[i] = state[j];
		state[j] = tmp;
	}

	// reference func: extract_CRpair <IOT_ATT.py>
	int s = 1;
    int k = 16;
    int final = ((1 << k) - 1) & (puff >> (s - 1));
    printf("SWATT: final :<%d>\n", final);
    int test[key_sz];
    for (int t = 0; t < key_sz; t++)
        test[t] = challengeInt[t] ^ final;

    for (int t = 0; t < key_sz; t++)
    {
        if (t != key_sz - 1)
            test[t] ^= test[t + 1];
        final += test[t] << 2;
    }

	// Calculate file's address need to access in the trustApp.
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT,
									 TEEC_VALUE_INOUT, TEEC_NONE);
	// reference func: getSWATT <IOT_ATT.py>
	int pprev_cs = state[256];
	int prev_cs = state[257];

	op.params[0].value.a = 0;		   //swatt_seed -> op.params[0].value.a
	op.params[0].value.b = m;		   //init_seed	-> op.params[0].value.b
	op.params[1].value.a = 0;		   // Address -> op.params[1].value.a
	op.params[1].value.b = state[258]; // current_cs -> op.params[1].value.b
	op.params[2].value.a = state[257]; // prev_cs -> op.params[2].value.a
	op.params[2].value.b = state[256]; // pprev_cs -> op.params[3].value.b

	for (int i = 0; i < addrNum; i++)
	{
		op.params[0].value.a = final ^ op.params[0].value.b;
		op.params[1].value.a = (state[i] << 8) + op.params[2].value.a;
		res = TEEC_InvokeCommand(&ctx->sess, TA_SWATT_CMD_RAND, &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				 res, origin);
		int Address = op.params[1].value.a;
		char strTemp = ret[Address];
		int num = i - 1;
		if (num < 0)
			num = m - 1;
		usleep(20000); // sleep a short while to avoid PI hang.
		op.params[1].value.b = op.params[1].value.b + ((int)strTemp ^ op.params[2].value.b + state[num]);
		//printf("R5:<%d>\n", current_cs);
		res = TEEC_InvokeCommand(&ctx->sess, TA_SWATT_CMD_CAL, &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				 res, origin);
		// Show the file checking progress bar.
		printProgress((double)i / addrNum);
	}
	printf("Finished\n");
	printf("SWATT: TA incremented value to %d\n", op.params[1].value.b);
	return op.params[1].value.b;
}

//-------------------------------------------------------------------------------

/* Load the IP and port data from the local config file. */
struct IPtuple getAddr()
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char *pch;
	fp = fopen("configLocal.txt", "r");
	if (fp == NULL)
	{
		printf("Local config file open error!");
		exit(EXIT_FAILURE);
	}
	while ((read = getline(&line, &len, fp)) != -1)
	{
		//printf("%s", line);
		if (line[0] == '#' || line[0] == '\n' || line == NULL)
			continue; // jump the comment and empty line.
		struct IPtuple r = {};
		//data format example: 127.0.0.1:8080
		strcpy(r.ipAddr, strtok(line, ":"));
		//printf("-IP:%s\n", r.ipAddr);
		r.port = atoi(strtok(NULL, ":"));
		//printf("-Port:%d\n", r.port);
		fclose(fp);
		if (line)
			free(line);
		return r;
	}
}
//-------------------------------------------------------------------------------

/* Display the hex number of the message/ciphText */
void display(char *ciphertext, int len, int debugLvl)
{	
	if(debugLvl == 0)
		return; // don't display anything if debug level == 0 
	printf("len: %d \n", len);
	if(debugLvl == 1)
		return; // only display data len if debug level == 1
	for (int v = 0; v < len; v++)
	{
		printf("%d ", ciphertext[v]);
	}
	printf("\n");
}
//-------------------------------------------------------------------------------

int main(void)
{
	struct test_ctx ctx;
	char key[AES_TEST_KEY_SIZE];
	char iv[AES_TEST_IV_SIZE];
	char clear[AES_TEST_BUFFER_SIZE];
	char ciph[AES_TEST_BUFFER_SIZE];
	char temp[AES_TEST_BUFFER_SIZE];
	 
	printf("TEE: Prepare TrustZone session with the TA.\n");
	prepare_tee_session(&ctx);
	int debugLvl = 0; // debug message display deepth.

	// Step 1: fetch the challenge from the server.
	printf("--------------------------------------\n");
	printf("TCP: Init the TCP client.\n");
	// Init the TCP client
	int sockfd, connfd;
	struct sockaddr_in servaddr, cli;
	// Socket create and varification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		printf("TCP: socket creation failed...\n");
		exit(0);
	}
	else
		printf("TCP: Socket successfully created..\n");
	bzero(&servaddr, sizeof(servaddr));
	// Assign TCP IPaddr, PORT(load the setting from the config file.)
	struct IPtuple r = getAddr();
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(r.ipAddr);
	servaddr.sin_port = htons(r.port);
	// Connect the client socket to server socket
	if (connect(sockfd, (SA *)&servaddr, sizeof(servaddr)) != 0)
	{
		printf("TCP: connection with the server failed...\n Client terminate.\n");
		exit(0);
	}
	else
		printf("TCP: connected to the server..\n"); 
	// Send challenge fetch request.
	printf("TCP: send the fetch request \n");
	char rbuff[AES_TEST_BUFFER_SIZE]; 
	bzero(rbuff, sizeof(rbuff)); 
	rbuff[0] = 'F';
	write(sockfd, rbuff, sizeof(rbuff));
	// get the cyphtext from the server.
	bzero(ciph, sizeof(ciph)); 
	read(sockfd, ciph, sizeof(ciph));
	printf("TCP: get <%d>Bytes ciphtext from server: \n", sizeof(ciph));
	display(ciph, sizeof(ciph), debugLvl);
	printf("--------------------------------------\n");

	// Step 2: Decode the message by AES256 and get challenge data.
	printf("Prepare AES decode operation(AES_D)\n");
	prepare_aes(&ctx, DECODE);

	printf("AES_D:Load key inside TA\n");
	memset(key, 0xa5, sizeof(key)); // load some value as key(hard code)
	set_key(&ctx, key, AES_TEST_KEY_SIZE);
	display(key, sizeof(key), debugLvl);

	printf("AES_D: Reset ciphering operation IV in TA \n");
	memset(iv, 0xa5, sizeof(iv)); /* Load some dummy value */
	set_iv(&ctx, iv, AES_TEST_IV_SIZE);
	display(iv, sizeof(iv), debugLvl);

	printf("AES_D: Decrypte ciphtext buffer from TA\n");
	cipher_buffer(&ctx, ciph, temp, AES_TEST_BUFFER_SIZE); // challenge-> temp
	//printf("DC: This is the challenge: %X\n",temp );
	display(temp, sizeof(temp), debugLvl);

	/* Check decoded is the clear content(only used for) */
	//memset(clear, 0x5a, sizeof(clear)); /* Load some dummy value */
	//printf("DC: This is the clear X: %X\n",clear );
	//display(clear, sizeof(clear), debugLvl));
	//if (memcmp(clear, temp, AES_TEST_BUFFER_SIZE))
	//	printf("Clear text and decoded text differ => ERROR\n");
	//else
	//	printf("Clear text and decoded text match\n");
	printf("--------------------------------------\n");

	// Step 3: Calcualte the SWATT data from the trust application.
	printf("SWATT: Pass in challenge data and calcualte: \n");
	int tempLen = 7; // The challenge data len we are going to use.
	int swattVal = get_swatt(&ctx, temp, tempLen);
	printf("--------------------------------------\n");

	// Step 4: Encode the SWATT message by AES256 and send to server.
	printf("Prepare AES encode operation(AES_E) \n");
	prepare_aes(&ctx, ENCODE);

	printf("AES_E: Load key in TA\n");
	memset(key, 0xa5, sizeof(key)); // load some value as key(hard code)
	set_key(&ctx, key, AES_TEST_KEY_SIZE);
	display(key, sizeof(key), debugLvl);

	printf("AES_E: Reset ciphering operation IV in TA \n");
	memset(iv, 0xa5, sizeof(iv)); /* Load some dummy value */
	set_iv(&ctx, iv, AES_TEST_IV_SIZE);
	display(iv, sizeof(iv), debugLvl);

	printf("AES_E: Encore chanllenge data buffer from TA\n");
	memset(clear, 0x5a, sizeof(clear)); /* Load some dummy value */
	snprintf(clear, 10, "%d", swattVal);
	printf("SWATT int val:<%s> \n", clear);
	cipher_buffer(&ctx, clear, ciph, AES_TEST_BUFFER_SIZE);
	//printf("AES_E: This is the ciphtext %X\n",ciph );
	display(ciph, sizeof(ciph), debugLvl);
	printf("--------------------------------------\n");

	// Step 5: Send to server and close the socket
	printf("TCP: send the encrypted swatt data\n");
	write(sockfd, ciph, sizeof(ciph));
	close(sockfd);
	printf("--------------------------------------\n");

	// Step 6: terminate the TA session.
	terminate_tee_session(&ctx);
	return 0;
}
