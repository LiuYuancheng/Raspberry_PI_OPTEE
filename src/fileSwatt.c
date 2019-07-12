#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*	Name:       fileSwatt.c
	Purpose:    This module is used to provide a SWATT calculator to get the 
                input file's swatt value.
	Author:     Yuancheng Liu
	Created:    2019/05/28
	Copyright:  NUS – Singtel Cyber Security Research & Development Laboratory
    License:    YC @ NUS
*/


int bsd_rand();     
int rseed = 0;      
char gv_flph[80];   // file we are going to check.
int debug = 0;      // debug level. 

//-------------------------------------------------------------------------------
/* Use Linear congruential generator(BSD) as the random number calculation result 
  is different on different plantform or use differnt compiler.   
*/
void bsd_srand(int x)
{
	rseed = x;
}

#define BSD_RAND_MAX ((1U << 31) - 1)
 
int bsd_rand()
{
	return rseed = (rseed * 1103515245 + 12345) & BSD_RAND_MAX;
}

//-------------------------------------------------------------------------------

/*read file block*/
char *readFileBytes(const char *name)
{
    FILE *fl = fopen(name, "r");
    fseek(fl, 0, SEEK_END);
    long len = ftell(fl);
    len = 128000; // Haroon use the fixed block size in his program
    char *ret = malloc(len);
    fseek(fl, 0, SEEK_SET);
    fread(ret, 1, len, fl);
    fclose(fl);
    return ret;
}

//-------------------------------------------------------------------------------
int getSWATT(char challengeB[], int cSize, int m, int n, int puff)
{   
// challengeB[] : a random challenge string
//  cSize       : challenge string size
//  (m, n)      : m-swap list size(must >=260), n-sample times in one block.

    strncpy(gv_flph, "firmwareSample", 16);
    char *ret = readFileBytes(gv_flph);
    char *challenge = challengeB;
    int keylen = cSize;
    // reference func: string_to_list <IOT_ATT.py>
    int challengeInt[keylen];
    for (int t = 0; t < keylen; t++)
    {
        challengeInt[t] = (int)challenge[t];
        if (debug == 1)
            printf(":<%d>\n", challengeInt[t]);
    }
    // reference func: setKey <IOT_ATT.py>
    int state[m];
    for (int i = 0; i < m; i++)
    {
        state[i] = i;
    }
    int j = 0;
    for (int i = 0; i < m; i++)
    {
        j = (j + state[i] + challengeInt[i % keylen]) % m;
        int tmp = state[i];
        state[i] = state[j];
        state[j] = tmp;
    }
    // reference func: extract_CRpair <IOT_ATT.py>
    int s = 1;  
    int k = 16;
    int final = ((1 << k) - 1) & (puff >> (s - 1));
    if (debug == 1)
        printf("Extract bytes final:<%d>\n", final);
    int test[keylen];
    for (int t = 0; t < keylen; t++)
        test[t] = challengeInt[t] ^ final;
    for (int t = 0; t < keylen-1; t++)
        final += test[t] << 2;
    // main loop of the SWATT
    int cr_response = final;
    int pprev_cs = state[256];
    int prev_cs = state[257];
    int current_cs = state[258];
    int init_seed = m;
    int swatt_seed = 0; 
    for (int i = 0; i < 100; i++)
    {
        swatt_seed = cr_response ^ init_seed;
        int Address = (state[i] << 8) + prev_cs;
        bsd_srand(Address);
        Address = bsd_rand() % 128000 + 1;
        char strTemp = ret[Address];
        if (debug == 1)
        {
            printf("R2:<%c>\n", strTemp);
            printf("R3:<%d>\n", current_cs);
            printf("R4:<%d>\n", pprev_cs);
        }
        int num = i - 1;
        if (num < 0)
            num = m - 1;
        current_cs = current_cs +((int)strTemp ^ pprev_cs + state[num]);
        init_seed = current_cs+swatt_seed;
        current_cs = current_cs >> 1; 
        pprev_cs = prev_cs;
        prev_cs = current_cs;
    }
    return current_cs;
}

//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
int main(void)
{   
    int m = 300; 
    int n = 100;
    int puff = 1549465112; // program unique id/computer MAC addr. 
    char challenge[] = "Testing";
    int number = getSWATT(challenge, 7, m, n, puff);
    printf("File swatt value :<%d>\n", number);
    if(number ==  4519){
        printf("Test case passed!\n");
    }
    else{
        printf("Test case Fail, please check the <firmwareSample> or the program!\n");
    }
}
