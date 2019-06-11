#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

char *readFileBytes(const char *name)
{
    FILE *fl = fopen(name, "r");
    fseek(fl, 0, SEEK_END);
    long len = ftell(fl);
    char *ret = malloc(len);
    fseek(fl, 0, SEEK_SET);
    fread(ret, 1, len, fl);
    fclose(fl);
    return ret;
}

int getSWATT(void)
{
    char *ret = readFileBytes("firmwareSample");
    int m = 300;
    int puff = 1549;
    char challenge[] = "Testing";
    int keylen = sizeof(challenge) - 1;
    int challengeInt[keylen];
    for (int t = 0; t < keylen; t++)
    {
        challengeInt[t] = (int)challenge[t];
        printf(":<%d>\n", challengeInt[t]);
    }
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

    int s = 1;
    int k = 16;
    int final = ((1 << k) - 1) & (puff >> (s - 1));
    printf("IP:<%d>\n", final);
    int test[keylen];
    for (int t = 0; t < keylen; t++)
    {
        test[t] = challengeInt[t] ^ final;

        printf(":<%d>\n", test[t]);
    }

    for (int t = 0; t < keylen; t++)
    {
        if (t != keylen - 1)
        {
            test[t] ^= test[t + 1];
        }
        final += test[t] << 2;
    }
    // main loop of the SWATT
    int cr_response = final;
    int pprev_cs = state[256];
    int prev_cs = state[257];
    int current_cs = state[258];
    int init_seed = m;
    int swatt_seed = 0; 
    for (int i = 0; i < m; i++)
    {
        swatt_seed = cr_response ^ init_seed;
        int Address = (state[i] << 8)+prev_cs;
        //printf("AD:<%d>\n", Address);
        srand(Address);
        int M = 1;
        int N = 128000;
        int num = M + rand() / (RAND_MAX / (N - M + 1) + 1);
        //printf("RA:<%d>\n", num);
        char strTemp = ret[num];
        current_cs = current_cs +((int)strTemp ^ pprev_cs+state[i-1]);
        init_seed = current_cs+swatt_seed;
        current_cs = current_cs >> 1; 
        pprev_cs = prev_cs;
        prev_cs = current_cs;
    }
    
    return current_cs;
}

int main(void)
{
    int number = getSWATT();
    printf("IP:<%d>\n", number);
}