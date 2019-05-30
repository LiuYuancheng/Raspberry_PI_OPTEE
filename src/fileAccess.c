#include <stdio.h>

#define MAXCHAR 1000
int main() {

    char iv[32];
    memset(iv, 0x5a, sizeof(iv));
    printf("This is vi <%s> \n", iv);

    FILE *fp;
    char str[MAXCHAR];
    char* filename = "input.txt";
    fp = fopen(filename, "r");
    if (fp == NULL){
        printf("Could not open file %s",filename);
        return 1;
    }
    while (fgets(str, MAXCHAR, fp) != NULL)
        printf("%s \n", str);
    int num = atoi(str);
    fclose(fp);
    printf("K %d", num);
    return 0;
}

