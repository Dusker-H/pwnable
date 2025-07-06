//gcc -fno-pie -fno-stack-protector -no-pie -Wl,-z,norelro example.c -o example
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int main() {
    char flag[50];
    FILE* file = fopen("flag", "r");
    fgets(flag, sizeof(flag), file);

    char arr1[5] = "asdf";
    char arr2[100];
    char arr3[5] = "asdf";

    initialize();

    fgets(arr2, 0x100, stdin);

    printf("%s", arr2);

    if (strcmp(arr1, arr3) != 0) {
        printf("%s", flag);
    }

    return 0;
}