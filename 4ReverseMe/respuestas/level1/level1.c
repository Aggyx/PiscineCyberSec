#include <stdio.h>
#include <string.h>

int main() {
    char flag[111]; // longitud máxima de scanf determinada por overflow
    printf("Enter the flag: ");
    scanf("%s", flag);
    if (strcmp("__stack_check", flag) == 0) {
        printf("Good job.\n");
    } else {
        printf("Nope.\n");
    }
}