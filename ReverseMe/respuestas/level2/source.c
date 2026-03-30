#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void no(void)
{
    puts("Nope.");
    exit(1);
}

static void ok(void)
{
    puts("Good job.");
}

int main(void)
{
    char input[24];   // scanf("%23s", ...)
    char out[9];      // "delabere" + '\0'
    char chunk[4];    // 3 dígitos + '\0' para atoi
    int scan_result;
    int src_idx;
    int dst_idx;

    printf("Please enter key: ");

    scan_result = scanf("%23s", input);
    if (scan_result != 1)
        no();

    if (input[0] != '0')
        no();
    if (input[1] != '0')
        no();

    //fflush(stdin);

    memset(out, 0, sizeof(out));
    out[0] = 'd';

    chunk[3] = '\0';
    src_idx = 2;
    dst_idx = 1;

    while (strlen(out) < 8 && (size_t)src_idx < strlen(input)) {
        chunk[0] = input[src_idx];
        chunk[1] = input[src_idx + 1];
        chunk[2] = input[src_idx + 2];

        out[dst_idx] = (char)atoi(chunk);

        src_idx += 3;
        dst_idx += 1;
    }

    out[dst_idx] = '\0';

    if (strcmp(out, "delabere") != 0)
        no();

    ok();
    return 0;
}