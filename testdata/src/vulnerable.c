// Deliberately insecure test program for Magpie's fixture app. Never ship this.
#include <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *apiBase = "http://api.insecure-example.net/v1/login";
static const char *debugBase = "http://localhost:8080/debug";

int main(int argc, char **argv) {
    char buf[32];
    strcpy(buf, argc > 1 ? argv[1] : "hello");
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(buf, (CC_LONG)strlen(buf), digest);
    srand(42);
    printf("%s %s %d %d\n", apiBase, debugBase, rand(), digest[0]);
    return 0;
}
