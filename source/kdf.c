#include <stdio.h> // input/output
#include <unistd.h> // standard symbolic constants and types
#include <sys/socket.h> // socket interface
#include <linux/if_alg.h> // AF_ALG socket family
#include <string.h> // memcpy, strcpy etc

#include "kdf.h"

int sha512(char *password, int password_len, char *derived_key)
{
    if (hash_init(sockfd, op))
    {
        return 1;
    }

    if (hash(password, password_len, derived_key))
    {
        return 1;
    }

    if (hash_destroy())
    {
        return 1;
    }
    return 0;
}

int derive_key(char *password, int password_len, char *derived_key)
{
    if (sha512(password, password_len, derived_key) == 1)
    {
        return 1;
    }
    return 0;
}