#include <stdio.h> // input/output
#include <unistd.h> // standard symbolic constants and types
#include <sys/socket.h> // socket interface
#include <linux/if_alg.h> // AF_ALG socket family
#include <string.h> // memcpy, strcpy etc

#include "kdf.h"

int hash_init(int *sockfd, int *op)
{
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "shash",
        .salg_name = "sha512"
    };

    *sockfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

    if (*sockfd == -1)
    {
        return 1;
    }

    if (bind(*sockfd, (struct sockaddr *)&sa, sizeof(sa)))
    {
        return 1;
    }

    *op = accept(*sockfd, NULL, 0);

    if (*op == -1)
    {
        return 1;
    }

    return 0;
}

int hash(char *password, int password_len, char *derived_key, int *op)
{
    if (send(*op, password, password_len, 0) != password_len)
    {
        return 1;
    }

    if (recv(*op, derived_key, 64, 0) != 64)
    {
        return 1;
    }

    return 0;
}

int hash_destroy(int *sockfd, int *op)
{
    close(*op);
    close(*sockfd);
    return 0;
}

int sha512(char *password, int password_len, char *derived_key)
{
    int sockfd;
    int op;

    if (hash_init(&sockfd, &op))
    {
        perror("hash_init");
        return 1;
    }

    if (hash(password, password_len, derived_key, &op))
    {
        perror("hash");
        return 1;
    }

    if (hash_destroy(&sockfd, &op))
    {
        perror("hash_destroy");
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