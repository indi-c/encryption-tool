#include "crypt.h"
#include <stdio.h>

int main(void) {
    char password[16] = "0123456789abcdef";

    if (crypt_init(password, 16))
    {
        perror("crypt_init");
        return 1;
    }

    // if (crypt_encrypt("/dev/loop6"))
    // {
    //     perror("crypt_encrypt");
    //     crypt_destroy();
    //     return 1;
    // }

    if (crypt_decrypt("/dev/loop6"))
    {
        perror("crypt_decrypt");
        crypt_destroy();
        return 1;
    }

    if (crypt_destroy())
    {
        perror("crypt_destroy");
        return 1;
    }

    return 0;
}