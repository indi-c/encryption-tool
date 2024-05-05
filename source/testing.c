#include "crypt.h"

int main(void) {
    char password[16] = "0123456789abcdef";

    const char *plaintext = "Single block msg";

    char ciphertext[16];

    int sockfd;
    int op;

    if (crypt_init(&password, 16))
    {
        perror("crypt_init");
        return 1;
    }

    if (crypt_encrypt(&plaintext, 16, &ciphertext, 16))
    {
        perror("crypt_encrypt");
        return 1;
    }

    if (crypt_decrypt(&ciphertext, 16, &plaintext, 16))
    {
        perror("crypt_decrypt");
        return 1;
    }

    if (crypt_destroy())
    {
        perror("crypt_destroy");
        return 1;
    }

    return 0;
}