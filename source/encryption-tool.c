#include "crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <string.h>

#define PASSWORD_SIZE 64

void get_password(char *password)
{
    // disable echo
    struct termios old, new;
    tcgetattr(fileno(stdin), &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), TCSAFLUSH, &new);
    // get password
    printf("Enter password: ");
    fgets(password, PASSWORD_SIZE, stdin);
    // remove newline
    password[strcspn(password, "\n")] = 0;
    // restore echo
    tcsetattr(fileno(stdin), TCSAFLUSH, &old);
    // newline
    printf("\n");
}

// takes two arguments, whether to encrypt or decrypt and the device to encrypt/decrypt
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <-e/-d> <device-path>\n", argv[0]);
        return 1;
    }

    char *password = malloc(PASSWORD_SIZE);
    if (password == NULL)
    {
        printf("Failed to allocate memory\n");
        return 1;
    }
    // initialise password
    memset(password, 0, PASSWORD_SIZE);
    get_password(password);

    if (crypt_init(password, PASSWORD_SIZE) != 0)
    {
        printf("Failed to initialize crypt\n");
        free(password);
        return 1;
    }

    if (strcmp(argv[1], "-e") == 0)
    {
        if (crypt_encrypt(argv[2]) != 0)
        {
            printf("Failed to encrypt %s\n", argv[2]);
            free(password);
            crypt_destroy();
            return 1;
        }
    }
    else if (strcmp(argv[1], "-d") == 0)
    {
        if (crypt_decrypt(argv[2]) != 0)
        {
            printf("Failed to decrypt %s\n", argv[2]);
            free(password);
            crypt_destroy();
            return 1;
        }
    }
    else
    {
        printf("Usage: %s <-e/-d> <device-path>\n", argv[0]);
        free(password);
        crypt_destroy();
        return 1;
    }

    free(password);
    crypt_destroy();
    return 0;
}