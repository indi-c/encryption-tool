#pragma once

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define KEY_LEN 512

#define CHUNK_SIZE 512
// #define BLOCK_SIZE 16
#define TWEAK_SIZE 16

#define SETTER 0
#define GETTER 1

int crypt_init(char *password, int password_len);

int crypt_encrypt(char *diskpath);

int crypt_decrypt(char *diskpath);

int crypt_destroy();