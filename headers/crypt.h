#pragma once

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define KEY_LEN 512

#define CHUNK_SIZE 512
#define BLOCK_SIZE 16
#define TWEAK_SIZE 16

int crypt_init(char *key, int key_len);

int crypt_encrypt(char *plaintext, int plaintext_len, char *ciphertext, int ciphertext_len);

int crypt_decrypt(char *ciphertext, int ciphertext_len, char *plaintext, int plaintext_len);

int crypt_destroy();

int i = 1;