// basic key derivation from SHA512 hash
// this is insecure but this avoids the need for salting and thus storing the salt

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int derive_key(char *password, int password_len, char *derived_key);