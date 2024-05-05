// basic key derivation from SHA512 hash
// this is insecure but this avoids the need for salting and thus storing the salt

int derive_key(char *password, int password_len, char *derived_key);