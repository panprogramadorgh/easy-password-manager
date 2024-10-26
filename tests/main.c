#include "../src/crypto/crypto.c"

int main()
{
  unsigned char *plain = "hello world";
  size_t plain_len = strlen(plain);
  unsigned char *cipher;
  size_t cipher_len;

  unsigned char *plain_key = "password";
  unsigned char key[AES_KEY_LENGTH / 8];

  unsigned char key_salt[crypto_pwhash_SALTBYTES];
  char iv[AES_BLOCK_SIZE];

  randombytes_buf(key_salt, sizeof(key_salt));
  if (crypto_pwhash(key, sizeof(key), plain_key, strlen(plain_key), key_salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
  {
    fprintf(stderr, "error: hashing error");
    return EXIT_FAILURE;
  }
  randombytes_buf(iv, sizeof(iv));
  cipher = (unsigned char *)malloc(plain_len + AES_BLOCK_SIZE);
  cipher_len = encrypt(plain, plain_len, key, iv, cipher);

  for (int i = 0; i < cipher_len; i++)
    printf("%02x\n", *(cipher + i));

  return EXIT_SUCCESS;
}