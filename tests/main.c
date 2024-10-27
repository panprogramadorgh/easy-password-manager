#include "../src/crypto/crypto.c"

int main()
{
  unsigned char *plain = "";
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

  unsigned char *foo = (unsigned char *)malloc(cipher_len);
  int foo_len = decrypt(cipher, cipher_len, key, iv, foo);

  printf("%s\n", foo);
  for (int i = 0; i < foo_len; i++)
    printf("%d\t%c\n", foo[i], foo[i]);

  return EXIT_SUCCESS;
}