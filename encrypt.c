#include "main.h"

#define AES_KEY_LENGTH 256
#define AES_BLOCK_SIZE 16

int encrypt(const unsigned char *plain, const int plain_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *cipher)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, cipher_len;

  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

  EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len);
  cipher_len = len;

  EVP_EncryptFinal_ex(ctx, cipher + len, &len);
  cipher_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return cipher_len;
}

int decrypt(const unsigned char *cipher, const int cipher_len, const unsigned char *key, const unsigned char *iv, unsigned char *plain)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, plain_len;

  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

  EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len);
  plain_len = len;

  EVP_DecryptFinal_ex(ctx, plain + len, &len);
  plain_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return plain_len;
}