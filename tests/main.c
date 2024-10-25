#include <sodium.h>
#include <string.h>

#define ARAGON_HASH_BYTES 32

int main()
{
  char *password = "password";
  unsigned char first_hash[ARAGON_HASH_BYTES];
  unsigned char seccond_hash[ARAGON_HASH_BYTES];
  unsigned char first_salt[crypto_pwhash_SALTBYTES];
  unsigned char seccond_salt[crypto_pwhash_SALTBYTES];

  randombytes_buf(first_salt, sizeof(first_salt));
  if (crypto_pwhash(first_hash, sizeof(first_hash), password, strlen(password), first_salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0)
  {
    perror("error: hashing error");
    return EXIT_FAILURE;
  }

  randombytes_buf(seccond_salt, sizeof(seccond_salt));
  if (crypto_pwhash(seccond_hash, sizeof(seccond_hash), password, strlen(password), seccond_salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0)
  {
    perror("error: hashing error");
    return EXIT_FAILURE;
  }

  printf("%d\n", sodium_memcmp(first_hash, seccond_hash, ARAGON_HASH_BYTES));

  return EXIT_SUCCESS;
}