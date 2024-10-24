#include <sodium.h>
#include <string.h>

int main()
{
  char inpkey[32];
  unsigned char inpkey_hash[32];
  unsigned char inpkey_salt[crypto_pwhash_SALTBYTES];

  // strncpy(inpkey, "mypassword", );
  char *test = "mypassword";

  randombytes_buf(inpkey_salt, sizeof(inpkey_salt));

  if (crypto_pwhash(inpkey_hash, 32, test, strlen(test), inpkey_salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_argon2i_ALG_ARGON2I13) != 0)
  {
    perror("error: could not authenticate");
    return EXIT_FAILURE;
  }

  for (int i = 0; i < 32; i++)
    printf("%d\n", inpkey_hash[i]);

  return EXIT_SUCCESS;
}