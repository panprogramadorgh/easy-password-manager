#include "../../include/main.h"
#include "../../include/input.h"
#include "../../include/crypto.h"

/* Buffer de entrada. */
static char buff[MAX_BUFF];
/* Posicion del buffer de entrada. */;
static char *buffpos = buff;

int getch(void)
{
  if (buffpos - buff > 0)
    return *--buffpos;
  return getchar();
}

void ungetch(int c)
{
  *buffpos++ = c;
}

void clrbuff(void)
{
  buffpos = buff;
}

int getnline(char *line, int n)
{
  size_t i, c;

  clrbuff();
  while (isspace((c = getch())))
    ;
  ungetch(c);
  i = 0;
  while (i < n && (c = getch()) != EOF && c != '\n')
    *(line + i++) = c;
  *(line + i) = '\0';
  return i;
}

/*
  TODO:

  # Comprobacion de clave privada.

  Leer archivo de clave, decodificar base64 en buffer binario, hashear clave introducida por el usuario (la supuesta clave privada), hashear de nuevo el hash obtenido, comparar este ultimo hash generado con el archivo de clave decodificado mediante la funcion sodium_memcpm.

*/
int auth()
{
  char *key = "mypassword";
  char inpkey[32];
  int inpkey_len;
  unsigned char inpkey_hash[ARAGON_HASH_BYTES];
  unsigned char key_hash[ARAGON_HASH_BYTES];
  unsigned char key_salt[crypto_pwhash_SALTBYTES];
  int match;

  inpkey_len = getnline(inpkey, 32);

  randombytes_buf(key_salt, sizeof(key_salt));

  if (crypto_pwhash(inpkey_hash, ARAGON_HASH_BYTES, inpkey, inpkey_len, key_salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_argon2i_ALG_ARGON2I13) != 0)
  {
    perror("error: could not authenticate");
    return -1;
  }

  if (crypto_pwhash(key_hash, ARAGON_HASH_BYTES, key, strlen(key), key_salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_argon2i_ALG_ARGON2I13) != 0)
  {
    perror("error: could not authenticate");
    return -1;
  }

  match = sodium_memcmp(inpkey_hash, key_hash, ARAGON_HASH_BYTES) == 0;
  if (!match)
  {
    errno = EACCES;
    perror("error: password manager key is not correct");
  }
  return match;
}

void prtusage(void)
{
  printf("Usage:\n");
  printf("\t- get-passwd <password name>\n");
  printf("\t- set-passwd <password name> <password>\n");
}