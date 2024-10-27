#include "../../include/main.h"
#include "../../include/input.h"
#include "../../include/file.h"
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

/* TODO: Derivar private_key */
enum auth_signals auth(char *private_key) // Mem blocks size: AES_KEY_LENGTH / 8
{
  char key_path[MAX_PATH_LEN];
  char salt_path[MAX_PATH_LEN];

  char
      *plain_key,
      *key, // Clave hasheada
      *salt_base64,
      *salt;
  size_t
      plain_key_len,
      key_len,
      salt_base64_len,
      salt_len;

  if (get_datadir_file_path(key_path, KEYFILE_NAME) != 0)
  {
    perror("error: could not authenticate");
    return auth_error;
  }
  if (get_datadir_file_path(salt_path, KEYSLTFILE_NAME) != 0)
  {
    perror("error: could not authenticate");
    return auth_error;
  }

  if ((key = read_file(key_path, &key_len)) == NULL)
  {
    perror("error: could not authenticate");
    return auth_error;
  }
  if ((salt_base64 = read_file(salt_path, &salt_base64_len)) == NULL)
  {
    perror("error: could not authenticate");
    return auth_error;
  }

  if (key_len == 0)
    return auth_nokey;
  if (key_len != crypto_pwhash_STRBYTES)
  {
    errno = EILSEQ;
    perror("error: could not read key data file since it is corrupted");
    return auth_corrupted;
  }
  salt = deserialize_base64_to_buffer(salt_base64, &salt_len);
  if (salt_len != crypto_pwhash_SALTBYTES)
  {
    errno = EILSEQ;
    perror("error: could not read key data file since it is corrupted");
    return auth_corrupted;
  }

  /* Obtener contraseña. */
  plain_key = getpass("Enter AES private key: ");
  plain_key_len = strlen(plain_key);

  /* Comparar contra hash de archivo de clave. */
  if (crypto_pwhash_str_verify(key, plain_key, plain_key_len) == -1)
  {
    errno = EACCES;
    perror("error: invalid private key");
    free(salt);
    free(salt_base64);
    free(key);
    return auth_failure;
  }

  /* Generar hash correspondiente a clave AES con salt de archivo. */
  if (crypto_pwhash(private_key, AES_KEY_LENGTH / 8, plain_key, plain_key_len, salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_DEFAULT) != 0)
  {
    perror("error: could not generate AES key from salt");
    free(salt);
    free(salt_base64);
    free(key);
    return auth_error;
  }

  /* Elimina el rastro de memoria de pila. */
  memset(plain_key, 0, plain_key_len);

  free(salt);
  free(salt_base64);
  free(key);

  return auth_success;
}

/* TODO: Terminar */
void prtusage(void)
{
  printf("Usage:\n");
  printf("\t- get-passwd <password name>\n");
  printf("\t- set-passwd <password name> <password>\n");
}