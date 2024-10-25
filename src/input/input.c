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

enum auth_signals auth()
{
  char *private_key;

  char keyfile_path[MAX_PATH_LEN];
  char *keyfile;
  size_t keyfile_bytes;

  if (get_datadir_file_path(keyfile_path, KEYFILE_NAME) != 0)
  {
    perror("error: could not authenticate");
    return auth_error;
  }
  if ((keyfile = read_file(keyfile_path, &keyfile_bytes)) == NULL)
  {
    perror("error: could not authenticate");
    return auth_error;
  }

  if (keyfile_bytes == 0)
    return auth_nokey;
  if (keyfile_bytes != crypto_pwhash_STRBYTES)
  {
    errno = EILSEQ;
    perror("error: could not read key data file since it is corrupted");
    return auth_corrupted;
  }

  /* Obtener contraseña. */
  private_key = getpass("Enter AES private key: ");

  if (crypto_pwhash_str_verify(keyfile, private_key, strlen(private_key)) == -1)
  {
    errno = EACCES;
    perror("error: invalid private key");
    return auth_failure;
  }

  /* Elimina el rastro. */
  memset(private_key, 0, strlen(private_key));

  return auth_success;
}

void prtusage(void)
{
  printf("Usage:\n");
  printf("\t- get-passwd <password name>\n");
  printf("\t- set-passwd <password name> <password>\n");
}