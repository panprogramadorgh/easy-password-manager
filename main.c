#include "main.h"
#include "include/main.h"
#include "include/crypto.h"
#include "include/file.h"
#include "include/input.h"

// TODO: Reemplazar fprintf(stderr ... con perror

int main(int argc, char *argv[])
{
  if (sodium_init() < 0)
  {
    perror("error: could not init sodium library");
    return EXIT_FAILURE;
  }

  enum auth_signals auth_state = auth();
  if (auth_state == auth_failure ||
      auth_state == auth_error)
    return EXIT_FAILURE;
  if (auth_state == auth_nokey ||
      auth_state == auth_corrupted)
  {
    unsigned char aes_key_hash[crypto_pwhash_STRBYTES];
    unsigned char aes_key_iv[AES_BLOCK_SIZE];
    char *aes_iv_base64; // Serializacion de aes_key_iv

    char line[MAXLN];

    if (auth_state == auth_nokey)
    {
      printf("To start storing passwords, you need to set up a master\n");
      printf("private key to keep them all safe.\n");
      printf("Create AES private key: ");
    }
    else
    {
      printf("To solve the corruption problem, you can delete all passwords\n");
      printf("and set a new private. Do you want to proceed ? [Y/N]: ");
      clrbuff();
      if (tolower(getch()) != 'y')
        return EXIT_FAILURE;
    }
    getnline(line, MAXLN);

    if (reset_private_key(line) != 0)
      return EXIT_FAILURE;
  }

  /* Inicializacion de archivos de datos del programa. */
  if (init_program_files() != 0)
    return EXIT_FAILURE;

  if (argc > 1 && !strcmp(argv[1], "drop"))
  {
    unsigned char aes_key_hash[crypto_pwhash_STRBYTES];
    unsigned char aes_key_iv[AES_BLOCK_SIZE];
    char *aes_iv_base64; // Serializacion de aes_key_iv
    if (argc != 3)
    {
      prtusage();
      return EXIT_FAILURE;
    }

    /* Confirmacion de reseteo de clave. */
    printf("Are you sure you want to set a new master key? Setting a master\n");
    printf("key means resetting the encrypted data file and thus deleting all\n");
    printf("the passwords stored on it [Y/N] : ");
    clrbuff();
    if (tolower(getch()) != 'y') // Confirmacion fallida.
      return EXIT_FAILURE;
    if (reset_private_key(argv[2]) != 0)
      return EXIT_FAILURE;
  }
  else if (argc > 1 && !strcmp(argv[1], "set"))
  {
    if (argc != 4)
    {
      prtusage();
      return EXIT_FAILURE;
    }
    int pstate = getpasswd(NULL, argv[2], 0);
    if (pstate == -1)
    {
      getpasswd(NULL, argv[2], 1);
      return EXIT_FAILURE;
    }
    else if (pstate == 1) // Si la password existe
    {
      fprintf(stderr, "error: password name is already taken '%s'\n", argv[2]);
      return EXIT_FAILURE;
    }
    /* pstate = 0 */
    if (setpasswd(argv[2], argv[3]) != 0)
      return EXIT_FAILURE;
  }
  else if (argc > 1 && !strcmp(argv[1], "remove"))
  {
    if (argc != 3)
    {
      prtusage();
      return EXIT_FAILURE;
    }
    printf("Are you sure do you want to remove the indicated password ?\n");
    printf("Once the password it's deleted, you will not have any\n");
    printf("option in order to restore it [Y/N] : ");
    clrbuff();
    if (tolower(getch()) != 'y')
      return EXIT_FAILURE;
    if (rmpasswd(argv[2]) != 0)
      return EXIT_FAILURE;
    printf("Remove process has been completed. '%s' was successfully removed.\n", argv[2]);
  }
  else if (argc > 1 && !strcmp(argv[1], "get"))
  {
    if (argc != 3)
    {
      prtusage();
      return EXIT_FAILURE;
    }
    char password[MAX_PASSWD];
    if (getpasswd(password, argv[2], 1) != 1)
      return EXIT_FAILURE;
    printf("%s\n", password);
  }
  else
  {
    prtusage();
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}