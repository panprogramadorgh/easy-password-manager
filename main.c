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

  /* Inicializacion de archivos de datos del programa. */
  if (init_program_files() != 0)
    return EXIT_FAILURE;

  char *private_key = (char *)malloc(MAXLN);
  enum auth_signals auth_state = auth(private_key);
  if (auth_state == auth_failure ||
      auth_state == auth_error)
    return EXIT_FAILURE;
  if (auth_state == auth_nokey ||
      auth_state == auth_corrupted)
  {
    char new_private_key[MAXLN];
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
      {
        free(private_key);
        return EXIT_FAILURE;
      }
    }
    getnline(new_private_key, MAXLN);
    if (reset_private_key(new_private_key) != 0)
    {
      free(private_key);
      return EXIT_FAILURE;
    }
  }

  if (argc > 1 && !strcmp(argv[1], "reset"))
  {
    if (argc != 3)
    {
      prtusage();
      free(private_key);
      return EXIT_FAILURE;
    }

    /* Confirmacion de reseteo de clave. */
    printf("Are you sure you want to set a new master key? Setting a master\n");
    printf("key means resetting the encrypted data file and thus deleting all\n");
    printf("the passwords stored on it [Y/N] : ");
    clrbuff();
    if (tolower(getch()) != 'y') // Confirmacion fallida.
    {
      free(private_key);
      return EXIT_FAILURE;
    }
    if (reset_private_key(argv[2]) != 0)
    {
      free(private_key);
      return EXIT_FAILURE;
    }
  }
  else if (argc > 1 && !strcmp(argv[1], "set"))
  {
    if (argc != 4)
    {
      prtusage();
      free(private_key);
      return EXIT_FAILURE;
    }
    /* pstate = 0 */
    if (setpasswd(argv[2], argv[3], private_key) != 0)
    {
      free(private_key);
      return EXIT_FAILURE;
    }

    printf("Password '%s' has been stablished.\n", argv[2]);
  }
  else if (argc > 1 && !strcmp(argv[1], "remove"))
  {
    if (argc != 3)
    {
      prtusage();
      free(private_key);
      return EXIT_FAILURE;
    }
    printf("Are you sure do you want to remove the indicated password ?\n");
    printf("Once the password it's deleted, you will not have any\n");
    printf("option in order to restore it [Y/N] : ");
    clrbuff();
    if (tolower(getch()) != 'y')
    {
      free(private_key);
      return EXIT_FAILURE;
    }
    if (rmpasswd(argv[2], private_key) != 0)
    {
      free(private_key);
      return EXIT_FAILURE;
    }
    printf("Remove process has been completed. '%s' was successfully removed.\n", argv[2]);
  }
  else if (argc > 1 && !strcmp(argv[1], "get"))
  {
    if (argc != 3)
    {
      prtusage();
      free(private_key);
      return EXIT_FAILURE;
    }
    char password[MAX_PASSWD];
    if (getpasswd(password, argv[2], private_key, 1) != 1)
    {
      free(private_key);
      return EXIT_FAILURE;
    }
    printf("%s\n", password);
  }
  else
  {
    free(private_key);
    prtusage();
    return EXIT_FAILURE;
  }

  free(private_key);
  return EXIT_SUCCESS;
}