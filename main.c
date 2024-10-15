#include "file.c"
#include "input.c"
#include "crypto.c"

int main(int argc, char *argv[])
{
  if (argc > 1 && !strcmp(argv[1], "set-master-key"))
  {
    if (argc != 3)
    {
      prtusage();
      return EXIT_FAILURE;
    }
    char *confirm = "I want to DELETE ALL passwords";
    printf("Are you sure you want to set a new master key? Setting a master\n");
    printf("key means resetting the encrypted data file and thus deleting all\n");
    printf("the passwords stored on it.\n\n");
    printf("If you are really sure, type the following message and press [Enter]:  %s\n\n", confirm);
    char line[MAXLN];
    getnline(line, MAXLN);
    if (strcmp(confirm, line)) // Confirmacion fallida.
    {
      fprintf(stderr, "error: incorrect confirmation.\n");
      return EXIT_FAILURE;
    }
    /* Guardar password hasheada en variable de entorno. */
    unsigned char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, line, strlen(line), crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0)
    {
      fprintf(stderr, "error: unexpected error when derivating key.\n");
      return EXIT_FAILURE;
    }
    printf("%s\n", hash);
  }
  else if (argc > 1 && !strcmp(argv[1], "set-passwd"))
  {
    if (argc != 4)
    {
      prtusage();
      return EXIT_FAILURE;
    }
    if (getpasswd(argv[2], NULL) == success)
    {
      printf("error: password name is taken '%s'\n", argv[2]);
      return EXIT_FAILURE;
    }
    int signal = setpasswd(argv[2], argv[3]);
    if (signal == inv_arg_err)
      printf("error: to long arguments.\n");
    else if (signal == open_file_err)
      printf("error: read file error.\n");
  }
  else if (argc > 1 && !strcmp(argv[1], "get-passwd"))
  {
    if (argc != 3)
    {
      prtusage();
      return EXIT_FAILURE;
    }
    char passvalue[MAXPASSVAL];
    int signal = getpasswd(argv[2], passvalue);
    if (signal == success)
      printf("%s\n", passvalue);
    else if (signal == not_found_err)
      printf("error: password not found '%s'\n", argv[2]);
    else if (signal == open_file_err)
      printf("error: read file error.\n");
  }
  else
  {
    prtusage();
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}