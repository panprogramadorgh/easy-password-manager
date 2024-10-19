#include "file.c"
#include "input.c"
#include "crypto.c"

int main(int argc, char *argv[])
{
  /* Rutas de archivos de datos del programa. */
  char datadir_path[MAX_PATH_LEN];
  char datafile_path[MAX_PATH_LEN];
  char keyfile_path[MAX_PATH_LEN];
  char ivfile_path[MAX_PATH_LEN];
  if (get_datadir_path(datadir_path) == -1 ||
      get_datadir_file_path(datafile_path, DATAFILE_NAME) == -1 ||
      get_datadir_file_path(keyfile_path, KEYFILE_NAME) == -1 ||
      get_datadir_file_path(ivfile_path, IVFILE_NAME) == -1)
  {
    fprintf(stderr, "error: there was an error calculating program data files paths.\n");
    return EXIT_FAILURE;
  }

  /* Inicializacion de archivos de datos del programa. */
  if (init_program_files() != 0)
    return EXIT_FAILURE;

  if (argc > 1 && !strcmp(argv[1], "set-master-key"))
  {
    /* Buffers. */
    unsigned char aes_key_buffer[AES_KEY_LENGTH / 8];
    unsigned char aes_iv_buffer[AES_BLOCK_SIZE];
    /* Hashing. */
    char aes_key_hash[crypto_pwhash_STRBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    /* Base64*/
    char *aes_key_base64;
    char *aes_iv_base64;

    if (argc != 3)
    {
      prtusage();
      return EXIT_FAILURE;
    }

    /* Confirmacion de reseteo de clave. */
    printf("Are you sure you want to set a new master key? Setting a master\n");
    printf("key means resetting the encrypted data file and thus deleting all\n");
    printf("the passwords stored on it [Y/N]: ");
    clrbuff();
    if (tolower(getch()) != 'y') // Confirmacion fallida.
    {
      fprintf(stderr, "error: incorrect confirmation.\n");
      return EXIT_FAILURE;
    }

    /* Generando clave para AES aplicando funcion hash a password introducida por usuario. */
    randombytes_buf(salt, sizeof(salt));
    if (crypto_pwhash(aes_key_buffer, sizeof(aes_key_buffer), argv[2], strlen(argv[2]), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
    {
      fprintf(stderr, "error: there was an error derivating user input key.\n");
      return EXIT_FAILURE;
    };

    /* Codificando clave AES de buffer binario a base64 y hasheandola en un string para guardarla en variable de entorno. */
    aes_key_base64 = serialize_buffer_to_base64(aes_key_buffer, sizeof(aes_key_buffer));
    if (crypto_pwhash_str(aes_key_hash, aes_key_base64, strlen(aes_key_base64), crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0)
    {
      fprintf(stderr, "error: there was an error derivating derivated key.\n");
      return EXIT_FAILURE;
    };
    free(aes_key_base64); // Liberar memoria
    aes_key_base64 = NULL;

    /* Generando vector de inicializacion para AES. */
    RAND_bytes(aes_iv_buffer, sizeof(aes_iv_buffer));
    aes_iv_base64 = serialize_buffer_to_base64(aes_iv_buffer, sizeof(aes_iv_buffer));

    /* Vaciando archivo de datos.  */
    if (create_file(datafile_path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
    {
      fprintf(stderr, "error: there was an error resetting data file.\n");
      return EXIT_FAILURE;
    }

    /* Guardando nueva clave. */
    if (write_file(keyfile_path, aes_key_hash, crypto_pwhash_STRBYTES) != 0)
      return EXIT_FAILURE;

    /* Guardando nuevo vector de inicializacion. */
    if (write_file(ivfile_path, aes_iv_base64, strlen(aes_iv_base64)) != 0)
      return EXIT_FAILURE;
    free(aes_iv_base64); // Liberar memoria

    printf("New master key for encryping data file has been stablished successfully.\n");
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