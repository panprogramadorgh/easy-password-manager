#include "file.c"
#include "input.c"
#include "crypto.c"

int main(int argc, char *argv[])
{
  /* Verificacion y creacion de archivos de datos del programa.
     $HOME/.local/sahre/epm  */
  char *datadir_path = get_datadir_path();   // Directorio padre
  char *datafile_path = get_datafile_path(); // Contraseñas
  char *keyfile_path = get_keyfile_path();   // Clave privada
  char *ivfile_path = get_ivfile_path();     // Vector inicializacion
  if (verify_program_files(datadir_path,
                           datafile_path,
                           keyfile_path,
                           ivfile_path) != 0)
    return EXIT_FAILURE;

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

    /* Generando clave para AES aplicando funcion hash a password introducida por usuario. */
    unsigned char aes_key_buffer[AES_KEY_LENGTH / 8];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));
    if (crypto_pwhash(aes_key_buffer, sizeof(aes_key_buffer), argv[2], strlen(argv[2]), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
    {
      fprintf(stderr, "error: there was an error derivating user input key.\n");
      return EXIT_FAILURE;
    };

    /* Codificando clave AES de buffer binario a base64 y hasheandola en un string para guardarla en variable de entorno. */
    const char *aes_key_base64 = serialize_buffer_to_base64(aes_key_buffer, sizeof(aes_key_buffer));
    char aes_key_hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(aes_key_hash, aes_key_base64, strlen(aes_key_base64), crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0)
    {
      fprintf(stderr, "error: there was an error derivating derivated key.\n");
      return EXIT_FAILURE;
    };

    /* Generando vector de inicializacion para AES. */
    unsigned char aes_iv_buffer[AES_BLOCK_SIZE];
    RAND_bytes(aes_iv_buffer, sizeof(aes_iv_buffer));
    const char *aes_iv_base64 = serialize_buffer_to_base64(aes_iv_buffer, sizeof(aes_iv_buffer));

    /* Vaciando archivo de datos.  */
    FILE *datafile = fopen(datafile_path, "w+");
    if (datafile == NULL)
    {
      fprintf(stderr, "error: there was an error creating new data file.\n");
      return EXIT_FAILURE;
    }
    fclose(datafile);

    /* Guardando nueva clave. */
    FILE *keyfile = fopen(aes_key_base64, "w+");
    if (keyfile == NULL)
    {
      fprintf(stderr, "error: there was an error creating new key file.\n");
      return EXIT_FAILURE;
    }
    fprintf(keyfile, "%s", aes_key_base64);
    fclose(keyfile);

    /* Guardando nuevo vector de inicializacion. */
    FILE *ivfile = fopen(ivfile_path, "w+");
    if (ivfile == NULL)
    {
      fprintf(stderr, "error: there was an error creating new iv file.\n");
      return EXIT_FAILURE;
    }
    fprintf(ivfile, "%s", aes_iv_base64);
    fclose(ivfile);
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

  /* Liberar memoria relativa a las rutas de archivos de datos. */
  free(datadir_path);
  free(datafile_path);
  free(keyfile_path);
  free(ivfile_path);
  datadir_path = datafile_path =
      keyfile_path = ivfile_path = NULL;

  return EXIT_SUCCESS;
}