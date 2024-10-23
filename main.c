#include "main.h"
#include "include/main.h"
#include "include/crypto.h"
#include "include/file.h"
#include "include/input.h"

// TODO: Reemplazar fprintf(stderr ... con perror

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

  if (argc > 1 && !strcmp(argv[1], "drop"))
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
    printf("the passwords stored on it [Y/N] : ");
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
    {
      printf("Remove process has been cancelled.\n");
      return EXIT_FAILURE;
    }
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