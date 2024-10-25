#include "../../include/main.h"
#include "../../include/file.h"
#include "../../include/crypto.h"
#include <sodium.h>

int init_program_files()
{
  char path[MAX_PATH_LEN];

  /* Creacion de directorio de datos. */
  if (get_datadir_path(path) == 0 && !direxists(path))
  {
    if (createdir(path) != 0)
      return -1;
  }
  /* Creacion del archivo de datos. */
  if (get_datadir_file_path(path, DATAFILE_NAME) == 0 && !filexists(path))
  {
    if (create_file(path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
      return -1;
  }
  /* Creacion del archivo de clave. */
  if (get_datadir_file_path(path, KEYFILE_NAME) == 0 && !filexists(path))
  {
    if (create_file(path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
      return -1;
  }
  /* Creacion del archivo de iv. */
  if (get_datadir_file_path(path, IVFILE_NAME) == 0 && !filexists(path))
  {
    if (create_file(path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
      return -1;
  }

  return 0;
}

int reset_private_key(char *newkey)
{
  char datafile_path[MAX_PATH_LEN];
  char keyfile_path[MAX_PATH_LEN];
  char ivfile_path[MAX_PATH_LEN];
  if (
      get_datadir_file_path(datafile_path, DATAFILE_NAME) == -1 ||
      get_datadir_file_path(keyfile_path, KEYFILE_NAME) == -1 ||
      get_datadir_file_path(ivfile_path, IVFILE_NAME) == -1)
  {
    fprintf(stderr, "error: there was an error calculating program data files paths.\n");
    return -1;
  }

  unsigned char aes_key_hash[crypto_pwhash_STRBYTES];
  unsigned char aes_key_iv[AES_BLOCK_SIZE];
  char *aes_iv_base64; // Serializacion de aes_key_iv

  /* Generando hash de cadena aragon. */
  if (crypto_pwhash_str(aes_key_hash, newkey, strlen(newkey), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0)
  {
    perror("error: could not implement hashing algorithm");
    return -1;
  }

  /* Generando vector de inicializacion para AES. */
  RAND_bytes(aes_key_iv, sizeof(aes_key_iv));
  aes_iv_base64 = serialize_buffer_to_base64(aes_key_iv, sizeof(aes_key_iv));

  /* Vaciando archivo de datos.  */
  if (create_file(datafile_path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
  {
    fprintf(stderr, "error: there was an error resetting data file.\n");
    return -1;
  }

  /* Guardando nueva clave hasheada. */
  if (write_file(keyfile_path, aes_key_hash, crypto_pwhash_STRBYTES) != 0)
    return -1;

  /* Guardando nuevo vector de inicializacion. */
  if (write_file(ivfile_path, aes_iv_base64, strlen(aes_iv_base64)) != 0)
  {
    write_file(keyfile_path, "", 0); // Vaciar clave en caso de error.
    return -1;
  }
  free(aes_iv_base64); // Liberar memoria

  printf("New master key for encryping data file has been stablished successfully.\n");
  printf("%s\n", aes_key_hash);

  return 0;
}