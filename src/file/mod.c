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
  /* Creacion del archivo de salt de clave. */
  if (get_datadir_file_path(path, KEYSLTFILE_NAME) == 0 && !filexists(path))
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
  char data_path[MAX_PATH_LEN];
  char key_path[MAX_PATH_LEN];
  char keysalt_path[MAX_PATH_LEN];
  char iv_path[MAX_PATH_LEN];
  if (
      get_datadir_file_path(data_path, DATAFILE_NAME) == -1 ||
      get_datadir_file_path(key_path, KEYFILE_NAME) == -1 ||
      get_datadir_file_path(keysalt_path, KEYSLTFILE_NAME) == -1 ||
      get_datadir_file_path(iv_path, IVFILE_NAME) == -1)
  {
    perror("error: could not stablish new private key");
    return -1;
  }

  unsigned char key[crypto_pwhash_STRBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];
  unsigned char iv[AES_BLOCK_SIZE];
  char *salt_base64;
  char *iv_base64; // Serializacion de iv

  /* Generando hash de cadena aragon. */
  if (crypto_pwhash_str(key, newkey, strlen(newkey), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0)
  {
    perror("error: could not stablish new private key");
    return -1;
  }

  /* Generando salt para clave AES. */
  randombytes_buf(salt, sizeof(salt));
  salt_base64 = serialize_buffer_to_base64(salt, sizeof(salt));

  /* Generando vector de inicializacion para AES. */
  randombytes_buf(iv, sizeof(iv));
  iv_base64 = serialize_buffer_to_base64(iv, sizeof(iv));

  /* Vaciando archivo de datos.  */
  if (create_file(data_path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
  {
    perror("error: could not stablish new private key");
    free(salt_base64);
    free(iv_base64);
    return -1;
  }

  /* Guardando nueva clave hasheada. */
  if (write_file(key_path, key, crypto_pwhash_STRBYTES) != 0)
  {
    free(salt_base64);
    free(iv_base64);
    return -1;
  }

  /* Guardando nuevo salt para clave AES. */
  if (write_file(keysalt_path, salt_base64, strlen(salt_base64)) != 0)
  {
    write_file(key_path, "", 0);
    free(salt_base64);
    free(iv_base64);
    return -1;
  }

  /* Guardando nuevo vector de inicializacion. */
  if (write_file(iv_path, iv_base64, strlen(iv_base64)) != 0)
  {
    write_file(key_path, "", 0);
    write_file(keysalt_path, "", 0);
    free(salt_base64);
    free(iv_base64);
    return -1;
  }

  free(salt_base64);
  free(iv_base64);

  printf("New master key for encryping data file has been stablished successfully.\n");
  printf("%s\n", key);

  return 0;
}