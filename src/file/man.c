#include "../../include/main.h"
#include "../../include/file.h"
#include "../../include/crypto.h"

int getpasswd(char *passwd, char *passwd_name, char *private_key, int logs)
{
  char datafile_path[MAX_PATH_LEN]; // Ruta al archivo de datos
  char ivfile_path[MAX_PATH_LEN];   // Ruta al archivo de iv

  char
      *iv_base64,
      *iv_buffer,
      *datafile,
      *enc_datafile,
      *enc_datafile_base64;
  size_t
      iv_base64_len,
      iv_buffer_len,
      enc_datafile_len,
      enc_datafile_base64_len;

  char *slnch, *lnch; // Caracteres de archivo

  /* Manejar error por espacios en passwd_name. */
  for (char *pwnch = passwd_name; *pwnch; pwnch++)
    if (*pwnch == ' ')
    {
      errno = EILSEQ;
      if (logs)
        perror("error: passwd_name cannot include the space character");
      return -1;
    }
  /* Manejando error de obtencion de ruta de archivo. */
  if (get_datadir_file_path(datafile_path, DATAFILE_NAME) == -1)
  {
    errno = ENOMEM;
    if (logs)
      perror("error: cannot calculate path too file");
    return -1;
  }
  if (get_datadir_file_path(ivfile_path, IVFILE_NAME) == -1)
  {
    errno = ENOMEM;
    if (logs)
      perror("error: cannot calculate path too file");
    return -1;
  }

  /* Manejar error de lectura de archivos. */
  if ((enc_datafile_base64 = read_file(datafile_path, &enc_datafile_base64_len)) == NULL)
    return -1;
  if ((iv_base64 = read_file(ivfile_path, &iv_base64_len)) == NULL)
    return -1;

  /* Deserializando archivo de datos a binary buffer. */
  enc_datafile = deserialize_base64_to_buffer(enc_datafile_base64, &enc_datafile_len);

  /* Deserializando base64 en buffer de iv. */
  iv_buffer = deserialize_base64_to_buffer(iv_base64, &iv_buffer_len);

  /* Asignar memoria dinamica suficiente para el texto plano. */
  datafile = (char *)malloc(enc_datafile_len + AES_BLOCK_SIZE + MAXLN);
  if (datafile == NULL)
  {
    perror("error: colud not allocate memory");
    return -1;
  }

  /* Desencriptar archivo de datos. */
  decrypt(enc_datafile, enc_datafile_len, private_key, iv_buffer, datafile);

  free(enc_datafile_base64);
  free(enc_datafile);
  free(iv_base64);
  free(iv_buffer);

  /* Iterar sobre cada linea. */
  slnch = datafile - 1;
  do
  {
    slnch++; // Primer caracter de linea.
    for (lnch = slnch;
         lnch - slnch < MAX_PASSWD_NAME && // ❌
         *lnch && *lnch != '\n'            // ❌
         && *lnch != ' ';                  // ✔
         lnch++)
      ;
    // TODO: Mejorar sistema de errores (aportar alguna solucion a la corrupcion).
    /* Manejando error por nombre demasiado largo. */
    if (lnch - slnch >= MAX_PASSWD_NAME)
    {
      free(datafile);
      errno = ENOMEM;
      if (logs)
        perror("error: password is corrupted as its name is too much long");
      return -1;
    }
    /* Manejo de error para contraseñas sin valor. */
    else if (*lnch == '\0' || *lnch == '\n')
    {
      if (lnch - slnch <= 0) // Ignora contraseñas sin nombre o lineas vacias.
        continue;

      free(datafile);
      errno = EILSEQ;
      if (logs)
        perror("error: password is corrupted since it does not have any value");
      return -1;
    }
    else // if (*lnch == ' ')
    {
      *lnch++ = '\0';
      char *password = lnch;

      /* Comparar el nombre de la contraseña. */
      if (strncmp(passwd_name, slnch, MAX_PASSWD_NAME) == 0)
      {
        /* Escribir en el arreglo del parametro el valor para la contraña. */
        for (;
             lnch - password < MAX_PASSWD - 1 &&     // Paso linea por limite
             *lnch && *lnch != '\n' && *lnch != ' '; // Paso linea por caracter
             lnch++)
        {
          if (passwd != NULL)
            passwd[lnch - password] = *lnch;
        }
        if (passwd != NULL)
          passwd[lnch - password] = '\0';

        /* Manejando error de longitud de password. */
        if (lnch - password >= MAX_PASSWD - 1)
        {
          free(datafile);
          errno = ENOMEM;
          if (logs)
            perror("error: password is corrupted, it is too much long");
          return -1;
        }
        /* Manejando error de corrupcion en el archivo (espacio en contraseña). */
        else if (*lnch == ' ')
        {
          free(datafile);
          errno = EILSEQ;
          if (logs)
            perror("error: password is corrupted since it contains space characters");
          return -1;
        }

        free(datafile);
        return 1;
      }
      else
      {
        /* Incrementando puntero para*/
        for (;
             lnch - password < MAX_PASSWD - 1 &&     // Paso linea por limite
             *lnch && *lnch != '\n' && *lnch != ' '; // Paso linea por caracter
             lnch++)
          ;
        /* Manejando error de longitud de password. */
        if (lnch - password >= MAX_PASSWD - 1)
        {
          free(datafile);
          errno = ENOMEM;
          if (logs)
            perror("error: password file is corrupted since there are too much long passwords");
          return -1;
        }
        /* Manejando error de corrupcion en el archivo (espacio en contraseña). */
        else if (*lnch == ' ')
        {
          free(datafile);
          errno = EILSEQ;
          if (logs)
            perror("error: password file is corrupted since there are passwords which contains space characters");
          return -1;
        }
        slnch = lnch;
      }
      password[-1] = ' ';
    }
  } while (*slnch);

  free(datafile);
  errno = EINVAL;
  if (logs)
    perror("error: password name has not been found");
  return 0;
}

int setpasswd(char *password_name, char *password, char *private_key)
{
  /* Errores de formato de contraseña. */
  size_t password_name_len, password_len;
  if ((password_name_len = strlen(password_name)) > MAX_PASSWD_NAME)
  {
    errno = EINVAL;
    perror("error: password name is too much long");
    return -1;
  }
  /* En el caso de la longitud de la contraseña, la macro hace mas bien referencia al tamaño de un arreglo en lugar de a la cantidad de caracteres validos para la contraña, lo que significa que la cantidad de caracteres admitidos es siempre inferior en 1 al valor de la macro. */
  else if ((password_len = strlen(password)) >= MAX_PASSWD)
  {
    errno = EINVAL;
    perror("error: password is too much long");
    return -1;
  }

  /* Error de duplicidad de contraseña. */
  int pstate = getpasswd(NULL, password_name, private_key, 0);
  if (pstate == -1)
  {
    getpasswd(NULL, password_name, private_key, 1);
    return -1;
  }
  else if (pstate == 1) // Si la password existe
  {
    errno = EINVAL;
    perror("error: password name is already taken");
    return -1;
  }

  char datafile_path[MAX_PATH_LEN]; // Ruta al archivo de datos
  char ivfile_path[MAX_PATH_LEN];   // Ruta al archivo de iv

  // TODO: Minizar uso de bloques de memoria diferentes en lugar de redimensionarlos.

  char
      *iv_base64,
      *iv_buffer,
      *datafile,
      *enc_datafile,
      *new_enc_datafile,
      *enc_datafile_base64,
      *new_enc_datafile_base64;

  size_t
      iv_base64_len,
      iv_buffer_len,
      datafile_len,
      enc_datafile_len,
      new_enc_datafile_len,
      enc_datafile_base64_len,
      new_enc_datafile_base64_len;

  /* Manejando error de obtencion de ruta de archivo. */
  if (get_datadir_file_path(datafile_path, DATAFILE_NAME) == -1)
    return -1;
  if (get_datadir_file_path(ivfile_path, IVFILE_NAME) == -1)
    return -1;

  /* Manejar error de lectura de archivos. */
  if ((enc_datafile_base64 = read_file(datafile_path, &enc_datafile_base64_len)) == NULL)
    return -1;
  if ((iv_base64 = read_file(ivfile_path, &iv_base64_len)) == NULL)
    return -1;

  /* Deserializar archivo de datos en binary buffer. */
  enc_datafile = deserialize_base64_to_buffer(enc_datafile_base64, &enc_datafile_len);

  /* Deserializar iv en base64 a binary buffer. */
  iv_buffer = deserialize_base64_to_buffer(iv_base64, &iv_buffer_len);

  /* Asignar memoria dinamica suficiente para el texto plano. Se hace mas grande como sea necesario para albergar una linea mas.*/
  datafile = (char *)malloc(enc_datafile_len + AES_BLOCK_SIZE + MAXLN);
  if (datafile == NULL)
  {
    perror("error: colud not allocate memory");
    return -1;
  }

  /* Desencriptar archivo de datos en texto plano. */
  decrypt(enc_datafile, enc_datafile_len, private_key, iv_buffer, datafile);

  /* Obtener longitud del texto plano. */
  datafile_len = strlen(datafile);

  /* Introducir linea en texto plano. */
  snprintf(datafile + datafile_len, MAXLN, "%s %s\n", password_name, password);
  datafile_len = strlen(datafile);

  /* Asignar memoria dinamica para nuevo archivo encriptado. */
  new_enc_datafile = (char *)malloc(datafile_len + AES_BLOCK_SIZE);
  if (new_enc_datafile == NULL)
  {
    perror("error: colud not allocate memory");
    return -1;
  }

  // Volver a encriptar y guardar archivo
  new_enc_datafile_len = encrypt(datafile, datafile_len, private_key, iv_buffer, new_enc_datafile);

  /* Serializacion de buffer cifrado. */
  new_enc_datafile_base64 = serialize_buffer_to_base64(new_enc_datafile, new_enc_datafile_len);
  new_enc_datafile_base64_len = strlen(new_enc_datafile_base64);

  free(new_enc_datafile);
  free(enc_datafile);
  free(datafile);
  free(iv_base64);
  free(iv_buffer);

  if (write_file(datafile_path, new_enc_datafile_base64, new_enc_datafile_base64_len) != 0)
  {
    free(new_enc_datafile_base64);
    return -1;
  }

  free(new_enc_datafile_base64);
  return 0;
}

int rmpasswd(char *password_name, char *private_key)
{
  int pstate = getpasswd(NULL, password_name, private_key, 1);
  if (pstate != 1) // Ya sea pq no existe o hay error
    return -1;

  char data_path[MAX_PATH_LEN];
  char iv_path[MAX_PATH_LEN];

  char
      *enc_data_base64,
      *enc_data, // binary buffer
      *new_enc_data,
      *new_enc_data_base64,
      *data,
      *iv_base64,
      *iv;
  size_t
      enc_data_base64_len,
      enc_data_len,
      new_enc_data_len,
      new_enc_data_base64_len,
      data_len,
      iv_base64_len,
      iv_len;

  if (get_datadir_file_path(data_path, DATAFILE_NAME) != 0)
    return -1;
  if (get_datadir_file_path(iv_path, IVFILE_NAME) != 0)
    return -1;

  if ((enc_data_base64 = read_file(data_path, &enc_data_base64_len)) == NULL)
    return -1;
  if ((iv_base64 = read_file(iv_path, &iv_base64_len)) == NULL)
  {
    free(enc_data_base64);
    return -1;
  }

  /* Deserializar datos en buffer binario. */
  enc_data = deserialize_base64_to_buffer(enc_data_base64, &enc_data_len);
  iv = deserialize_base64_to_buffer(iv_base64, &iv_len);

  /* Asignar bloque de memoria en donde guardar texto plano. */
  data = (char *)malloc(enc_data_len + AES_BLOCK_SIZE);
  if (data == NULL)
  {
    perror("error: could not remove password");
    return -1;
  }

  /* Desencriptar buffer. */
  decrypt(enc_data, enc_data_len, private_key, iv, data);

  free(enc_data_base64);
  free(enc_data);
  free(iv_base64);

  char *lnch,
      *slnch;
  int offset = 0;

  slnch = data - 1;
  do
  {
    /* Obteniendo nombre de password. */
    slnch++;
    for (lnch = slnch;
         lnch - slnch < MAX_PASSWD_NAME &&       // Paso de linea por longitud de nombre
         *lnch && *lnch != '\n' && *lnch != ' '; // Paso de linea por caracter
         lnch++)
      ;
    *lnch++ = '\0';
    char *password = lnch;
    if (strcmp(password_name, slnch) == 0)
    {
      /* Desplazarse al final de la linea. */
      for (;
           lnch - password < MAX_PASSWD - 1 &&
           *lnch && *lnch != '\n' && *lnch != ' ';
           lnch++)
        ;
      password[-1] = ' ';
      offset = (lnch - slnch) + 1;

      /* Desplazar caracteres offset veces a partir de la password a eliminar.*/
      for (lnch = slnch + offset; *lnch; lnch++)
        lnch[-offset] = *lnch;
      lnch[-offset] = '\0';

      /* Obtener nueva longitud de datos. */
      data_len = strlen(data);

      /* Nuevos datos encriptados en buffer binario. */
      new_enc_data = (char *)malloc(data_len + AES_BLOCK_SIZE);

      /* Encriptar nuevos datosen buffer binaio. */
      encrypt(data, data_len, private_key, iv, new_enc_data);
      new_enc_data_len = strlen(new_enc_data);

      /* Serializar nuevos datos encriptadose en base64. */
      new_enc_data_base64 = serialize_buffer_to_base64(new_enc_data, new_enc_data_len);
      new_enc_data_base64_len = strlen(new_enc_data_base64);

      /* Escribir nuevo buffer en archivo. */
      if (write_file(data_path, new_enc_data_base64, new_enc_data_base64_len) != 0)
      {
        free(data);
        free(new_enc_data_base64);
        free(new_enc_data);
        free(iv);
        return -1;
      }

      free(data);
      free(new_enc_data_base64);
      free(new_enc_data);
      free(iv);
      return 0;
    }
    else
    {
      /* Desplazarse al final de la linea. */
      for (;
           lnch - password < MAX_PASSWD - 1 &&
           *lnch && *lnch != '\n' && *lnch != ' ';
           lnch++)
        ;
      /* Avanzar a la siguiente linea. */
      password[-1] = ' ';
      slnch = lnch;
    }
  } while (*slnch && offset == 0);

  free(data);
  errno = EAGAIN;
  perror("error: could not search password");
  return -1;
}