#include "../../include/main.h"
#include "../../include/file.h"

int getpasswd(char *passwd, char *passwd_name, int logs)
{
  char datafile_path[MAX_PATH_LEN]; // Ruta al archivo
  size_t datafile_len;              // Tamaño en bytes del archivo
  char *datafile;                   // Archivo
  char *slnch, *lnch;               // Caracteres de archivo

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
  /* Manejar error de lectura de archivo. */
  if ((datafile = read_file(datafile_path, &datafile_len)) == NULL)
    return -1;

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

int setpasswd(char *password_name, char *password)
{
  if (strlen(password_name) > MAX_PASSWD_NAME)
  {
    errno = EINVAL;
    perror("error: password name is too much long");
    return -1;
  }
  /* En el caso de la longitud de la contraseña, la macro hace mas bien referencia al tamaño de un arreglo en lugar de a la cantidad de caracteres validos para la contraña, lo que significa que la cantidad de caracteres admitidos es siempre inferior en 1 al valor de la macro. */
  else if (strlen(password) >= MAX_PASSWD)
  {
    errno = EINVAL;
    perror("error: password is too much long");
    return -1;
  }

  char datafile_path[MAX_PATH_LEN]; // Ruta al archivo
  /* Manejando error de obtencion de ruta de archivo. */
  if (get_datadir_file_path(datafile_path, DATAFILE_NAME) == -1)
    return -1;

  char nline[MAXLN];
  snprintf(nline, MAXLN, "%s %s\n", password_name, password);

  if (append_file(datafile_path, nline, strlen(nline)) != 0)
    return -1;

  return 0;
}

int rmpasswd(char *password_name)
{
  int pstate = getpasswd(NULL, password_name, 1);
  if (pstate != 1) // Ya sea pq no existe o hay error
    return -1;

  char datafile_path[MAX_PATH_LEN];
  char *datafile;
  size_t datafile_len;
  if (get_datadir_file_path(datafile_path, DATAFILE_NAME) != 0)
    return -1;
  if ((datafile = read_file(datafile_path, &datafile_len)) == NULL)
    return -1;

  char *lnch, *slnch;
  int offset = 0;

  slnch = datafile - 1;
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

      /* Escribir nuevo buffer en archivo. */
      if (write_file(datafile_path, datafile, strlen(datafile)) != 0)
        return -1;

      free(datafile);
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

  free(datafile);
  errno = EAGAIN;
  perror("error: could not search password");
  return -1;
}