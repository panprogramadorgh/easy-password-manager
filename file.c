#include "main.h"

// TODO: Reemplazar fprintf(stderr, ...) com perror.

/* --- Obtencion de rutas para archivo de datos. --- */

/* Determina la maxima cantidad de caracteres para una ruta. */
#define MAX_PATH_LEN 256

#define DATAFILE_NAME "epm_data.enc"
#define KEYFILE_NAME "epm_aes_hashed_key.key"
#define IVFILE_NAME "epm_aes_iv.key"

/* Determina la maxima cantidad de caracteres para el nombre de una contraseña. */
#define MAX_PASSWD_NAME 64
/* Determina la maxima cantidad de caracteres para una contraseña. */
#define MAX_PASSWD (MAXLN - MAX_PASSWD_NAME - 2) // Quitar el espacio entre nombre y valor y el fin de linea (\n o \0)

/* Permite obtener la ruta al directorio donde se encuentran los archivos de datos. Retorna la longitud de la ruta o -1 en caso de error por desbordamiento de maxima cantidad de caracteres para ruta. */
static int get_datadir_path(char *dirpath)
{
  char *home = getenv("HOME"); // /home/alvaro
  char *rmng = ".local/share/epm";
  /* En caso de exceso (tambien hay que contar la /) */
  if (strlen(home) + strlen(rmng) + 1 >= MAX_PATH_LEN)
  {
    errno = ENOMEM;
    perror("error: max path length exceded");
    return -1;
  }
  // /home/alvaro/.local/share/epm
  snprintf(dirpath, MAX_PATH_LEN, "%s/%s", home, rmng);
  return 0;
}

/* Permite obtener la ruta a un archivo de datos del programa. filepath sera un buffer con al menos 256 caracteres de tamaño y rpath la ruta relativa desde el directorio de datos. La funcion retorna la longitud o -1 en caso de error. */
static int get_datadir_file_path(
    char *filepath,
    char *rpath /* ruta relativa al archivo */)
{
  int dirpath_len, rpath_len;
  if (get_datadir_path(filepath) != 0)
    return -1;
  dirpath_len = strlen(filepath);
  rpath_len = strlen(rpath);
  if (dirpath_len + rpath_len + 1 >= MAX_PATH_LEN)
  {
    errno = ENOMEM;
    perror("error: max path length exceded");
    return -1;
  }
  snprintf(filepath + dirpath_len, MAX_PATH_LEN - dirpath_len, "/%s", rpath);
  return 0;
}

/* --- Funciones genericas de archivos. --- */

/* Retorna 1 si el directorio existe, 0 si no. */
int direxists(char *path)
{
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Retorna 1 si el archivo existe, 0 si no. */
int filexists(char *path)
{
  struct stat st;
  return stat(path, &st) == 0 && !S_ISDIR(st.st_mode);
}

/* Permire crear todos los directorios intermedios en una ruta. */
int createdir(char *path)
{
  char spath[MAX_PATH_LEN];
  char *ch;
  int path_len;

  snprintf(spath, sizeof(spath), "%s", path);
  path_len = strlen(spath);

  /* Eliminar utlima barra si existe. */
  if (spath[path_len - 1] == '/')
    spath[path_len - 1] = '\0';

  /* Crea cada una de las carpetas intermedias en la ruta.  */
  for (ch = spath + 1; *ch; ch++)
  {
    if (*ch == '/')
    {
      *ch = '\0';
      /* Crear carpeta */
      if (mkdir(spath, 0755) != 0 && errno != EEXIST)
      {
        errno = EAGAIN;
        perror("error: directory could not be created");
        return -1;
      };
      *ch = '/';
    }
  }
  /* Ultimo directorio. */
  if (mkdir(spath, 0755) != 0 && errno != EEXIST)
  {
    errno = EAGAIN;
    perror("error: directory could not be created");
    return -1;
  }

  return 0;
}

/* Permite crear un archivo e introducir contenido en el al mismo tiempo. Si se creo correctamente devuelve 0, si no, -1. */
int create_file(char *path, char *content, int content_len, int access)
{
  struct stat st;
  /* Si existe el archivo se elimina. */
  if (filexists(path))
    if (remove(path) != 0)
    {
      errno = EAGAIN;
      perror("error: file could not be created");
      return -1;
    }
  /* Se crea el archivo bajo los permisos determinados. */
  int fd = open(path, O_CREAT | O_WRONLY, access);
  if (fd == -1)
  {
    errno = EAGAIN;
    perror("error: file could not be created");
    return -1;
  }
  /* En caso de que se quiera introducir contenido.  */
  if (content != NULL)
    if (write(fd, content, content_len) == -1)
    {
      close(fd);
      remove(path);
      perror("error: content could not be written in file");
      return -1;
    }
  close(fd);
  return 0;
}

/* Permite la escritura de archivos. Si no existe el archivo o si hay cualquier error retorna -1, si todo fue bien retorna 0. */
int write_file(char *path, char *content, int content_len)
{
  int fd = open(path, O_WRONLY);
  if (fd == -1)
  {
    perror("error: there was an error opening file");
    return -1;
  }
  if (write(fd, content, content_len) == -1)
  {
    perror("error: there was an error writing file");
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

/* Permite la escritura apendices sobre archivos. Si no existe el archivo o si hay cualquier error retorna -1, si todo fue bien retorna 0. */
int append_file(char *path, char *content, int content_len)
{
  int fd = open(path, O_WRONLY | O_APPEND);
  if (fd == -1)
  {
    perror("error: there was an error opening file");
    return -1;
  }
  if (write(fd, content, content_len) == -1)
  {
    perror("error: there was an error writing file");
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

/* Permire leer el archivo path facilmente devolviendo un puntero o NULL en caso de error. */
char *read_file(char *path, size_t *len)
{
  char *buffer;       // Donde se almacenara el archivo leido
  int fd;             // Descriptor de arhivo
  off_t buffer_size;  // Tamaño del buffer
  ssize_t bytes_read; // Bytes leidos

  /* Comprobar que la ruta pertenezca a un archivo. */
  if (filexists(path) == 0)
  {
    errno = EISDIR;
    perror("error: invalid path");
    return NULL;
  }

  /* Abrir el archivo en modo lectura. */
  fd = open(path, O_RDONLY);
  if (fd == -1)
  {
    perror("error: could not open file");
    return NULL;
  }
  /* Obtener tamaño de buffer. */
  buffer_size = lseek(fd, 0, SEEK_END);
  if (buffer_size == -1)
  {
    perror("error: could not get file size");
    close(fd);
    return NULL;
  }
  if (lseek(fd, 0, SEEK_SET) == -1) // Posicionar lectura de archivo.
  {
    perror("error: could not resset file offset");
    close(fd);
    return NULL;
  }
  /* Asignando memoria. */
  buffer = (char *)malloc(buffer_size + 1); // Fin de cadena.
  if (buffer == NULL)
  {
    perror("error: could not allocate memory");
    close(fd);
    return NULL;
  }
  /* Leer archvo en el buffer. */
  bytes_read = read(fd, buffer, buffer_size);
  if (bytes_read != buffer_size)
  {
    perror("error: could not read file");
    free(buffer);
    close(fd);
    return NULL;
  }
  close(fd);
  /* Establecer longitud de cadena. */
  *len = buffer_size;
  /* Fin de cadena. */
  buffer[buffer_size] = '\0';
  return buffer;
}

/* --- Funciones de escritura / lectura del archivo de datos. --- */

/* Permite obtener una password por su nombre. La funcion retorna 0 si exsite y -1 si no exsite; ademas, si passvalue es diferente de NULL, en el guardara la contraseña. */
int getpasswd(char *passwd, char *passwd_name)
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
      perror("error: passwd_name cannot include the space character");
      return -1;
    }
  /* Manejando error de obtencion de ruta de archivo. */
  if (get_datadir_file_path(datafile_path, DATAFILE_NAME) == -1)
  {
    errno = ENOMEM;
    perror("error: cannot calculate path to file");
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
         lnch - slnch < MAX_PASSWD_NAME && // Paso de linea por exceso de caracteres.
         *lnch && *lnch != '\n'            // Paso de linea por fin de archivo / nueva linea.
         && *lnch != ' ';                  // Paso de linea correcto puesto que se va a indicar a continuacion la contraseña.
         lnch++)
      ;
    /* Manejando error por nombre demasiado largo. */
    if (lnch - slnch > MAX_PASSWD_NAME)
    {
      free(datafile);
      errno = ENOMEM;
      perror("error: password is corrupted as its name is to much long");
      return -1;
    }
    /* Manejo de error para contraseñas sin valor. */
    else if (*lnch == '\0' || *lnch == '\n')
    {
      free(datafile);
      errno = EILSEQ;
      perror("error: password is corrupted since it does not have any value");
      return -1;
    }
    /* En caso de que no haya un error de formato en el archivo
    (se respete la maxima cantidad caracteres para el nombre y valor). */
    else if (*lnch == ' ')
    {
      // TODO: Mejorar (basar en punteros)
      int i;
      char *lnchbefcmp = lnch;

      *lnch++ = '\0';
      /* Comparar el nombre de la contraseña. */
      if (strncmp(passwd_name, slnch, MAX_PASSWD_NAME) == 0)
      {
        /* Escribir en el arreglo del parametro el valor para la contraña. */
        for (i = 0;
             i < MAX_PASSWD - 1 &&                   // Paso linea por limite
             *lnch && *lnch != '\n' && *lnch != ' '; // Paso linea por caracter
             lnch++, i++)
        {
          if (passwd != NULL)
            passwd[i] = *lnch;
        }
        if (passwd != NULL)
          passwd[i++] = '\0';

        /* Manejando error de longitud de password. */
        if (i >= MAX_PASSWD)
        {
          free(datafile);
          errno = ENOMEM;
          perror("error: password is corrupted, it is to much long");
          return -1;
        }
        /* Manejando error de corrupcion en el archivo (espacio en contraseña). */
        else if (*lnch == ' ')
        {
          free(datafile);
          errno = EILSEQ;
          perror("error: password is corrupted since it contains space characters");
          return -1;
        }
        free(datafile);
        return 0;
      }
      else
      {
        /* Incrementando puntero para*/
        for (i = 0;
             i < MAX_PASSWD &&                       // Paso linea por limite
             *lnch && *lnch != '\n' && *lnch != ' '; // Paso linea por caracter
             lnch++, i++)
          ;
        /* Manejando error de longitud de password. */
        if (i >= MAX_PASSWD)
        {
          free(datafile);
          errno = ENOMEM;
          perror("error: password file is corrupted, to much long passwords where found");
          return -1;
        }
        /* Manejando error de corrupcion en el archivo (espacio en contraseña). */
        else if (*lnch == ' ')
        {
          free(datafile);
          errno = EILSEQ;
          perror("error: password file is corrupted, space ending passwords where found");
          return -1;
        }
        *lnchbefcmp = ' ';
        slnch = lnch;
      }
    }
  } while (*slnch);

  free(datafile);
  errno = EINVAL;
  perror("error: password name has not been found");
  return -1;
}

/* Permite establecer una nueva entrada en el archivo de contraseñas. Si hay un error retorna -1, si no, 0. */
int setpasswd(char *password_name, char *password)
{
  if (strlen(password_name) > MAX_PASSWD_NAME)
  {
    errno = EINVAL;
    perror("error: password name is to much long");
    return -1;
  }
  /* En el caso de la longitud de la contraseña, la macro hace mas bien referencia al tamaño de un arreglo en lugar de a la cantidad de caracteres validos para la contraña, lo que significa que la cantidad de caracteres admitidos es siempre inferior en 1 al valor de la macro. */
  else if (strlen(password) >= MAX_PASSWD)
  {
    errno = EINVAL;
    perror("error: password is to much long");
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
  if (getpasswd(NULL, password_name) != 0)
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
    slnch++;
    for (lnch = slnch;
         lnch - slnch < MAX_PASSWD_NAME &&       // Paso de linea por longitud de nombre
         *lnch && *lnch != '\n' && *lnch != ' '; // Paso de linea por caracter
         lnch++)
      ;
    if (lnch - slnch > MAX_PASSWD_NAME)
    {
      free(datafile);
      errno = ENOMEM;
      perror("error: password is corrupted, it is to much long");
      return -1;
    }
    else if (*lnch == '\0' || *lnch == '\n')
    {
      free(datafile);
      errno = EILSEQ;
      perror("error: password is corrupted since it does not have any value");
      return -1;
    }
    else if (*lnch == ' ')
    {
      *lnch++ = '\0';
      char *password = lnch;
      if (strcmp(password_name, slnch) == 0)
      {
        for (;
             lnch - password < MAX_PASSWD - 1 &&
             *lnch && *lnch != '\n' && *lnch != ' ';
             lnch++)
          ;
        /* Manejando error por nombre demasiado largo. */
        if (lnch - password >= MAX_PASSWD)
        {
          free(datafile);
          errno = ENOMEM;
          perror("error: password is corrupted, it is to much long");
          return -1;
        }
        /* Manejo de error para contraseñas sin valor. */
        else if (*lnch == ' ')
        {
          free(datafile);
          errno = EILSEQ;
          perror("error: password is corrupted since it contains space characters");
          return -1;
        }
        offset = (lnch - slnch) + 1;

        // TODO: Desplazar todos los caracteres del archivo a partir de cierta posicion
      }
      else
      {
        for (;
             lnch - password < MAX_PASSWD - 1 &&
             *lnch && *lnch != '\n' && *lnch != ' ';
             lnch++)
          ;
        /* Manejando error por nombre demasiado largo. */
        if (lnch - password >= MAX_PASSWD)
        {
          free(datafile);
          errno = ENOMEM;
          perror("error: password is corrupted, it is to much long");
          return -1;
        }
        /* Manejo de error para contraseñas sin valor. */
        else if (*lnch == ' ')
        {
          free(datafile);
          errno = EILSEQ;
          perror("error: password is corrupted since it contains space characters");
          return -1;
        }
        slnch = lnch;
      }
    }
  } while (*slnch && offset == 0);
}

/* Se encarga de hacer una comprobacion de los archivos de datos del programa y de crear los que sean necesarios.*/
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