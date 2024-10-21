#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

/* Determina la maxima cantida de caracteres por line para el archivo de datos. */
#define MAXLN 1024
/* Determina la maxima cantidad de caracteres para el nombre de la contraseña. */
#define MAX_PASSWD_NAME 64
/* Determina la maxima cantidad de caracteres para la contraseña. */
#define MAX_PASSWD (MAXLN - MAX_PASSWD_NAME - 2) // Hay que quitar el espacio entre nombre y valor y el salto de linea.

/* Determina la maxima cantidad de caracteres para una ruta. */
#define MAX_PATH_LEN 256

#define DATAFILE_NAME "epm_data.enc"
#define KEYFILE_NAME "epm_aes_hashed_key.key"
#define IVFILE_NAME "epm_aes_iv.key"

int getpasswd(char *passname, char *passvalue);

char *read_file(char *path, size_t *len);

static int get_datadir_path(char *dirpath);

static int get_datadir_file_path(
    char *filepath,
    char *rpath /* ruta relativa al archivo */);

int main()
{
  char password[MAX_PASSWD];
  if (getpasswd(password, "pass2") != 0)
    return EXIT_FAILURE;

  printf("%s\n", password);

  return EXIT_SUCCESS;
}

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
      errno = ENOMEM;
      perror("error: password name is to much long");
      return -1;
    }
    /* Manejo de error para contraseñas sin valor. */
    else if (*lnch == '\0' || *lnch == '\n')
    {
      errno = EILSEQ;
      perror("error: password is corrupted since it does not have any value");
      return -1;
    }
    /* En caso de que no haya un error de formato en el archivo
    (se respete la maxima cantidad caracteres para el nombre y valor). */
    else if (*lnch == ' ')
    {
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
          errno = ENOMEM;
          perror("error: password is corrupted, it is to much long");
          return -1;
        }
        /* Manejando error de corrupcion en el archivo (espacio en contraseña). */
        else if (*lnch == ' ')
        {
          errno = EILSEQ;
          perror("error: password is corrupted since it contains space characters");
          return -1;
        }
        *lnchbefcmp = ' ';
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
          errno = ENOMEM;
          perror("error: password file is corrupted, to much long passwords where found");
          return -1;
        }
        /* Manejando error de corrupcion en el archivo (espacio en contraseña). */
        else if (*lnch == ' ')
        {
          errno = EILSEQ;
          perror("error: password file is corrupted, space ending passwords where found");
          return -1;
        }
        *lnchbefcmp = ' ';
        slnch = lnch;
      }
    }
  } while (*slnch);

  errno = EINVAL;
  perror("error: password name has not been found");
  return -1;
}

/* Permire leer el archivo path facilmente devolviendo un puntero o NULL en caso de error. */
char *read_file(char *path, size_t *len)
{
  char *buffer;       // Donde se almacenara el archivo leido
  int fd;             // Descriptor de arhivo
  off_t buffer_size;  // Tamaño del buffer
  ssize_t bytes_read; // Bytes leidos

  /* Abrir el archivo en modo lectura. */
  fd = open(path, O_RDONLY);
  if (fd == -1)
  {
    perror("error: there was an error opening file");
    return NULL;
  }
  /* Obtener tamaño de buffer. */
  buffer_size = lseek(fd, 0, SEEK_END);
  if (buffer_size == -1)
  {
    perror("error: there was an error getting file size");
    close(fd);
    return NULL;
  }
  if (lseek(fd, 0, SEEK_SET) == -1) // Posicionar lectura de archivo.
  {
    perror("error: there was an error resetting file offset");
    close(fd);
    return NULL;
  }
  /* Asignando memoria. */
  buffer = (char *)malloc(buffer_size + 1); // Fin de cadena.
  if (buffer == NULL)
  {
    perror("error: there was an error allocating memory");
    close(fd);
    return NULL;
  }
  /* Leer archvo en el buffer. */
  bytes_read = read(fd, buffer, buffer_size);
  if (bytes_read != buffer_size)
  {
    perror("error: there was en error reading file");
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

/* Permite obtener la ruta al directorio donde se encuentran los archivos de datos. Retorna la longitud de la ruta o -1 en caso de error por desbordamiento de maxima cantidad de caracteres para ruta. */
static int get_datadir_path(char *dirpath)
{
  char *home = getenv("HOME"); // /home/alvaro
  char *rmng = ".local/share/epm";
  /* En caso de exceso (tambien hay que contar la /) */
  if (strlen(home) + strlen(rmng) + 1 > MAX_PATH_LEN)
    return -1;
  // home/alvaro/.local/share/epm
  return snprintf(dirpath, MAX_PATH_LEN, "%s/%s", home, rmng);
}

/* Permite obtener la ruta a un archivo de datos del programa. filepath sera un buffer con al menos 256 caracteres de tamaño y rpath la ruta relativa desde el directorio de datos. La funcion retorna la longitud o -1 en caso de error. */
static int get_datadir_file_path(
    char *filepath,
    char *rpath /* ruta relativa al archivo */)
{
  /* Obtener ruta absoluta al directorio de archivos de datos. */
  int datadir_len = get_datadir_path(filepath);
  if (datadir_len == -1)
    return -1;
  /* Evitar maxima cantidad caracteres ruta (tambien cuenta la /). */
  if (datadir_len + strlen(rpath) + 1 > MAX_PATH_LEN)
    return -1;
  /* Escribir la cadena formateada. */
  return snprintf(filepath + datadir_len, MAX_PATH_LEN, "/%s", rpath);
}