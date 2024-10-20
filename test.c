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
  printf("%d\n", getpasswd(NULL, "hello world"));

  return EXIT_SUCCESS;
}

/* Permite obtener una password por su nombre. La funcion retorna 0 si exsite y -1 si no exsite; ademas, si passvalue es diferente de NULL, en el guardara la contraseña. */
int getpasswd(char *passwd, char *passwd_name)
{
  char datafile_path[MAX_PATH_LEN]; // Ruta al archivo
  size_t datafile_len;              // Tamaño en bytes del archivo
  char *datafile;                   // Archivo
  char *slnch, *lnch;               // Caracteres de archivo
  /* Manejando error de obtencion de ruta de archivo. */
  if (get_datadir_file_path(datafile_path, DATAFILE_NAME) == -1)
  {
    perror("error: cannot calculate path to file.\n");
    return -1;
  }
  if ((datafile = read_file(datafile_path, &datafile_len)) == NULL)
    return -1;

  /* Imprime todas las lineas del archivo. */
  slnch = datafile - 1;
  do
  {
    slnch++;
    for (lnch = slnch;
         lnch - slnch <= MAX_PASSWD_NAME && // Paso de linea por exceso de caracteres.
         *lnch && *lnch != '\n'             // Paso de linea por fin de archivo / nueva linea.
         && *lnch != ' ';                   // Paso de linea correcto puesto que se va a indicar a continuacion la contraseña.
         lnch++)
      ;
    /* En caso de que no haya un error de formato en el archivo
    (se respete la maxima cantidad caracteres para el nombre y valor). */
    if (*lnch == ' ')
    {
      /* Comparar el nombre de la contraseña. */
      *lnch = '\0';
      if (strncmp(passwd_name, slnch, MAX_PASSWD_NAME) == 0)
      {
        if (passwd != NULL)
        { /* Escribir en el arreglo del parametro el valor para la contraña. */
          for (;
               lnch - slnch - MAXLN - 2 - 1 <= MAX_PASSWD && // Paso de linea por exceso de caracteres (avanzar 1 menos para poder guardar la password en un string de tamaño MAX_PASSWD).
               *lnch && *lnch != '\n' && *lnch != ' ';       // Paso de linea por fin de archivo / nueva linea.
               lnch++)
            passwd[lnch - slnch - MAXLN - 2] = *lnch;
          passwd[lnch - slnch - MAXLN - 2] = '\0';
        }
        return 0;
      }
    }
  } while (*slnch);

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
    perror("error: there was an error opening file.\n");
    return NULL;
  }
  /* Obtener tamaño de buffer. */
  buffer_size = lseek(fd, 0, SEEK_END);
  if (buffer_size == -1)
  {
    perror("error: there was an error getting file size.\n");
    close(fd);
    return NULL;
  }
  if (lseek(fd, 0, SEEK_SET) == -1) // Posicionar lectura de archivo.
  {
    perror("error: there was an error resetting file offset.\n");
    close(fd);
    return NULL;
  }
  /* Asignando memoria. */
  buffer = (char *)malloc(buffer_size + 1); // Fin de cadena.
  if (buffer == NULL)
  {
    perror("error: there was an error allocating memory.\n");
    close(fd);
    return NULL;
  }
  /* Leer archvo en el buffer. */
  bytes_read = read(fd, buffer, buffer_size);
  if (bytes_read != buffer_size)
  {
    perror("error: there was en error reading file.\n");
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