#include "main.h"

/* --- Obtencion de rutas para archivo de datos. --- */

// TODO: Actualizar todas las rutinas del archivo de acuerdo con las nuevas funciones de creacion / lectura / escritura de archivos.

// TODO: Mejorar macros de tal manera que no se llamen tantas veces a las funciones.

/* Determina la maxima cantidad de caracteres para una ruta. */
#define MAX_PATH_LEN 256

/* Ruta almacen para macros epm.  */
static char path[MAX_PATH_LEN];

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

/* Macros epm para resolucion de rutas de archivos de datos. */

#define epm_datadir_path (get_datadir_path(path), path)
#define epm_datafile_path (get_datadir_file_path(path, "epm_data.enc"), path)
#define epm_keyfile_path (get_datadir_file_path(path, "epm_aes_hashed_key.key"), path)
#define epm_ivfile_path (get_datadir_file_path(path, "epm_aes_iv.key"), path)

/* --- Funciones de escritura / lectura del archivo de datos. --- */

/* Formatea un string de acuerdo con el formato del archivo de contraseñas. */
static void format_passwd_line(char *dest, char *passname, char *passvalue)
{
  strcpy(dest, passname);
  strcat(dest, " ");
  strcat(dest, passvalue);
  strcat(dest, "\n");
}

/* Permite obtener una password por su nombre. La funcion retorna 1 si exsite y 0 si no exsite; ademas, si passvalue es diferente de NULL, en el guardara la contraseña. */
int getpasswd(char *passname, char *passvalue)
{
  char *datafile_path = get_datafile_path();
  FILE *file = fopen(datafile_path, "r");
  if (file != NULL)
  {
    char buff[MAXLN];
    char *ch;
    while (fgets(buff, MAXLN, file) != NULL)
    {
      ch = buff;
      while (ch - buff < MAXLN && *ch != ' ')
        ch++;
      if (strncmp(buff, passname, ch - buff) == 0)
      {
        if (passvalue != NULL)
        {
          ch++;
          while (*ch != '\n')
            *passvalue++ = *ch++;
        }
        free(datafile_path);
        fclose(file);
        return success;
      }
    }
    free(datafile_path);
    fclose(file);
    return not_found_err;
  }
  free(datafile_path);
  fclose(file);
  return open_file_err;
}

/* Permite establecer una nueva entrada en el archivo de contraseñas. Si hay un error retorna 0, si no, retorna 1. */
int setpasswd(char *passname, char *passvalue)
{
  if (strlen(passname) > MAXPASSNAME)
    return inv_arg_err;
  else if (strlen(passvalue) > MAXPASSVAL)
    return inv_arg_err;

  char *datafile_path = get_datafile_path();
  FILE *file = fopen(datafile_path, "a");
  if (file != NULL)
  {
    char nline[MAXLN];
    format_passwd_line(nline, passname, passvalue);
    fprintf(file, "%s", nline);
    free(datafile_path);
    fclose(file);
    return success;
  }
  free(datafile_path);
  fclose(file);
  return open_file_err;
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
  char spath[256];
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
        return -1;
      *ch = '/';
    }
  }

  /* Ultimo directorio. */
  if (mkdir(spath, 0755) != 0 && errno != EEXIST)
    return -1;

  return 0;
}

/* Permite crear un archivo e introducir contenido en el al mismo tiempo. Si se creo correctamente devuelve 0, si no, -1. */
int create_file(char *path, char *content, int content_len, int access)
{
  struct stat st;
  /* Si existe el archivo se elimina. */
  if (filexists(path))
    if (remove(path) != 0)
      return -1;
  /* Se crea el archivo bajo los permisos determinados. */
  int fd = open(path, O_CREAT | O_WRONLY, access);
  if (fd == -1)
    return fd;
  /* En caso de que se quiera introducir contenido.  */
  if (content != NULL)
    if (write(fd, content, content_len) == -1)
      return -1;

  close(fd);

  return 0;
}

/* Permite la escritura de archivos en path. Si no existe o si hay cualquier error retorna -1, si todo fue bien retorna 0. */
int write_file(char *path, char *content, int content_len)
{
  int fd = open(path, O_WRONLY);
  if (fd == -1)
  {
    perror("error: there was an error opening file.\n");
    return -1;
  }
  if (write(fd, content, content_len) == -1)
  {
    perror("error: there was an error writing file.\n");
    close(fd);
    return -1;
  }
  return 0;
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

/* Se encarga de hacer una comprobacion de los archivos de datos del programa y de crear los que sean necesarios.*/
int init_program_files()
{
  /* Creacion de directorio de datos. */
  if (!direxists(epm_datadir_path))
  {
    if (createdir(epm_datadir_path) != 0)
    {
      fprintf(stderr, "error: there was en error creating program data directory '%s'.\n", epm_datadir_path);
      return -1;
    }
  }
  /* Creacion del archivo de datos. */
  if (!filexists(epm_datafile_path))
  {
    if (create_file(epm_datafile_path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
    {
      fprintf(stderr, "error: there was an error creating program data file '%s'.\n", epm_datafile_path);
      printf("%d\n", errno);
      return -1;
    }
  }
  /* Creacion del archivo de clave. */
  if (!filexists(epm_keyfile_path))
  {
    if (create_file(epm_keyfile_path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
    {
      fprintf(stderr, "error: there was an error creating program key file '%s'.\n", epm_keyfile_path);
      return -1;
    }
  }
  if (!filexists(epm_ivfile_path))
  {
    // Permisos de archivo 600
    if (create_file(epm_ivfile_path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
    {
      fprintf(stderr, "error: there was an error creating program iv file '%s'.\n", epm_ivfile_path);
      return -1;
    }
  }

  return 0;
}