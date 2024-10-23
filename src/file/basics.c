#include "../../include/main.h"
#include "../../include/file.h"

int get_datadir_path(char *dirpath)
{
  char *home = getenv("HOME"); // /home/alvaro
  char *rmng = ".local/share/epm";
  /* En caso de exceso (tambien hay que contar la /) */
  if (strlen(home) + strlen(rmng) + 1 >= MAX_PATH_LEN)
  {
    errno = ENAMETOOLONG;
    perror("error: max path length exceded");
    return -1;
  }
  // /home/alvaro/.local/share/epm
  snprintf(dirpath, MAX_PATH_LEN, "%s/%s", home, rmng);
  return 0;
}

int get_datadir_file_path(
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
    errno = ENAMETOOLONG;
    perror("error: max path length exceded");
    return -1;
  }
  snprintf(filepath + dirpath_len, MAX_PATH_LEN - dirpath_len, "/%s", rpath);
  return 0;
}

int direxists(char *path)
{
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int filexists(char *path)
{
  struct stat st;
  return stat(path, &st) == 0 && !S_ISDIR(st.st_mode);
}

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

int write_file(char *path, char *content, int content_len)
{
  /* Si existe el archivo se elimina, si no tira un error. */
  if (!filexists(path))
  {
    errno = ENOENT;
    perror("error: could not write content in file");
    return -1;
  }
  if (remove(path) != 0)
  {
    errno = EAGAIN;
    perror("error: file could not be created");
    return -1;
  }

  int fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
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