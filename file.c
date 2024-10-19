#include "main.h"

/* --- Obtencion de rutas para archivo de datos. --- */

#define MAXPATHLENGTH 256

/* Permite obtener la ruta al directorio donde se encuentra el archivo de datos. Tras utilizarse liberar memoria con free.  */

char *get_datadir_path()
{
  char *dirpath = (char *)malloc(MAXPATHLENGTH);
  if (dirpath == NULL)
    return NULL;

  char *frst_chunk = getenv("HOME"); // Ej: /home/alvaro
  char *scnd_chunk = ".local/share/epm";
  if (strlen(frst_chunk) + strlen(scnd_chunk) > MAXPATHLENGTH)
    return NULL;

  snprintf(dirpath, MAXPATHLENGTH, "%s/%s", frst_chunk, scnd_chunk); // Ej: /home/alvaro/.local/share/epm

  return dirpath;
}

/* TODO: Crear funcion para simplicar lectura de archivos de datos del programa.  */

/* Permite obtener la ruta al archivo de datos. Tras utilizarse liberar memoria con free. */
char *get_datafile_path()
{
  char *filepath = (char *)malloc(MAXPATHLENGTH);
  if (filepath == NULL)
    return NULL;

  char *frst_chunk = get_datadir_path();
  char *scnd_chunk = "data.enc";
  if (frst_chunk == NULL)
    return NULL;
  if (strlen(frst_chunk) + strlen(scnd_chunk) > MAXPATHLENGTH)
    return NULL;

  snprintf(filepath, MAXPATHLENGTH, "%s/%s", frst_chunk, scnd_chunk);

  free(frst_chunk); // Cerrar fugas de memoria.

  return filepath;
}

char *get_keyfile_path()
{
  char *filepath = (char *)malloc(MAXPATHLENGTH);
  if (filepath == NULL)
    return NULL;

  char *frst_chunk = get_datadir_path();
  char *scnd_chunk = "epm_aes_hashed_key.key";
  if (frst_chunk == NULL)
    return NULL;
  if (strlen(frst_chunk) + strlen(scnd_chunk) > MAXPATHLENGTH)
    return NULL;

  snprintf(filepath, MAXPATHLENGTH, "%s/%s", frst_chunk, scnd_chunk);

  free(frst_chunk); // Cerrar fugas de memoria.

  return filepath;
}

char *get_ivfile_path()
{
  char *filepath = (char *)malloc(MAXPATHLENGTH);
  if (filepath == NULL)
    return NULL;

  char *frst_chunk = get_datadir_path();
  char *scnd_chunk = "epm_aes_iv.key";
  if (frst_chunk == NULL)
    return NULL;
  if (strlen(frst_chunk) + strlen(scnd_chunk) > MAXPATHLENGTH)
    return NULL;

  snprintf(filepath, MAXPATHLENGTH, "%s/%s", frst_chunk, scnd_chunk);

  free(frst_chunk); // Cerrar fugas de memoria.

  return filepath;
}

// TODO: Normalizar nombres de rutinas.

/* --- Funciones de escritura / lectura del archivo de datos. --- */

/* Formatea un string de acuerdo con el formato del archivo de contraseñas. */
static void setpasswdln(char *dest, char *passname, char *passvalue)
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
    setpasswdln(nline, passname, passvalue);
    fprintf(file, "%s", nline);
    free(datafile_path);
    fclose(file);
    return success;
  }
  free(datafile_path);
  fclose(file);
  return open_file_err;
}

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

/* Permite crear un archivo e introducir contenido en el. Si se creo correctamente devuelve 0, si no, -1. */
int create_file(char *path, char *content, int content_len, int access)
{
  struct stat st;
  if (stat(path, &st) == 0 && !S_ISDIR(st.st_mode))
    if (remove(path) != 0)
      return -1;
  int fd = open(path, O_CREAT | O_WRONLY, access);
  if (fd == -1)
    return fd;

  if (content != NULL)
    if (write(fd, content, content_len) == -1)
      return -1;

  close(fd);

  return 0;
}

/* Se encarga de hacer una comprobacion de los archivos de datos del programa y de crear los que sean necesarios.*/
int verify_program_files(
    char *datadir_path,  // Directorio donde se encuentran archivos de datos
    char *datafile_path, // Archivos de contraseñas
    char *keyfile_path,  // Archivos de clave
    char *ivfile_path)   // Archivos de vector de inicializacion
{
  /* Creacion de directorio de datos. */
  if (!direxists(datadir_path))
  {
    if (createdir(datadir_path) != 0)
    {
      fprintf(stderr, "error: there was en error creating program data directory '%s'.\n", datadir_path);
      return -1;
    }
  }
  /* Creacion del archivo de datos. */
  if (!filexists(datafile_path))
  {
    if (create_file(datafile_path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
    {
      fprintf(stderr, "error: there was an error creating program data file '%s'.\n", datafile_path);
      printf("%d\n", errno);
      return -1;
    }
  }
  /* Creacion del archivo de clave. */
  if (!filexists(keyfile_path))
  {
    if (create_file(keyfile_path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
    {
      fprintf(stderr, "error: there was an error creating program key file '%s'.\n", datafile_path);
      return -1;
    }
  }
  if (!filexists(ivfile_path))
  {
    // Permisos de archivo 600
    if (create_file(ivfile_path, NULL, 0, S_IRUSR | S_IWUSR) != 0)
    {
      fprintf(stderr, "error: there was an error creating program iv file '%s'.\n", datafile_path);
      return -1;
    }
  }

  return 0;
}