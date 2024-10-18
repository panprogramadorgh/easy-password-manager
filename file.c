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

/* Se encarga de hacer una comprobacion de los archivos de datos del programa y de crear los que sean necesarios.*/
int verify_program_files(
    char *datadir_path,
    char *datafile_path,
    char *keyfile_path,
    char *ivfile_path)
{
  /* Manejar error de calculo de ruta. */
  if (!datadir_path ||
      !datafile_path ||
      !keyfile_path ||
      !ivfile_path)
  {
    fprintf(stderr, "error: there was an error calculating data files paths.\n");
    return -1;
  }
  /* Creacion de directorio de datos. */
  if (!direxists(datadir_path))
  {
    if (createdir(datadir_path) != 0)
    {
      fprintf(stderr, "error: there was en error creating program data directories.\n");
      return -1;
    }
  }
  /* Creacion del archivo de datos. */
  if (!filexists(datafile_path))
  {
    // Permisos de archivo 600
    int fd = open(datafile_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
      fprintf(stderr, "error: there was an error creating program data file '%s'.\n", datafile_path);
      return -1;
    }
    close(fd);
  }
  /* Creacion del archivo de clave. */
  if (!filexists(keyfile_path))
  {
    // Permisos de archivo 600
    int fd = open(keyfile_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
      fprintf(stderr, "error: there was an error creating program data file '%s'.\n", keyfile_path);
      return -1;
    }
    close(fd);
  }
  /* Creacion del archivo de iv. */
  if (!filexists(ivfile_path))
  {
    // Permisos de archivo 600
    int fd = open(ivfile_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
      fprintf(stderr, "error: there was an error creating program data file '%s'.\n", ivfile_path);
      return EXIT_FAILURE;
      -1;
    }
    close(fd);
  }

  return 0;
}