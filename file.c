#include "main.h"

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
  FILE *file = fopen(PASSDATA_FILE, "r");
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
        fclose(file);
        return success;
      }
    }
    return not_found_err;
  }
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

  FILE *file = fopen(PASSDATA_FILE, "a");
  if (file != NULL)
  {
    char nline[MAXLN];
    setpasswdln(nline, passname, passvalue);
    fprintf(file, "%s", nline);
    fclose(file);
    return success;
  }
  fclose(file);
  return open_file_err;
}

int direxists(char *path)
{
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

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