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
  FILE *file = fopen(PASSDATA, "r");
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
        return 1;
      }
    }
  }
  fclose(file);
  return 0;
}

/* Permite establecer una nueva entrada en el archivo de contraseñas. Si hay un error retorna 0, si no, retorna 1. */
int setpasswd(char *passname, char *passvalue)
{
  if (strlen(passname) > MAXPASSNAME)
    return 0;
  else if (strlen(passvalue) > MAXPASSVAL)
    return 0;

  FILE *file = fopen(PASSDATA, "a");
  if (file != NULL)
  {
    char nline[MAXLN];
    setpasswdln(nline, passname, passvalue);
    fprintf(file, "%s", nline);
    fclose(file);
    return 1;
  }
  fclose(file);
  return 0;
}