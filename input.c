#include "main.h"

/* Maximo tamaño del buffer de entrada. */
#define MAXBUFF 128

/* Buffer de entrada. */
static char buff[MAXBUFF];
/* Posicion del buffer de entrada. */;
static char *buffpos = buff;

/* Retorna el ultimo caracter del buffer de entrada o en caso de estar vacio, recurre a la entrada del usuario.*/
int getch(void)
{
  if (buffpos - buff > 0)
    return *--buffpos;
  return getchar();
}

/* Introduce un caracter en el buffer de entrada. */
void ungetch(int c)
{
  *buffpos++ = c;
}

/* Limpia por completo el buffer de entrada. */
void clrbuff(void)
{
  buffpos = buff;
}

/* Permite obtener una linea de entrada con n caracteres. */
int getnline(char *line, int n)
{
  size_t i, c;

  clrbuff();
  while (isspace((c = getch())))
    ;
  ungetch(c);
  i = 0;
  while (i < n && (c = getch()) != EOF && c != '\n')
    *(line + i++) = c;
  *(line + i) = '\0';
}

/* Imprime las instrucciones de uso del comando. */
void prtusage(void)
{
  printf("Usage:\n");
  printf("\t- get-passwd <password name>\n");
  printf("\t- set-passwd <password name> <password>\n");
}