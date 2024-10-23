#include "../../include/main.h"
#include "../../include/input.h"

/* Buffer de entrada. */
static char buff[MAX_BUFF];
/* Posicion del buffer de entrada. */;
static char *buffpos = buff;

int getch(void)
{
  if (buffpos - buff > 0)
    return *--buffpos;
  return getchar();
}

void ungetch(int c)
{
  *buffpos++ = c;
}

void clrbuff(void)
{
  buffpos = buff;
}

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

void prtusage(void)
{
  printf("Usage:\n");
  printf("\t- get-passwd <password name>\n");
  printf("\t- set-passwd <password name> <password>\n");
}