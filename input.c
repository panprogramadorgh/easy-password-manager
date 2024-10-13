#include "main.h"

#define MAXBUFF 128

static char buff[MAXBUFF];
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
  int i, c;

  clrbuff();
  while (isspace((c = getch())))
    ;
  ungetch(c);
  i = 0;
  while (i < n && (c = getch()) != EOF && c != '\n')
    *(line + i++) = c;
  *(line + i) = '\0';
}