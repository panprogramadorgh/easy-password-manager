#ifndef main_h
#define main_h

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAXLN 1024
#define MAXPASSNAME 64
#define MAXPASSVAL MAXLN - MAXPASSNAME - 2 // Hay que quitar el espacio entre nombre y valor y el salto de linea.
#define PASSDATA "./passwords.txt"

#endif
