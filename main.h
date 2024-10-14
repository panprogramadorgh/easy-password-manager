#ifndef main_h
#define main_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAXLN 1024
#define MAXPASSNAME 64
#define MAXPASSVAL MAXLN - MAXPASSNAME - 2 // Hay que quitar el espacio entre nombre y valor y el salto de linea.
#define PASSDATA "./passwords.txt"

enum passwd_signals
{
  success,
  inv_arg_err,
  not_found_err,
  open_file_err,
};

#endif
