#ifndef input_h
#define input_h

/* Maximo tamaño del buffer de entrada. */
#define MAX_BUFF 128

/* Señales de retorno para auth(). */
enum auth_signals
{
  auth_success,
  auth_failure,
  auth_error,
  auth_nokey,
  auth_corrupted,
};

/* Retorna el ultimo caracter del buffer de entrada o en caso de estar vacio, recurre a la entrada del usuario.*/
int getch(void);

/* Introduce un caracter en el buffer de entrada. */
void ungetch(int c);

/* Limpia por compasleto el buffer de entrada. */
void clrbuff(void);

/* Permite obtener una linea de entrada con n caracteres. */
int getnline(char *line, int n);

/* Permite autenticar al usuario preguntando la clave privada AES. */
enum auth_signals auth();

/* Imprime las instrucciones de uso del comando. */
void prtusage(void);

#endif