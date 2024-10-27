#ifndef file_h
#define file_h

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Determina la maxima cantidad de caracteres para una ruta. */
#define MAX_PATH_LEN 256

/* Nombres de archivos de datos. */
#define DATAFILE_NAME "epm_data.enc"
#define KEYFILE_NAME "epm_aes_key.key"
#define KEYSLTFILE_NAME "epm_aes_key_salt.key"
#define IVFILE_NAME "epm_aes_iv.key"

/* Determina la maxima longitud de linea. */
#define MAXLN 1024
/* Determina la maxima cantidad de caracteres para el nombre de una contraseña. */
#define MAX_PASSWD_NAME 64
/* Determina la maxima cantidad de caracteres para una contraseña. */
#define MAX_PASSWD (MAXLN - MAX_PASSWD_NAME - 2) // Quitar el espacio entre nombre y valor y el fin de linea (\n o \0)

/* Permite obtener la ruta al directorio donde se encuentran los archivos de datos. Retorna la longitud de la ruta o -1 en caso de error por desbordamiento de maxima cantidad de caracteres para ruta. */
int get_datadir_path(char *dirpath);

/* Permite obtener la ruta a un archivo de datos del programa. filepath sera un buffer con al menos 256 caracteres de tamaño y rpath la ruta relativa desde el directorio de datos. La funcion retorna la longitud o -1 en caso de error. */
int get_datadir_file_path(
    char *filepath,
    char *rpath /* ruta relativa al archivo */);

/* Retorna 1 si el directorio existe, 0 si no. */
int direxists(char *path);

/* Retorna 1 si el archivo existe, 0 si no. */
int filexists(char *path);

/* Permire crear todos los directorios intermedios en una ruta. */
int createdir(char *path);

/* Permite creacion de directorios recursiva similar a mkdir -p. */
int createdir(char *path);

/* Permite crear un archivo e introducir contenido en el al mismo tiempo. Si se creo correctamente devuelve 0, si no, -1. */
int create_file(char *path, char *content, int content_len, int access);

/* Permite la escritura de archivos. Si no existe el archivo o si hay cualquier error retorna -1, si todo fue bien retorna 0. */
int write_file(char *path, char *content, int content_len);

/* Permite la escritura apendices sobre archivos. Si no existe el archivo o si hay cualquier error retorna -1, si todo fue bien retorna 0. */
int append_file(char *path, char *content, int content_len);

/* Permire leer el archivo path facilmente devolviendo un puntero o NULL en caso de error. */
char *read_file(char *path, size_t *len);

/* Permite obtener una password por su nombre. La funcion retorna 1 si exsite, 0 si no exsite y -1 si hay un error; ademas, si passvalue es diferente de NULL, en el guardara la contraseña. */
int getpasswd(char *passwd, char *passwd_name, char *private_key, int logs);

/* Permite establecer una nueva entrada en el archivo de contraseñas. Si hay un error retorna -1, si no, 0. */
int setpasswd(char *password_name, char *password, char *private_key);

/* Permite la eliminacion de contraseñas en el archivo de datos. */
int rmpasswd(char *password_name, char *private_key);

// --  Funciones de modularizacion --

/* Se encarga de hacer una comprobacion de los archivos de datos del programa y de crear los que sean necesarios.*/
int init_program_files();

/* Permite la sobre-escritura de la antigua clave privada y vector de inicializacion a demas del borrado del archivo de datos. */
int reset_private_key(char *newkey);

#endif