#ifndef crypto_h
#define crypto_h

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sodium.h>

/* Determina la cantidad de bits para la clave privada AES */
#define AES_KEY_LENGTH 256
/* Determina la cantidad de bytes para el vector de serializacion de AES. */
#define AES_BLOCK_SIZE 16
/* Determina la cantidad de bytes para los hashes aragon. */
#define ARAGON_HASH_BYTES 32

/* Permite el cifrado de un buffer con AES. */
int encrypt(const unsigned char *plain, const int plain_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *cipher);

/* Permite descifrado de un buffer con AES. */
int decrypt(const unsigned char *cipher, const int cipher_len, const unsigned char *key, const unsigned char *iv, unsigned char *plain);

/* Serializa un buffer a una cadena de base64. Se debe liberar la memoria del puntero retornado. */
char *serialize_buffer_to_base64(unsigned char *buffer, size_t bufflen);

/* Deserializa una cadena en base64 en un buffer binario. Se debe liberar la memoria del puntero retornado. */
unsigned char *deserialize_base64_to_buffer(const char *b64text, size_t *length);

#endif