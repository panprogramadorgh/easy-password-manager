#include "main.h"

#define AES_KEY_LENGTH 256
#define AES_BLOCK_SIZE 16

/* --- Funciones de cifrado con AES ---  */

int encrypt(const unsigned char *plain, const int plain_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *cipher)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, cipher_len;

  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

  EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len);
  cipher_len = len;

  EVP_EncryptFinal_ex(ctx, cipher + len, &len);
  cipher_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return cipher_len;
}

int decrypt(const unsigned char *cipher, const int cipher_len, const unsigned char *key, const unsigned char *iv, unsigned char *plain)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, plain_len;

  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

  EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len);
  plain_len = len;

  EVP_DecryptFinal_ex(ctx, plain + len, &len);
  plain_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return plain_len;
}

/* --- Funciones de serializacion de buffers --- */

/* Serializa un buffer a una cadena de base64. Se debe liberar la memoria del puntero retornado. */
char *serialize_buffer_to_base64(unsigned char *buffer, size_t bufflen)
{
  BIO *bio, *b64;
  BUF_MEM *mbuff_ptr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  /* Procesar buffer con bio. */
  BIO_write(bio, buffer, bufflen);
  BIO_flush(bio);

  /* Obtener acceso a los datos del bio de memoria. */
  BIO_get_mem_ptr(bio, &mbuff_ptr);

  /* Convertir el texto en un string. */
  char *b64text = (char *)malloc(mbuff_ptr->length + 1);
  memcpy(b64text, mbuff_ptr->data, mbuff_ptr->length);
  b64text[mbuff_ptr->length] = '\0';

  BIO_free_all(bio); // Liberar la memoria del bio
  return b64text;
}

/* Deserializa una cadena en base64 en un buffer binario. Se debe liberar la memoria del puntero retornado. */
unsigned char *deserialize_base64_to_buffer(const char *b64text, size_t *length)
{
  BIO *bio, *b64;
  size_t decode_len = strlen(b64text);
  unsigned char *buffer = (unsigned char *)malloc(decode_len);

  /* Crea el bio de memoria en base a la cadena codificada y prevee automaticamente la longitud del buffer resultante. */
  bio = BIO_new_mem_buf(b64text, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  /* Lee el bio tras haber pasado por el filtro de base64, escribe el resultado decodificado en el buffer. */
  *length = BIO_read(bio, buffer, decode_len);

  BIO_free_all(bio);

  return buffer;
}