/*
 * crypto_manager.h
 *
 *  Created on: Feb 27, 2024
 *      Author: gags
 */

#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include "mbedtls.h"

// Define the key size for AES encryption
#define AES_KEY_SIZE 32 // 256-bit key size for AES-256


int crypto_manager_init(void);

int aes_generate_key(unsigned char *key, size_t key_len);
int aes_encrypt(const unsigned char *plaintext, size_t plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, size_t *ciphertext_len);
int aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *dectext);


void print_base64_encoded_message(uint8_t* msg, size_t msg_len);


#endif /* CRYPTO_MANAGER_H */
