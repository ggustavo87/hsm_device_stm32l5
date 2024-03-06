#include "crypto_manager.h"
#include "mbedtls.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"

#define KEY_SIZE 256 // Key size in bits


int aes_generate_key(unsigned char *key, size_t key_size) {
	int ret=0;
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init(&aes_ctx);

	mbedtls_ctr_drbg_context ctr_drbg_ctx;
	mbedtls_entropy_context entropy_ctx;
	mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
	mbedtls_entropy_init(&entropy_ctx);

	// Generate context and entropy source
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
	if (ret != 0) {
	  printf("Failed to initialize random generator\n");
	  return 1;
	}

	// Generate AES key
	ret = mbedtls_ctr_drbg_random(&ctr_drbg_ctx, key, key_size);

    mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
    mbedtls_entropy_free(&entropy_ctx);

    return ret;
}


int aes_encrypt(const unsigned char *plaintext, size_t plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, size_t *ciphertext_len) {
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init(&aes_ctx);

	// Check if plaintext length is a multiple of AES block size
	size_t block_size = 16;
	size_t padding_len = block_size - (plaintext_len % block_size);
	*ciphertext_len = plaintext_len + padding_len;
	unsigned char paddedtext[*ciphertext_len];
	int ret = 0;

	memcpy(paddedtext, plaintext, plaintext_len);

	// Padding if necessary
	if (padding_len != 0) {
		for (size_t i = 0; i < padding_len; i++) {
			paddedtext[plaintext_len + i] = (unsigned char) padding_len;
		}
	}

	// Encrypt the plain text
	mbedtls_aes_setkey_enc(&aes_ctx, key, AES_KEY_SIZE * 8);
	ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, *ciphertext_len, iv, (const unsigned char *)paddedtext, ciphertext);

	mbedtls_aes_free(&aes_ctx);

	return ret;
}

int aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *dectext) {
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init(&aes_ctx);
	int ret = 0;

	mbedtls_aes_setkey_dec(&aes_ctx, key, AES_KEY_SIZE * 8);
	ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, ciphertext_len, iv, ciphertext, dectext);

	mbedtls_aes_free(&aes_ctx);

	return ret;
}


#define MAX_ENCODED_MESSAGE_SIZE 512
void print_base64_encoded_message(uint8_t* msg, size_t msg_len) {
    // Allocate memory for the encoded message
    char* base64_encoded_message = (char*)malloc(MAX_ENCODED_MESSAGE_SIZE);

    // Encode the message to Base64 format
    size_t base64_encoded_len = 0;
    int ret = mbedtls_base64_encode((unsigned char *)base64_encoded_message, MAX_ENCODED_MESSAGE_SIZE, &base64_encoded_len, msg, msg_len);

    // Check if Base64 encoding was successful
    if (ret != 0) {
        printf("Base64 encoding failed\n");
        return;
    }

    // Print the Base64 encoded message
    printf("\nEncrypted Message (Base64): %s\n", base64_encoded_message);

    // Free the allocated memory
    free(base64_encoded_message);
}

int crypto_manager_init(void){
}

