#include "crypto_manager.h"
#include "mbedtls.h"


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
