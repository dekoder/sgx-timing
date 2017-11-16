#ifndef VICTIM_ENCLAVE_T_H__
#define VICTIM_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tseal.h"
#include "sgx_trts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void createSecret();
void getSecretSize();
void storeSecret(sgx_sealed_data_t* storage, uint32_t sealed_secret_size);
void loadSecret(sgx_sealed_data_t* storage);
void encrypt_step(unsigned char* input);
void encrypt_final(unsigned char* output);
void encrypt_loop(unsigned char* input, unsigned char* output, int* flag, int* flag_out);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
