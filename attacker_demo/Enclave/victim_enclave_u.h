#ifndef VICTIM_ENCLAVE_U_H__
#define VICTIM_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "aes.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t createSecret(sgx_enclave_id_t eid);
sgx_status_t getSecretSize(sgx_enclave_id_t eid);
sgx_status_t storeSecret(sgx_enclave_id_t eid, sgx_sealed_data_t* storage, uint32_t sealed_secret_size);
sgx_status_t loadSecret(sgx_enclave_id_t eid, sgx_sealed_data_t* storage);
sgx_status_t encrypt_step(sgx_enclave_id_t eid, unsigned char* input);
sgx_status_t encrypt_final(sgx_enclave_id_t eid, unsigned char* output);
sgx_status_t encrypt_loop(sgx_enclave_id_t eid, unsigned char* input, unsigned char* output, int* flag, int* flag_out);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
