#include "victim_enclave_u.h"
#include <errno.h>



typedef struct ms_storeSecret_t {
	sgx_sealed_data_t* ms_storage;
	uint32_t ms_sealed_secret_size;
} ms_storeSecret_t;

typedef struct ms_loadSecret_t {
	sgx_sealed_data_t* ms_storage;
} ms_loadSecret_t;

typedef struct ms_encrypt_step_t {
	unsigned char* ms_input;
} ms_encrypt_step_t;

typedef struct ms_encrypt_final_t {
	unsigned char* ms_output;
} ms_encrypt_final_t;

typedef struct ms_encrypt_loop_t {
	unsigned char* ms_input;
	unsigned char* ms_output;
	int* ms_flag;
	int* ms_flag_out;
} ms_encrypt_loop_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_victim_enclave = {
	0,
	{ NULL },
};
sgx_status_t createSecret(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_victim_enclave, NULL);
	return status;
}

sgx_status_t getSecretSize(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_victim_enclave, NULL);
	return status;
}

sgx_status_t storeSecret(sgx_enclave_id_t eid, sgx_sealed_data_t* storage, uint32_t sealed_secret_size)
{
	sgx_status_t status;
	ms_storeSecret_t ms;
	ms.ms_storage = storage;
	ms.ms_sealed_secret_size = sealed_secret_size;
	status = sgx_ecall(eid, 2, &ocall_table_victim_enclave, &ms);
	return status;
}

sgx_status_t loadSecret(sgx_enclave_id_t eid, sgx_sealed_data_t* storage)
{
	sgx_status_t status;
	ms_loadSecret_t ms;
	ms.ms_storage = storage;
	status = sgx_ecall(eid, 3, &ocall_table_victim_enclave, &ms);
	return status;
}

sgx_status_t encrypt_step(sgx_enclave_id_t eid, unsigned char* input)
{
	sgx_status_t status;
	ms_encrypt_step_t ms;
	ms.ms_input = input;
	status = sgx_ecall(eid, 4, &ocall_table_victim_enclave, &ms);
	return status;
}

sgx_status_t encrypt_final(sgx_enclave_id_t eid, unsigned char* output)
{
	sgx_status_t status;
	ms_encrypt_final_t ms;
	ms.ms_output = output;
	status = sgx_ecall(eid, 5, &ocall_table_victim_enclave, &ms);
	return status;
}

sgx_status_t encrypt_loop(sgx_enclave_id_t eid, unsigned char* input, unsigned char* output, int* flag, int* flag_out)
{
	sgx_status_t status;
	ms_encrypt_loop_t ms;
	ms.ms_input = input;
	ms.ms_output = output;
	ms.ms_flag = flag;
	ms.ms_flag_out = flag_out;
	status = sgx_ecall(eid, 6, &ocall_table_victim_enclave, &ms);
	return status;
}

