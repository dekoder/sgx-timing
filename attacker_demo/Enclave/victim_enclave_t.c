#include "victim_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)




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

static sgx_status_t SGX_CDECL sgx_createSecret(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	createSecret();
	return status;
}

static sgx_status_t SGX_CDECL sgx_getSecretSize(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	getSecretSize();
	return status;
}

static sgx_status_t SGX_CDECL sgx_storeSecret(void* pms)
{
	ms_storeSecret_t* ms = SGX_CAST(ms_storeSecret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_storage = ms->ms_storage;

	CHECK_REF_POINTER(pms, sizeof(ms_storeSecret_t));

	storeSecret(_tmp_storage, ms->ms_sealed_secret_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_loadSecret(void* pms)
{
	ms_loadSecret_t* ms = SGX_CAST(ms_loadSecret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_storage = ms->ms_storage;

	CHECK_REF_POINTER(pms, sizeof(ms_loadSecret_t));

	loadSecret(_tmp_storage);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encrypt_step(void* pms)
{
	ms_encrypt_step_t* ms = SGX_CAST(ms_encrypt_step_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_input = ms->ms_input;

	CHECK_REF_POINTER(pms, sizeof(ms_encrypt_step_t));

	encrypt_step(_tmp_input);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encrypt_final(void* pms)
{
	ms_encrypt_final_t* ms = SGX_CAST(ms_encrypt_final_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_output = ms->ms_output;

	CHECK_REF_POINTER(pms, sizeof(ms_encrypt_final_t));

	encrypt_final(_tmp_output);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encrypt_loop(void* pms)
{
	ms_encrypt_loop_t* ms = SGX_CAST(ms_encrypt_loop_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_input = ms->ms_input;
	unsigned char* _tmp_output = ms->ms_output;
	int* _tmp_flag = ms->ms_flag;
	int* _tmp_flag_out = ms->ms_flag_out;

	CHECK_REF_POINTER(pms, sizeof(ms_encrypt_loop_t));

	encrypt_loop(_tmp_input, _tmp_output, _tmp_flag, _tmp_flag_out);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_createSecret, 0},
		{(void*)(uintptr_t)sgx_getSecretSize, 0},
		{(void*)(uintptr_t)sgx_storeSecret, 0},
		{(void*)(uintptr_t)sgx_loadSecret, 0},
		{(void*)(uintptr_t)sgx_encrypt_step, 0},
		{(void*)(uintptr_t)sgx_encrypt_final, 0},
		{(void*)(uintptr_t)sgx_encrypt_loop, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


